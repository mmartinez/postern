package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/mmartinez/postern/internal/broker"
)

// scrubbedMarker replaces a credential found in an upstream response. It
// matches redactionValue so an operator grepping a captured response and one
// grepping the logs see the same token.
const scrubbedMarker = redactionValue

// scrubChunkSize is the read size the scrubber pulls from upstream. It bounds
// the scrubber's own buffer without affecting delivery: Read hands back
// whatever the current fill produced, so a chunk boundary here never becomes
// a boundary at the agent.
const scrubChunkSize = 32 << 10

// scrubEnabled reports the effective response-scrub setting: on unless the
// operator explicitly pointed it at false.
func scrubEnabled(cfg *bool) bool { return cfg == nil || *cfg }

// staleBodyMetadata lists the response headers that describe the body as it
// arrived upstream. Once redaction has rewritten that body they all describe
// something the agent will never receive.
var staleBodyMetadata = []string{
	"Content-Length",
	"Content-Range",
	"ETag",
	"Digest",
	"Content-MD5",
}

// credentialNeedles builds the byte patterns that must never reach the agent.
//
// Injection does not always put the credential on the wire verbatim: a path or
// query substitution percent-escapes it, so an upstream that echoes the
// request reflects the ESCAPED form. Matching only the raw value would leave
// that copy in the response. The escaped forms are what
// broker's substitutePath and substituteQuery can emit, so they are the forms
// worth carrying.
func credentialNeedles(creds []string) [][]byte {
	needles := make([][]byte, 0, len(creds)*3)
	seen := make(map[string]struct{}, len(creds)*3)
	add := func(s string) {
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		needles = append(needles, []byte(s))
	}
	for _, c := range creds {
		add(c)
		add(url.QueryEscape(c))
		add(url.PathEscape(c))
	}
	return needles
}

// scrubResponse strips the credential the broker injected on this request out
// of the upstream response, so an upstream that reflects the credential back —
// in a Set-Cookie, in a JSON error body, in an SSE frame — cannot hand it to
// the agent.
//
// It returns resp unchanged when the broker injected no credential, which is
// the passthrough case: no scan, no allocation, no new reader. That is why the
// credential hand-off is a request-context value rather than a filter the
// broker installs unconditionally.
//
// The body is scrubbed by a streaming transform, never by buffering: SSE and
// chunked responses keep their incremental delivery and their flushes.
func scrubResponse(resp *http.Response, logger *slog.Logger) *http.Response {
	if resp == nil || resp.Request == nil {
		return resp
	}
	creds, ok := broker.InjectedCredentials(resp.Request.Context())
	if !ok {
		return resp
	}

	// One needle set for headers and body: a credential echoed in a header is
	// as exposed as one echoed in the body, and it arrives in the same escaped
	// forms.
	needles := credentialNeedles(creds)
	scrubHeaderValues(resp.Header, needles)
	scrubHeaderValues(resp.Trailer, needles)

	if bodyIsScrubbable(resp) {
		resp.Body = newScrubber(resp.Body, needles)
		// Redaction changes the body's length and content, so every piece of
		// metadata describing the pre-redaction body is now a lie: the agent
		// would be told the delivered body is a length it is not, or verify a
		// digest over bytes it did not receive. Drop them all rather than let
		// a client assemble ranges or check integrity against a body that no
		// longer exists.
		resp.ContentLength = -1
		for _, h := range staleBodyMetadata {
			resp.Header.Del(h)
		}
	}

	// The broker hook drops Accept-Encoding on brokered requests so this
	// transport negotiates (and transparently decodes) compression itself,
	// leaving the scrubber plaintext. An upstream that ignored that and
	// encoded anyway has put the credential inside a deflate stream no byte
	// matcher can reach; say so loudly rather than let the scrubber look
	// like it did its job.
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		logger.Warn("upstream response is encoded; the credential scrubber cannot inspect it",
			slog.String("host", hostOf(resp.Request)),
			slog.String("content_encoding", ce),
		)
	}

	logger.Debug("proxy scrubbed upstream response",
		slog.String("host", hostOf(resp.Request)),
		slog.Int("credentials", len(creds)),
	)
	return resp
}

// bodyIsScrubbable reports whether resp.Body can be wrapped in a scrubber.
//
// Two shapes must be left alone, because wrapping them would break framing or
// the tunnel rather than protect anything:
//
//   - a HEAD response. goproxy preserves a HEAD response's Content-Length only
//     while the body reader is unchanged (see goproxy's handleHttp), so
//     wrapping it strips a length the agent is entitled to.
//   - a 101 upgrade. net/http hands back a body that is also an io.ReadWriter
//     and goproxy hijacks the connection to speak raw bytes over it; wrapping
//     it turns a working tunnel into a broken one.
//
// A nil body has nothing to scrub either.
func bodyIsScrubbable(resp *http.Response) bool {
	switch {
	case resp.Body == nil, resp.Body == http.NoBody:
		return false
	case resp.Request.Method == http.MethodHead:
		return false
	}
	if _, isTunnel := resp.Body.(io.ReadWriter); isTunnel {
		return false
	}
	return true
}

// scrubHeaderValues deletes every header value in h that contains a
// credential. Deleting the whole value (rather than blanking the credential in
// place) keeps a reflected credential from surviving in any encoding of its
// neighbours, and a header that carried the credential is not trustworthy
// anyway.
func scrubHeaderValues(h http.Header, needles [][]byte) {
	for name, values := range h {
		for _, v := range values {
			if containsAnyNeedle(v, needles) {
				h.Del(name)
				break
			}
		}
	}
}

// containsAnyNeedle reports whether v holds any needle as a substring. It
// matches the escaped forms as well as the raw credential, because a header
// echoing a percent-encoded path or query carries the escaped form.
func containsAnyNeedle(v string, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains([]byte(v), n) {
			return true
		}
	}
	return false
}

// hostOf returns the destination host for log attribution, tolerating a
// request whose URL was cleared.
func hostOf(req *http.Request) string {
	if req.URL == nil {
		return req.Host
	}
	return req.URL.Host
}

// scrubber wraps an upstream response body and replaces every occurrence of a
// brokered credential as the bytes stream past, without ever materialising the
// body.
//
// The only state carried between reads is the tail of the previous fill that
// could still be the beginning of an occurrence. That is what makes the
// transform safe across arbitrary transport chunking: an occurrence split
// across two, three, or a hundred reads is still found, because the bytes are
// held until either the rest of the occurrence arrives or the stream ends.
//
// Holding back unconditionally — always len(longest needle)-1 bytes — would be
// simpler and would break SSE: an event smaller than one credential length
// would not be delivered until that many trailing bytes arrived.
// partialSuffixLen withholds only what can actually still match, so the common
// case retains nothing and each event goes out as soon as upstream sends it.
type scrubber struct {
	src     io.ReadCloser
	needles [][]byte

	// buf is the scratch buffer upstream bytes are read into. It is allocated
	// once and reused for the life of the response.
	buf []byte
	// fill is the undecided tail carried from the previous read: bytes that
	// could still turn out to be the start of an occurrence.
	fill []byte
	// ready is scrubbed bytes waiting for the caller to take them.
	ready []byte
	// err is the sticky terminal error from src.
	err error
}

// newScrubber wraps src so every occurrence of a needle is replaced with
// scrubbedMarker. An empty needle set still streams, so the caller does not
// need a separate pass-through type.
func newScrubber(src io.ReadCloser, needles [][]byte) *scrubber {
	return &scrubber{
		src:     src,
		needles: needles,
		buf:     make([]byte, scrubChunkSize),
		ready:   make([]byte, 0, scrubChunkSize),
	}
}

// Read implements io.Reader. It returns whatever the current fill made
// available rather than filling p, so a trickle upstream is relayed at
// upstream's pace instead of being batched up to p's size.
func (s *scrubber) Read(p []byte) (int, error) {
	for len(s.ready) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		s.fillOnce()
	}
	n := copy(p, s.ready)
	s.ready = s.ready[n:]
	return n, nil
}

func (s *scrubber) fillOnce() {
	n, err := s.src.Read(s.buf)
	if n > 0 {
		s.fill = append(s.fill, s.buf[:n]...)
	}
	if err != nil {
		// The stream is over: the retained tail can no longer grow into an
		// occurrence, so it is decided now rather than dropped. Decided once,
		// on one pass — a second pass would reset the ready buffer and discard
		// whatever the data-bearing read already moved into it.
		s.scrubFill(true)
		s.err = err
		return
	}
	if n > 0 {
		s.scrubFill(false)
	}
}

// scrubFill moves as much of the accumulated fill as can be decided into
// ready, retaining the trailing bytes that are still a proper prefix of a
// needle.
//
// final reports that the upstream stream has ended, in which case nothing is
// retained.
func (s *scrubber) scrubFill(final bool) {
	if len(s.fill) == 0 {
		return
	}
	hold := 0
	if !final {
		hold = partialSuffixLen(s.fill, s.needles)
		if hold > 0 {
			hold = s.holdBackSplit(hold)
		}
	}
	// Read only calls fillOnce when ready is drained, so it is always empty
	// here and the scrubbed bytes land in its existing capacity.
	s.ready = replaceAll(s.ready[:0], s.fill[:len(s.fill)-hold], s.needles)
	// Move the retained bytes to the front so the buffer does not grow without
	// bound over a long-lived stream.
	s.fill = append(s.fill[:0], s.fill[len(s.fill)-hold:]...)
}

// holdBackSplit widens the withhold so that no occurrence straddles the
// emitted/retained boundary.
//
// partialSuffixLen answers "can the tail still become an occurrence?", which is
// necessary but not sufficient. With a self-overlapping needle the retained
// tail can be the second half of an occurrence whose first half was already
// emitted: needle "abab" over body "abab" withholds "ab", emits "ab" (no match
// is visible yet), and then emits the retained "ab" at EOF. The agent
// reassembles the credential from two halves that each looked innocent.
//
// So walk the boundary backwards while the bytes immediately before it are
// themselves the start of a partial occurrence. When hold is zero there is no
// pending prefix and none of this can apply, so the common case costs nothing.
func (s *scrubber) holdBackSplit(hold int) int {
	boundary := len(s.fill) - hold
	for boundary > 0 && endsWithNeedlePrefix(s.fill[:boundary], s.needles) {
		boundary--
	}
	return len(s.fill) - boundary
}

// endsWithNeedlePrefix reports whether some suffix of prefix is a proper
// prefix of some needle — that is, whether an occurrence could start before
// the end of prefix and continue past it.
func endsWithNeedlePrefix(prefix []byte, needles [][]byte) bool {
	for _, n := range needles {
		limit := len(n) - 1
		if limit > len(prefix) {
			limit = len(prefix)
		}
		for k := limit; k > 0; k-- {
			if bytes.Equal(prefix[len(prefix)-k:], n[:k]) {
				return true
			}
		}
	}
	return false
}

// replaceAll appends src to dst with every occurrence of a needle replaced by
// scrubbedMarker. Occurrences are matched leftmost-first and, where two
// needles match at the same offset, the longest wins — so a credential that is
// a prefix of another cannot leave the tail of the longer one behind.
func replaceAll(dst, src []byte, needles [][]byte) []byte {
	for i := 0; i < len(src); {
		at, width := nextMatch(src, needles, i)
		if width == 0 {
			return append(dst, src[i:]...)
		}
		dst = append(dst, src[i:at]...)
		dst = append(dst, scrubbedMarker...)
		i = at + width
	}
	return dst
}

// nextMatch returns the offset of the first occurrence of any needle at or
// after from, and that occurrence's width. A zero width means no needle occurs
// in src[from:].
func nextMatch(src []byte, needles [][]byte, from int) (at, width int) {
	at, width = -1, 0
	for _, n := range needles {
		i := bytes.Index(src[from:], n)
		if i < 0 {
			continue
		}
		i += from
		if at < 0 || i < at || (i == at && len(n) > width) {
			at, width = i, len(n)
		}
	}
	if at < 0 {
		return 0, 0
	}
	return at, width
}

// partialSuffixLen returns the length of the longest suffix of b that is a
// proper prefix of one of the needles — the number of trailing bytes an
// occurrence could still begin at, and therefore the number that must be
// withheld until more bytes arrive. Zero means the tail cannot start an
// occurrence and nothing needs to be held back.
//
// The result is always less than the longest needle, which bounds the retained
// state to at most one credential length regardless of body size.
func partialSuffixLen(b []byte, needles [][]byte) int {
	longest := 0
	for _, n := range needles {
		if len(n)-1 > longest {
			longest = len(n) - 1
		}
	}
	// Start from the largest candidate and shrink: the first hit is the
	// answer, and the loop is bounded by the longest credential.
	for k := min(longest, len(b)); k > 0; k-- {
		suffix := b[len(b)-k:]
		for _, n := range needles {
			if len(n) > k && bytes.Equal(n[:k], suffix) {
				return k
			}
		}
	}
	return 0
}

// Close closes the upstream body.
func (s *scrubber) Close() error { return s.src.Close() }
