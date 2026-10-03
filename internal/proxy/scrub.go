package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
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

	scrubHeaderValues(resp.Header, creds)
	scrubHeaderValues(resp.Trailer, creds)

	if bodyIsScrubbable(resp) {
		needles := make([][]byte, 0, len(creds))
		for _, c := range creds {
			needles = append(needles, []byte(c))
		}
		resp.Body = newScrubber(resp.Body, needles)
		// The scrubbed body is a different length than the one upstream
		// framed, so the length has to be dropped and recomputed by the
		// chunked writer.
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
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
func scrubHeaderValues(h http.Header, creds []string) {
	for name, values := range h {
		for _, v := range values {
			if containsAny(v, creds) {
				h.Del(name)
				break
			}
		}
	}
}

// containsAny reports whether v holds any credential as a substring.
func containsAny(v string, creds []string) bool {
	for _, c := range creds {
		if strings.Contains(v, c) {
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

// fillOnce performs one upstream read and scrubs what it can, retaining only
// the trailing bytes that could still start an occurrence.
func (s *scrubber) fillOnce() {
	n, err := s.src.Read(s.buf)
	if n > 0 {
		s.fill = append(s.fill, s.buf[:n]...)
		s.scrubFill(false)
	}
	if err != nil {
		// The stream is over: the retained tail can no longer grow into an
		// occurrence, so it is decided now rather than dropped.
		s.scrubFill(true)
		s.err = err
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
	}
	// Read only calls fillOnce when ready is drained, so it is always empty
	// here and the scrubbed bytes land in its existing capacity.
	s.ready = replaceAll(s.ready[:0], s.fill[:len(s.fill)-hold], s.needles)
	// Move the retained bytes to the front so the buffer does not grow without
	// bound over a long-lived stream.
	s.fill = append(s.fill[:0], s.fill[len(s.fill)-hold:]...)
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
