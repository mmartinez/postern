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

// dropStaleBodyMetadata removes the headers that describe the body as it
// arrived upstream. Once redaction has rewritten that body they all describe
// something the agent will never receive: a length it is not, a byte range
// that no longer lines up, a digest over bytes it did not get.
func dropStaleBodyMetadata(resp *http.Response) {
	resp.ContentLength = -1
	for _, h := range [...]string{
		"Content-Length",
		"Content-Range",
		"ETag",
		"Digest",
		"Content-MD5",
	} {
		resp.Header.Del(h)
	}
}

// credentialNeedle is one byte pattern the scrubber must never let past, and
// whether hex case may be folded when matching it.
type credentialNeedle struct {
	pat []byte
	// foldHex is set only for the percent-escaped forms postern itself
	// produced. A raw credential is a case-sensitive literal: when it happens
	// to contain a percent sequence such as abc%2Fdef, folding would make it
	// also match abc%2fdef — a different string — rewriting an unrelated
	// response or deleting an unrelated header.
	foldHex bool
}

// needleKey identifies a pattern for dedupe. The folding flag is part of the
// key because the same string can be needed twice under different matching
// rules: one credential's raw value can be another's percent-escaped form, and
// suppressing the folded copy would leave that second credential's escaped and
// lowercased casing unsrubbed.
type needleKey struct {
	pat     string
	foldHex bool
}

// credentialNeedles builds the byte patterns that must never reach the agent.
//
// Injection does not always put the credential on the wire verbatim: a path or
// query substitution percent-escapes it, so an upstream that echoes the
// request reflects the ESCAPED form. Matching only the raw value would leave
// that copy in the response. The escaped forms are what
// broker's substitutePath and substituteQuery can emit, so they are the forms
// worth carrying.
//
// The escaped forms' hex casing is deliberately not pinned. Percent-decoding is
// case-insensitive, so %2f and %2F decode to the same byte, and indexNeedle
// matches the two digits behind a % in either case — covering an upstream that
// re-encodes the path it was handed, and one that mixes casing digit by digit,
// without carrying 2^n variants of every escaped needle. The raw credential is
// matched byte-for-byte whatever percent sequences it happens to contain.
func credentialNeedles(creds []string) []credentialNeedle {
	needles := make([]credentialNeedle, 0, len(creds)*3)
	seen := make(map[needleKey]struct{}, len(creds)*3)
	add := func(s string, foldHex bool) {
		if s == "" {
			return
		}
		key := needleKey{pat: s, foldHex: foldHex}
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		needles = append(needles, credentialNeedle{pat: []byte(s), foldHex: foldHex})
	}
	for _, c := range creds {
		add(c, false)
		add(url.QueryEscape(c), true)
		add(url.PathEscape(c), true)
	}
	return needles
}

// indexNeedle returns the offset of the first occurrence of n in hay, or -1 if
// there is none. Hex folding applies only where n is a percent-escaped form
// that actually carries a %; everything else takes the assembly-optimised
// bytes.Index path unchanged.
func indexNeedle(hay []byte, n credentialNeedle) int {
	pct := bytes.IndexByte(n.pat, '%')
	if !n.foldHex || pct < 0 {
		return bytes.Index(hay, n.pat)
	}
	// Anchor the scan on the leading literal run: it must match byte for byte,
	// and bytes.Index locates its occurrences fast, so the candidate set stays
	// small instead of testing every offset in the body.
	anchor := []byte{'%'}
	if pct > 0 {
		anchor = n.pat[:pct]
	}
	for off := 0; ; {
		j := bytes.Index(hay[off:], anchor)
		if j < 0 {
			return -1
		}
		off += j
		if equalNeedle(n.pat, hay[off:]) {
			return off
		}
		off++
	}
}

// prefixMatches reports whether the bytes of n.pat preceding suffix's length
// equal suffix, folding hex case only where n is a percent-escaped form. It is
// what lets a partial occurrence survive a read boundary with the same casing
// rules the full scan uses.
func prefixMatches(n credentialNeedle, suffix []byte) bool {
	prefix := n.pat[:len(suffix)]
	if !n.foldHex || bytes.IndexByte(prefix, '%') < 0 {
		return bytes.Equal(prefix, suffix)
	}
	return equalNeedle(prefix, suffix)
}

// equalNeedle reports whether needle occurs at the start of hay. Bytes must
// match exactly, except the two hex digits behind a % in the needle, which
// match in either ASCII case because percent-decoding ignores hex case. A byte
// is foldable only while it sits inside the %HH group the needle itself
// declares, so literal text after an escape is never case-folded.
func equalNeedle(needle, hay []byte) bool {
	if len(needle) > len(hay) {
		return false
	}
	escaped := 0 // bytes left in the %HH group being matched
	for i := range len(needle) {
		if needle[i] == '%' {
			escaped = 2
			if hay[i] != '%' {
				return false
			}
			continue
		}
		foldable := escaped > 0
		if escaped > 0 {
			escaped--
		}
		if needle[i] == hay[i] {
			continue
		}
		if foldable && isHexLetter(needle[i]) && isHexLetter(hay[i]) &&
			lowerHexDigit(needle[i]) == lowerHexDigit(hay[i]) {
			continue
		}
		return false
	}
	return true
}

// isHexLetter reports whether c is a letter a-f or A-F. Digits 0-9 need no
// folding, and anything else is literal text that must match exactly.
func isHexLetter(c byte) bool {
	return (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}

// lowerHexDigit maps an uppercase hex letter to lowercase and returns
// everything else — digits, lowercase letters, non-hex bytes — untouched.
func lowerHexDigit(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// scrubResponse strips the credential the broker injected on this request out
// of the upstream response, so an upstream that reflects the credential back —
// in a Set-Cookie, in a JSON error body, in an SSE frame, in a trailer — cannot
// hand it to the agent.
//
// It returns resp unchanged when the broker injected no credential, which is
// the passthrough case: no scan, no allocation, no new reader. That is why the
// credential hand-off is a request-context value rather than a filter the
// broker installs unconditionally.
//
// The body is scrubbed by a streaming transform and never buffered. Anything
// else turns a trickling upstream into a stalled agent: an earlier version
// read small fixed-length responses whole so the metadata decision could be
// exact, and an upstream sending 5 KB incrementally then delivered neither
// headers nor a first chunk until every declared byte had arrived. The price
// is that validators are dropped before anyone knows whether redaction will
// happen — a response that echoes nothing loses an ETag it could have kept.
// A dropped validator is recoverable; a Content-Range or digest that no
// longer describes the delivered bytes is not.
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

	// A HEAD response, a 101 upgrade and a bodyless response are left alone:
	// wrapping those breaks framing or the tunnel rather than protecting
	// anything.
	scrubbable := bodyIsScrubbable(resp)

	// The encoding gate is decided before this function mutates a single
	// header. It reads Content-Encoding, which scrubHeaderValues below deletes
	// whole when the value carries the credential — so an upstream that folds
	// the credential into its own Content-Encoding value would have that header
	// removed first, and the gate would then see no encoding at all and forward
	// a compressed body it cannot inspect.
	//
	// The broker hook drops Accept-Encoding on brokered requests, so this
	// transport negotiates and transparently decodes gzip itself, which is what
	// leaves the scrubber plaintext. Anything still carrying a Content-Encoding
	// at this point reached us compressed with the credential sealed inside,
	// where no byte matcher can reach it: deflate, br, the x-gzip alias, a
	// stacked "gzip, gzip", and anything at all on a ranged request, where Go
	// skips transparent decoding outright. Forwarding that hands the agent the
	// credential the moment it decompresses, so fail closed with the same
	// generic 502 every other refusal already uses.
	encoding := resp.Header.Get("Content-Encoding")
	if scrubbable && !resp.Uncompressed && encoding != "" && !strings.EqualFold(encoding, "identity") {
		logger.Warn("refusing an upstream response the credential scrubber cannot inspect",
			slog.String("host", hostOf(resp.Request)),
			slog.String("content_encoding", encodingLabel(encoding)),
		)
		_ = resp.Body.Close()
		return bad502(resp.Request)
	}

	scrubHeaderValues(resp.Header, needles)
	// Go fills Response.Trailer in two stages: the keys arrive with the header
	// block, the values only once the body reaches EOF. This pass takes
	// whatever is already there — which for the shapes whose body is never
	// wrapped is all there ever is — and the scrubber takes the real values
	// when upstream declares the body over.
	scrubHeaderValues(resp.Trailer, needles)

	if scrubbable {
		resp.Body = newScrubber(resp.Body, needles, &resp.Trailer)
		dropStaleBodyMetadata(resp)
	} else if resp.StatusCode == http.StatusSwitchingProtocols {
		// The tunnel itself cannot be scanned — goproxy hijacks the connection
		// and relays raw frames — and that is a recorded caveat. Say it on every
		// one, so a brokered host that upgrades is never mistaken for a host
		// postern inspected end to end.
		logger.Warn("brokered request upgraded to a protocol tunnel; its frames are not scrubbed",
			slog.String("host", hostOf(resp.Request)),
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
func scrubHeaderValues(h http.Header, needles []credentialNeedle) {
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
func containsAnyNeedle(v string, needles []credentialNeedle) bool {
	for _, n := range needles {
		if indexNeedle([]byte(v), n) >= 0 {
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

// encodingLabel names the coding an upstream used, for the refusal warning.
// The Content-Encoding value is upstream-controlled and can carry the
// credential itself, so it is never echoed: only a name on this fixed list is
// reported and everything else collapses to "other". That is what makes it
// safe — no byte of the input reaches the log, whatever the upstream sends.
func encodingLabel(encoding string) string {
	coding, _, _ := strings.Cut(encoding, ";")
	coding = strings.ToLower(strings.TrimSpace(coding))
	switch coding {
	case "gzip", "x-gzip", "deflate", "br", "zstd", "compress", "identity":
		return coding
	default:
		return "other"
	}
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
//
// The trailer map is scrubbed at the terminal read instead of on the way in,
// because that is the only moment its values exist: Go fills them in the Read
// that reports the end of the body. It is held as a pointer to the field for
// the same reason — HTTP/2 may install a fresh map after the scrubber is built.
type scrubber struct {
	src     io.ReadCloser
	needles []credentialNeedle

	// buf is the scratch buffer upstream bytes are read into. It is allocated
	// once and reused for the life of the response.
	buf []byte
	// fill is the undecided tail carried from the previous read: bytes that
	// could still turn out to be the start of an occurrence.
	fill []byte
	// ready is scrubbed bytes waiting for the caller to take them.
	ready []byte
	// trailer points at the response's trailer map, read once the body is over
	// rather than captured by value, because HTTP/2 can install a brand-new map
	// into resp.Trailer after this scrubber was constructed. nil when the caller
	// has no trailers to protect.
	trailer *http.Header
	// err is the sticky terminal error from src.
	err error
}

// newScrubber wraps src so every occurrence of a needle is replaced with
// scrubbedMarker. An empty needle set still streams, so the caller does not
// need a separate pass-through type. trailer, when non-nil, is scrubbed at the
// end of the stream.
func newScrubber(src io.ReadCloser, needles []credentialNeedle, trailer *http.Header) *scrubber {
	return &scrubber{
		src:     src,
		needles: needles,
		trailer: trailer,
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
		// This is the only moment the trailer values exist: Go fills them in
		// the Read that reports the end of the body, and goproxy copies
		// resp.Trailer to the agent only after the body has been drained.
		//
		// The field is read through the pointer rather than captured by value,
		// because HTTP/2 installs a brand-new map into resp.Trailer when an
		// upstream sends a trailer it never announced: copyTrailers does
		// `if *t == nil { *t = make(http.Header) }` against &resp.Trailer. A
		// snapshot taken when the scrubber was built would still be the old,
		// empty map.
		if s.trailer != nil {
			scrubHeaderValues(*s.trailer, s.needles)
		}
		s.err = err
		return
	}
	if n > 0 {
		s.scrubFill(false)
	}
}

// scrubFill moves as much of the accumulated fill as can be decided into
// ready, and withholds only the bytes the leftmost-first scan never settled.
//
// The scan reports where it stopped: everything up to there either matched or
// was literal text before the last consumed occurrence. Only bytes past that
// point can still become an occurrence, so those are the only ones to hold.
//
// Measuring the tail from the end of the fill instead — the obvious reading —
// is wrong in both directions. It withholds bytes the scan has already decided
// (needle "abab" over body "abab" would emit "ab" before the occurrence
// resolved), and the fix for that, walking the boundary back while the
// preceding bytes could start an occurrence, never terminates on a body whose
// bytes keep repeating a credential prefix — the boundary slides to zero on
// every read, nothing is emitted, and the fill grows for the life of the
// stream. Anchoring the withhold to the scan keeps it bounded by one credential
// length no matter what the body contains.
//
// final reports that the upstream stream has ended, in which case nothing is
// withheld.
func (s *scrubber) scrubFill(final bool) {
	if len(s.fill) == 0 {
		return
	}
	ready, lastCut := replaceAll(s.ready[:0], s.fill, s.needles)
	hold := 0
	if !final {
		hold = partialSuffixLen(s.fill[lastCut:], s.needles)
	}
	// replaceAll appended every byte, including the ones about to be withheld,
	// so give the withheld tail back before the caller can take it.
	if hold > 0 {
		ready = ready[:len(ready)-hold]
	}
	s.ready = ready
	// Move the retained bytes to the front so the buffer does not grow without
	// bound over a long-lived stream. hold is bounded by one credential length,
	// so the scrubber's state is bounded no matter what the body contains.
	s.fill = append(s.fill[:0], s.fill[len(s.fill)-hold:]...)
}

// replaceAll appends src to dst with every occurrence of a needle replaced by
// scrubbedMarker, and returns the index in src just past the last occurrence it
// consumed (0 if it consumed none). Occurrences are matched leftmost-first and,
// where two needles match at the same offset, the longest wins, so a credential
// that is a prefix of another cannot leave the tail of the longer one behind.
//
// That index is what lets a streaming caller withhold exactly the right bytes:
// everything up to it is settled, so a fill that already contains a whole
// occurrence withholds nothing at all.
func replaceAll(dst, src []byte, needles []credentialNeedle) (out []byte, lastCut int) {
	for i := 0; i < len(src); {
		at, width := nextMatch(src, needles, i)
		if width == 0 {
			return append(dst, src[i:]...), lastCut
		}
		dst = append(dst, src[i:at]...)
		dst = append(dst, scrubbedMarker...)
		i = at + width
		lastCut = i
	}
	return dst, lastCut
}

// nextMatch returns the offset of the first occurrence of any needle at or
// after from, and that occurrence's width. A zero width means no needle occurs
// in src[from:].
func nextMatch(src []byte, needles []credentialNeedle, from int) (at, width int) {
	at, width = -1, 0
	for _, n := range needles {
		i := indexNeedle(src[from:], n)
		if i < 0 {
			continue
		}
		i += from
		if at < 0 || i < at || (i == at && len(n.pat) > width) {
			at, width = i, len(n.pat)
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
func partialSuffixLen(b []byte, needles []credentialNeedle) int {
	longest := 0
	for _, n := range needles {
		if len(n.pat)-1 > longest {
			longest = len(n.pat) - 1
		}
	}
	// Start from the largest candidate and shrink: the first hit is the
	// answer, and the loop is bounded by the longest credential.
	for k := min(longest, len(b)); k > 0; k-- {
		suffix := b[len(b)-k:]
		for _, n := range needles {
			if len(n.pat) > k && prefixMatches(n, suffix) {
				return k
			}
		}
	}
	return 0
}

// Close closes the upstream body.
func (s *scrubber) Close() error { return s.src.Close() }
