package proxy

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// eofWithDataReader returns data and io.EOF from the same Read call, which
// io.Reader explicitly permits and which a real transport does at end of body.
type eofWithDataReader struct {
	data []byte
	done bool
}

func (r *eofWithDataReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.data)
	return n, io.EOF
}

func (r *eofWithDataReader) Close() error { return nil }

// Greptile P1: an occurrence must never be split across the emitted/retained
// boundary. With a self-overlapping needle the withheld tail can be the second
// half of an occurrence whose first half was already emitted, so the agent
// reassembles the credential from two innocent-looking halves.
func TestScrubber_SelfOverlappingNeedleIsNotSplitAcrossBoundary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		needle string
		body   string
	}{
		{"identical", "abab", "abab"},
		{"prefix_and_tail", "abab", "abababab"},
		{"single char", "aa", "aaaa"},
		{"long overlap", "sk-antsk-ant", "sk-antsk-ant"},
		{"embedded", "abab", "xxababyy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newScrubber(io.NopCloser(strings.NewReader(tc.body)), credentialNeedles([]string{tc.needle}), nil)
			got := readAll(t, s)
			require.NotContains(t, got, tc.needle,
				"the credential survived because it was split across the emit boundary")
		})
	}
}

// The same hazard driven one byte at a time, which is the worst case for
// boundary splitting: every possible split point is exercised.
func TestScrubber_SelfOverlappingNeedleByteAtATime(t *testing.T) {
	t.Parallel()

	s := newScrubber(io.NopCloser(&oneByteReader{data: []byte("abab")}), credentialNeedles([]string{"abab"}), nil)
	got := readAll(t, s)
	require.NotContains(t, got, "abab")
}

// The hazard needs the body to END in a partial needle prefix: only then does
// the first pass leave a retained tail for the error path to re-scan, and only
// then does the reset of the ready buffer discard real output.
func TestScrubber_TerminalReadReturningDataAndEOFTogether(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		body   string
		needle string
		want   string
	}{
		{"ends mid-credential", "payload sk-secret-1234 tail sk-sec", "sk-secret-1234", "payload <redacted> tail sk-sec"},
		{"no retained tail", "hello sk-secret-1234 world", "sk-secret-1234", "hello <redacted> world"},
		{"no needle at all", "nothing to redact here", "sk-secret-1234", "nothing to redact here"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newScrubber(&eofWithDataReader{data: []byte(tc.body)}, credentialNeedles([]string{tc.needle}), nil)
			got := readAll(t, s)
			require.Equal(t, tc.want, got, "bytes were dropped or reordered by the terminal read")
			require.NotContains(t, got, tc.needle)
		})
	}
}

// Greptile P1: injection percent-escapes the credential when it lands in a
// path or a query. An upstream that echoes that request back reflects the
// ESCAPED form, which a raw-needle match does not find.
func TestScrubResponse_ScrubsEscapedFormsOfTheCredential(t *testing.T) {
	t.Parallel()

	cred := "sk+ant/api03=secret"
	req := requestWithCredential(http.MethodGet, cred)
	resp := &http.Response{
		Request: req,
		Header:  http.Header{"Content-Type": []string{"text/plain"}},
		Body: io.NopCloser(strings.NewReader(
			"path=/v1/" + url.PathEscape(cred) + " query=?k=" + url.QueryEscape(cred) + " raw=" + cred,
		)),
		ContentLength: -1,
	}

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()
	got := readAll(t, scrubbed.Body)

	require.NotContains(t, got, cred)
	require.NotContains(t, got, url.PathEscape(cred), "path-escaped credential survived")
	require.NotContains(t, got, url.QueryEscape(cred), "query-escaped credential survived")
}

// Percent-decoding is case-insensitive, so an upstream that re-encodes the
// path it was handed can reflect %2f where postern sent %2F. The agent decodes
// both to the same credential, so the lowercase rendering is just as exposed as
// the one postern emits.
func TestScrubResponse_ScrubsLowercaseEscapedFormsOfTheCredential(t *testing.T) {
	t.Parallel()

	cred := "sk+ant/api03=secret"
	lower := "sk%2bant%2fapi03%3dsecret"
	decoded, err := url.QueryUnescape(lower)
	require.NoError(t, err)
	require.Equal(t, cred, decoded,
		"precondition: percent-decoding ignores hex case, so this is the same credential")
	require.NotEqual(t, url.QueryEscape(cred), lower,
		"precondition: the lowercase rendering is not the needle already carried")

	body := "url=https://x/v1?k=" + lower + "&ok=1"
	resp := &http.Response{
		Request:       requestWithCredential(http.MethodGet, cred),
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()
	got := readAll(t, scrubbed.Body)

	require.NotContains(t, got, lower, "a lowercase percent-escaped credential survived")
	require.Contains(t, got, "&ok=1", "the surrounding response was mangled")
}

// The case-insensitive hex match has to survive a read boundary, not just work
// inside one buffer. partialSuffixLen is what decides this: if it compares the
// trailing bytes case-sensitively, a body ending in %2b is emitted immediately,
// the rest arrives on the next read, and the agent reassembles the credential
// out of two halves that each looked harmless.
func TestScrubber_MixedCaseEscapeSplitAcrossReadsIsCaught(t *testing.T) {
	t.Parallel()

	cred := "sk+ant/api03=secret"
	mixed := "sk%2bant%2Fapi03%3dsecret"
	split := strings.Index(mixed, "%2F") + 2 // land inside an escape group
	require.Equal(t, "sk%2bant%2", mixed[:split], "precondition: the split lands mid-escape")

	r := io.MultiReader(
		strings.NewReader("head "+mixed[:split]),
		strings.NewReader(mixed[split:]+" tail"),
	)
	s := newScrubber(io.NopCloser(r), credentialNeedles([]string{cred}), nil)

	got := readAll(t, s)
	require.NotContains(t, got, mixed, "a mixed-case escaped credential survived")
	require.Contains(t, got, "head ", "the response before the credential was mangled")
	require.Contains(t, got, " tail", "the response after the credential was mangled")
}

// The raw credential is case-sensitive and must stay that way: SK-ANT-... is
// not the secret, and redacting it would corrupt an honest response.
func TestScrubber_RawCredentialIsMatchedCaseSensitively(t *testing.T) {
	t.Parallel()

	upper := strings.ToUpper(testCredential)
	require.NotEqual(t, testCredential, upper)

	s := newScrubber(
		io.NopCloser(strings.NewReader("token="+upper)),
		credentialNeedles([]string{testCredential}),
		nil,
	)
	require.Equal(t, "token="+upper, readAll(t, s),
		"a credential differing only in case was redacted, which corrupts the response")
}

// HTTP/2 stores a pointer to resp.Trailer in the transport, and for a trailer
// the upstream never announced it installs a brand-new map at end of stream:
// copyTrailers does `if *t == nil { *t = make(http.Header) }`. HTTP/2 allows
// unannounced trailers where HTTP/1.1 does not, so a real h2 server can
// produce this shape. Go's own server cannot: it announces every trailer from
// the Trailer header, and setting the key with http.TrailerPrefix after the
// body does not produce one either — an attempt at that leaves resp.Trailer
// allocated but empty. So the assignment is reproduced here directly, which is
// what actually needs pinning. A scrubber that captured resp.Trailer by value
// would still hold the nil map it saw when the body was wrapped, and the
// credential would reach the agent intact.
func TestScrubResponse_ScrubsTrailerMapInstalledAfterTheBodyWasWrapped(t *testing.T) {
	t.Parallel()

	body := "harmless body"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    requestWithCredential(http.MethodGet, testCredential),
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Trailer:    nil, // unannounced HTTP/2 trailers leave this nil until EOF
	}

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()

	// Exactly what http2's copyTrailers does against &resp.Trailer.
	if scrubbed.Trailer == nil {
		scrubbed.Trailer = make(http.Header)
	}
	scrubbed.Trailer.Set("X-Audit", "key="+testCredential)

	require.Equal(t, body, readAll(t, scrubbed.Body))
	require.Empty(t, scrubbed.Trailer.Get("X-Audit"),
		"the credential survived in a trailer installed after the body was wrapped")
}

// Greptile P2: redaction changes the body's length, so every piece of metadata
// describing the pre-redaction body is now wrong. Content-Length is already
// dropped; the rest must go too, or a client assembling ranges or verifying a
// digest gets told the delivered body is something it is not.
func TestScrubResponse_DropsMetadataThatDescribesTheUnredactedBody(t *testing.T) {
	t.Parallel()

	req := requestWithCredential(http.MethodGet, "sk-secret-1234")
	resp := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader("sk-secret-1234")),
		ContentLength: int64(len("sk-secret-1234")),
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len("sk-secret-1234")))
	resp.Header.Set("Content-Range", "bytes 0-10/1024")
	resp.Header.Set("ETag", `"v1"`)
	resp.Header.Set("Digest", "sha-256=abc")
	resp.Header.Set("Content-MD5", "Zm9v")

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()

	for _, h := range []string{"Content-Length", "Content-Range", "ETag", "Digest", "Content-MD5"} {
		require.Empty(t, resp.Header.Get(h), "%s describes the pre-redaction body", h)
	}
}

// repeatingPrefixReader serves one long run of a single byte and then io.EOF,
// counting its reads. It stands in for a long-lived stream — an event feed, a
// watch — whose every byte is a possible credential prefix. It ends after a
// fixed byte count on purpose: a reader that never returns EOF turns a
// reintroduced stall into a hung suite instead of a failing test.
type repeatingPrefixReader struct {
	b     byte
	left  int
	reads int
}

func (r *repeatingPrefixReader) Read(p []byte) (int, error) {
	r.reads++
	if r.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.left)
	for i := range n {
		p[i] = r.b
	}
	r.left -= n
	return n, nil
}

func (r *repeatingPrefixReader) Close() error { return nil }

// A body whose bytes keep repeating a credential PREFIX must not stall and
// must not be buffered. An earlier version walked the withhold boundary back
// whenever the bytes before it could start an occurrence; against a run of "a"
// with credential "ab", every trailing "a" is a possible prefix and no
// complete occurrence ever exists, so that version emitted nothing, never
// terminated its scan, and grew the fill for the life of the stream.
func TestScrubber_RepeatingCredentialPrefixDoesNotStallOrBuffer(t *testing.T) {
	t.Parallel()

	const needle = "ab"
	src := &repeatingPrefixReader{b: 'a', left: 4 * scrubChunkSize}
	s := newScrubber(src, credentialNeedles([]string{needle}), nil)

	first := make([]byte, 4096)
	n, err := s.Read(first)
	require.NoError(t, err)
	require.Positive(t, n, "a stream of repeated credential prefixes must still deliver data")
	require.Equal(t, 1, src.reads,
		"the first read had to drain the stream before it could answer; upstream's pace is the agent's pace")
	require.LessOrEqual(t, len(s.fill), len(needle),
		"the scrubber retained more than one credential length, so it is buffering the stream")
}

// countingReader counts Read calls so a test can tell whether a body was
// drained before the response was handed to the agent.
type countingReader struct {
	data  []byte
	off   int
	reads int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads++
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func (r *countingReader) Close() error { return nil }

// Greptile P1: a small fixed-length response must not have its body drained
// before the response is handed on. An earlier version read any response
// declaring 64 KiB or less in full so it could decide the metadata exactly,
// which means an upstream streaming 5 KB incrementally delivers neither
// headers nor the first chunk until every declared byte has arrived — the
// stall this scrubber exists to prevent.
func TestScrubResponse_DoesNotDrainSmallFixedLengthBodyBeforeReturning(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("x", 5<<10)
	src := &countingReader{data: []byte(body)}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Request:       requestWithCredential(http.MethodGet, testCredential),
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          src,
		ContentLength: int64(len(body)),
	}

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()

	require.Zero(t, src.reads,
		"scrubResponse read the upstream body before returning; a fixed-length response would stall the exchange")
	require.Equal(t, body, readAll(t, scrubbed.Body),
		"an unchanged body must still reach the agent byte-for-byte")
}

// A credential reflected in a wire trailer must not reach the agent. Go fills
// Response.Trailer in two stages — the keys arrive with the header block, the
// values only once the body hits EOF — so a scrub that runs before the body is
// read sees an empty map and the trailer goes out carrying the credential.
// This drives a real chunked response over a real transport, because a
// hand-built response with a pre-populated Trailer map cannot reproduce the
// timing that turns this into a leak.
func TestScrubResponse_ScrubsCredentialFromWireTrailer(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Audit")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "harmless body")
		w.Header().Set("X-Audit", "key="+testCredential)
	}))
	defer upstream.Close()

	resp, err := http.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	resp.Request = requestWithCredential(http.MethodGet, testCredential)
	require.Empty(t, resp.Trailer.Get("X-Audit"),
		"precondition: trailer values arrive only at EOF, which is why an early scrub finds nothing to delete")

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()
	require.Equal(t, "harmless body", readAll(t, scrubbed.Body))

	require.Empty(t, scrubbed.Trailer.Get("X-Audit"),
		"the credential survived in a trailer the agent receives after the body")
}

// A response that never echoes the credential must reach the agent exactly as
// upstream sent it. The scrubber cannot know whether it will redact anything
// until the body has started flowing, so it commits to streaming and drops the
// validators up front rather than risk a Content-Range or digest describing
// bytes it is about to rewrite. Losing a validator is the accepted cost; a
// false one is a framing bug.
func TestScrubResponse_UnchangedBodyIsDeliveredByteForByte(t *testing.T) {
	t.Parallel()

	body := "a perfectly ordinary json body with nothing secret in it"
	req := requestWithCredential(http.MethodGet, "sk-secret-1234")
	resp := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()

	require.Equal(t, body, readAll(t, scrubbed.Body), "an unchanged body must pass through byte-for-byte")
}

// A response that under-declares its Content-Length must not be truncated, and
// must not have its unscanned tail handed to the agent. An upstream-declared
// length is never a bound: the body streams to EOF, so the undeclared tail is
// both delivered and scanned.
func TestScrubResponse_UnderstatedContentLengthNeitherTruncatesNorSkips(t *testing.T) {
	t.Parallel()

	body := "harmless head sk-secret-1234 harmful tail that was never declared"
	req := requestWithCredential(http.MethodGet, "sk-secret-1234")
	resp := &http.Response{
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: 12, // deliberately short of the real body
	}

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()
	got := readAll(t, scrubbed.Body)

	require.NotContains(t, got, "sk-secret-1234", "the undeclared tail went out unscanned")
	require.Contains(t, got, "harmful tail that was never declared",
		"bytes beyond the declared length were dropped")
}

// compressZlib returns s as a zlib stream: a real encoding an upstream can
// choose that Go's transport never decodes on our behalf.
func compressZlib(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// postern advertises gzip and the transport decodes exactly that, so the
// scrubber usually sees plaintext. Every other encoding arrives still
// compressed — and so does gzip itself on a ranged request, where Go skips
// transparent decoding outright. A body the scrubber provably cannot inspect
// must fail closed: forwarded, the agent recovers the credential the moment it
// decompresses.
func TestScrubResponse_FailsClosedOnABodyItCannotInspect(t *testing.T) {
	t.Parallel()

	plaintext := `{"token":"` + testCredential + `"}`

	for _, tc := range []struct {
		name, encoding string
		wantStatus     int
	}{
		{name: "deflate", encoding: "deflate", wantStatus: http.StatusBadGateway},
		{name: "brotli", encoding: "br", wantStatus: http.StatusBadGateway},
		{name: "registered gzip alias", encoding: "x-gzip", wantStatus: http.StatusBadGateway},
		{name: "stacked gzip", encoding: "gzip, gzip", wantStatus: http.StatusBadGateway},
		{name: "identity is not an encoding we must refuse", encoding: "identity", wantStatus: http.StatusOK},
		{name: "no encoding at all", encoding: "", wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The refusals carry a genuinely compressed body; the two
			// pass-through cases carry the plaintext one, so they prove the
			// guard does not over-block and that scrubbing still happens.
			body := []byte(plaintext)
			if tc.wantStatus == http.StatusBadGateway {
				body = compressZlib(t, plaintext)
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Request:    requestWithCredential(http.MethodGet, testCredential),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
			}
			if tc.encoding != "" {
				resp.Header.Set("Content-Encoding", tc.encoding)
			}

			got := scrubResponse(resp, discardLogger())
			defer func() { _ = got.Body.Close() }()

			require.Equal(t, tc.wantStatus, got.StatusCode)
			delivered := readAll(t, got.Body)
			require.NotContains(t, delivered, testCredential)
			if tc.wantStatus == http.StatusOK {
				require.Contains(t, delivered, scrubbedMarker,
					"an inspectable body must still be scrubbed, not merely passed through")
			}
		})
	}
}

// A gzip body the transport already decoded is plaintext by the time the
// scrubber runs, so the guard must not refuse it: resp.Uncompressed is the
// transport's own record that it inflated the body.
func TestScrubResponse_AllowsAnEncodingTheTransportAlreadyDecoded(t *testing.T) {
	t.Parallel()

	plaintext := `{"token":"` + testCredential + `"}`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Request:       requestWithCredential(http.MethodGet, testCredential),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(plaintext)),
		ContentLength: int64(len(plaintext)),
		Uncompressed:  true,
	}
	// A transport that decoded the body but left the header behind must not be
	// treated as an uninspectable body.
	resp.Header.Set("Content-Encoding", "gzip")

	got := scrubResponse(resp, discardLogger())
	defer func() { _ = got.Body.Close() }()

	require.Equal(t, http.StatusOK, got.StatusCode, "a body the transport decoded is inspectable")
	require.Equal(t, `{"token":"`+scrubbedMarker+`"}`, readAll(t, got.Body))
}

// The encoding gate must read Content-Encoding before the header scrubber can
// delete it. scrubHeaderValues drops a header whole when its value carries the
// credential, so an upstream that folds the credential into its own
// Content-Encoding value would have that header removed first — leaving the
// gate to see no encoding at all and forward a compressed body it cannot
// inspect.
func TestScrubResponse_EncodingGateSurvivesHeaderScrubbing(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    requestWithCredential(http.MethodGet, testCredential),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(compressZlib(t, `{"token":"`+testCredential+`"}`))),
	}
	resp.Header.Set("Content-Encoding", "br; token="+testCredential)

	got := scrubResponse(resp, discardLogger())
	defer func() { _ = got.Body.Close() }()

	require.Equal(t, http.StatusBadGateway, got.StatusCode,
		"the encoding gate was defeated by header scrubbing, so a compressed body went out uninspected")
}

// The Content-Encoding value is upstream-controlled and can carry the
// credential itself, so the refusal warning must never echo it. Reporting only
// a recognised coding name is what keeps the secret out of the log — this
// project forbids writing a credential to any log, stdout, or file, and the
// ordering regression test above deliberately puts one in this exact header.
func TestScrubResponse_EncodingWarningNeverLogsTheCredential(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, encoding, wantLabel string
	}{
		{name: "credential is the whole value", encoding: testCredential, wantLabel: "other"},
		{name: "credential is a coding parameter", encoding: "deflate; token=" + testCredential, wantLabel: "deflate"},
		{name: "credential ahead of a parameter", encoding: testCredential + "; q=1", wantLabel: "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logger, logs := captureLogger()
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Request:    requestWithCredential(http.MethodGet, testCredential),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(compressZlib(t, "harmless"))),
			}
			resp.Header.Set("Content-Encoding", tc.encoding)

			got := scrubResponse(resp, logger)
			defer func() { _ = got.Body.Close() }()

			require.Equal(t, http.StatusBadGateway, got.StatusCode)
			out := logs.String()
			require.Contains(t, out, "refusing an upstream response",
				"the refusal must still be logged; silence would hide the refusal from operators")
			require.Contains(t, out, "content_encoding="+tc.wantLabel)
			require.NotContains(t, out, testCredential, "the credential reached the log")
		})
	}
}

// Percent-hex folding belongs to the escaped forms postern produced, not to the
// raw credential. A credential that itself contains a percent sequence is a
// case-sensitive literal: abc%2Fdef is not abc%2fdef, and treating them as one
// rewrites an unrelated response body.
func TestScrubber_RawCredentialWithPercentSequenceIsMatchedExactly(t *testing.T) {
	t.Parallel()

	const cred = "abc%2Fdef"

	for _, tc := range []struct {
		name, body string
		wantMatch  bool
	}{
		{name: "the credential itself", body: "token=" + cred + ";", wantMatch: true},
		{name: "lowercased hex is a different string", body: "token=abc%2fdef;", wantMatch: false},
		{name: "uppercased hex is a different string", body: "token=abc%2FDEF;", wantMatch: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newScrubber(
				io.NopCloser(strings.NewReader(tc.body)),
				credentialNeedles([]string{cred}),
				nil,
			)
			got := readAll(t, s)

			if tc.wantMatch {
				require.NotContains(t, got, cred, "the credential itself must still be scrubbed")
				require.Contains(t, got, scrubbedMarker)
				return
			}
			require.Equal(t, tc.body, got,
				"text that merely resembles the credential was rewritten; folding leaked into the raw form")
		})
	}
}

// The same rule governs the header path, and there it costs more: a header is
// deleted whole when it carries the credential, so folding the raw form there
// drops headers an unrelated upstream response would otherwise keep.
func TestScrubResponse_HeaderKeptForAPercentCaseResemblance(t *testing.T) {
	t.Parallel()

	const cred = "abc%2Fdef"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    requestWithCredential(http.MethodGet, cred),
		Header:     http.Header{"X-Echo": []string{"abc%2fdef"}},
		Body:       http.NoBody,
	}

	scrubResponse(resp, discardLogger()) //nolint:bodyclose // the scrubber, not the test, owns the body from here

	require.Equal(t, "abc%2fdef", resp.Header.Get("X-Echo"),
		"a header that merely resembles the credential was deleted")
}

// One credential's raw value can be another's percent-escaped form, so the two
// must be tracked separately rather than deduped by pattern alone. With creds
// "a%2Fb" and "a/b", both produce the pattern "a%2Fb"; collapsing them drops
// the folded copy, and "a%2fb" — the escaped, lowercased form of a/b — goes
// out unscrubbed.
func TestCredentialNeedles_KeepsExactAndFoldedCopiesOfOnePattern(t *testing.T) {
	t.Parallel()

	needles := credentialNeedles([]string{"a%2Fb", "a/b"})

	var exact, folded bool
	for _, n := range needles {
		if string(n.pat) != "a%2Fb" {
			continue
		}
		if n.foldHex {
			folded = true
		} else {
			exact = true
		}
	}
	require.True(t, exact, "the raw credential a%2Fb must be matched byte-for-byte")
	require.True(t, folded, "the escaped form of a/b must fold hex case, or a%2fb leaks")

	s := newScrubber(io.NopCloser(strings.NewReader("url=?k=a%2fb")), needles, nil)
	require.Equal(t, "url=?k="+scrubbedMarker, readAll(t, s),
		"a second credential's escaped, lowercased form was not scrubbed")
}

// The refusal must unwrap every Content-Encoding coding, in two ways.
// http.Header.Get returns only the first header value, so an upstream sending
// `identity` and `br` as separate fields hides the coding. And one value can
// carry a comma-separated list whose elements carry parameters, so
// `identity; q=1, br` names two codings and cutting at the semicolon first
// keeps only the first. Either way the credential rides out inside the
// compressed body, where the byte scrubber cannot reach it.
func TestScrubResponse_FailsClosedOnALaterContentEncodingValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		values  []string
		wantRef bool
	}{
		{name: "identity first, brotli second", values: []string{"identity", "br"}, wantRef: true},
		{name: "brotli first, identity second", values: []string{"br", "identity"}, wantRef: true},
		{name: "identity alone", values: []string{"identity"}, wantRef: false},
		{name: "identity repeated", values: []string{"identity", "identity"}, wantRef: false},
		{name: "identity with a parameter, brotli behind it", values: []string{"identity; q=1, br"}, wantRef: true},
		{name: "brotli first in a combined value", values: []string{"br, identity"}, wantRef: true},
		{name: "identity carrying only a parameter", values: []string{"identity; q=1"}, wantRef: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Request:    requestWithCredential(http.MethodGet, testCredential),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(compressZlib(t, `{"token":"`+testCredential+`"}`))),
			}
			for _, v := range tc.values {
				resp.Header.Add("Content-Encoding", v)
			}

			got := scrubResponse(resp, discardLogger())
			defer func() { _ = got.Body.Close() }()

			if tc.wantRef {
				require.Equal(t, http.StatusBadGateway, got.StatusCode,
					"a later Content-Encoding value was not inspected; a compressed body went out unscrubbed")
				return
			}
			require.Equal(t, http.StatusOK, got.StatusCode)
		})
	}
}

// A brokered 101 cannot be scrubbed — goproxy hijacks the connection and
// relays raw frames — but it must not pass in silence either, or a host that
// upgrades reads as one postern inspected end to end. The body must also come
// back untouched: wrapping it is what breaks the tunnel.
func TestScrubResponse_LogsABrokeredProtocolUpgrade(t *testing.T) {
	t.Parallel()

	logger, logs := captureLogger()
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Request:    requestWithCredential(http.MethodGet, testCredential),
		Header:     http.Header{"Upgrade": []string{"websocket"}},
		Body:       rwCloser{},
	}

	got := scrubResponse(resp, logger) //nolint:bodyclose // a hijacked tunnel body must not be closed by the filter; that is the behaviour under test

	require.Equal(t, rwCloser{}, got.Body, "the upgrade body was wrapped; that breaks the tunnel")
	require.Contains(t, logs.String(), "upgraded to a protocol tunnel")
	require.NotContains(t, logs.String(), testCredential, "the credential reached the log")
}
