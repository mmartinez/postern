package proxy

import (
	"io"
	"net/http"
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
			s := newScrubber(io.NopCloser(strings.NewReader(tc.body)), [][]byte{[]byte(tc.needle)})
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

	s := newScrubber(io.NopCloser(&oneByteReader{data: []byte("abab")}), [][]byte{[]byte("abab")})
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
			s := newScrubber(&eofWithDataReader{data: []byte(tc.body)}, [][]byte{[]byte(tc.needle)})
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

// endlessReader emits an unending run of one byte, standing in for a
// long-lived stream (an event feed, a watch) that never ends.
type endlessReader struct {
	b     byte
	chunk int
	left  int
}

func (r *endlessReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		r.left = r.chunk
	}
	n := len(p)
	if n > r.left {
		n = r.left
	}
	for i := range n {
		p[i] = r.b
	}
	r.left -= n
	return n, nil
}

func (r *endlessReader) Close() error { return nil }

// A body whose bytes keep repeating a credential prefix must not stall. An
// earlier version walked the withhold boundary back whenever the bytes before
// it could start an occurrence; against an endless run of "a" with credential
// "aa" that never terminates, so nothing was ever emitted and the fill grew
// for the life of the stream.
func TestScrubber_RepeatingCredentialPrefixDoesNotStallOrGrowUnbounded(t *testing.T) {
	t.Parallel()

	s := newScrubber(&endlessReader{b: 'a', chunk: 512}, [][]byte{[]byte("aa")})

	first := make([]byte, 4096)
	n, err := s.Read(first)
	require.NoError(t, err)
	require.Positive(t, n, "a stream of repeated credential prefixes must still deliver data")
	require.LessOrEqual(t, len(s.fill), len("aa")+8,
		"the scrubber retained far more than one credential length; it is buffering the stream")

	for range 64 {
		if _, err := s.Read(first); err != nil {
			t.Fatalf("read failed partway: %v", err)
		}
	}
	require.LessOrEqual(t, len(s.fill), len("aa")+8,
		"retained state must stay bounded no matter how long the response runs")
}

// Redaction that never happens must not cost an honest response its metadata.
// For a body small enough to settle up front the decision is exact.
func TestScrubResponse_UnchangedBodyKeepsItsMetadata(t *testing.T) {
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
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Range", "bytes 0-"+strconv.Itoa(len(body)-1)+"/1024")
	resp.Header.Set("ETag", `"v1"`)

	scrubbed := scrubResponse(resp, discardLogger())
	defer func() { _ = scrubbed.Body.Close() }()

	require.Equal(t, body, readAll(t, scrubbed.Body), "an unchanged body must pass through byte-for-byte")
	require.Equal(t, `"v1"`, resp.Header.Get("ETag"), "nothing was redacted, so the validator is still true")
	require.NotEmpty(t, resp.Header.Get("Content-Range"), "nothing was redacted, so the range still describes the body")
}

// A response that under-declares its Content-Length must not be truncated, and
// must not have its unscanned tail handed to the agent. Content-Length is a
// hint; reading exactly that many bytes would drop the rest and would only
// have scrubbed the part it read.
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
