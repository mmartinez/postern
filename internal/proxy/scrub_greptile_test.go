package proxy

import (
	"io"
	"net/http"
	"net/url"
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
		ContentLength: 11,
	}
	resp.Header.Set("Content-Length", "11")
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
