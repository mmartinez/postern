package proxy

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
)

const testCredential = "sk-ant-api03-SUPERSECRET"

// testNeedles is testCredential in the byte-slice form the scrubber scans
// for. It is a function rather than a package-level var because a mutable
// global outside main is banned by the project rules.
func testNeedles() [][]byte { return [][]byte{[]byte(testCredential)} }

// oneByteReader hands out its payload one byte per Read, so a credential can
// only be found by a scrubber that carries a partial match across reads.
// Every real transport chunks arbitrarily, so a scrubber that passed only on
// whole-buffer reads would be passing by accident.
type oneByteReader struct {
	data []byte
	off  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.off]
	r.off++
	return 1, nil
}

// erroringReader serves its payload on the first Read and fails every later
// one. A scrubber that reads past the point where it could have answered
// surfaces the error here and fails, instead of blocking the test.
type erroringReader struct {
	payload []byte
	reads   int
}

func (r *erroringReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		return 0, io.ErrUnexpectedEOF
	}
	return copy(p, r.payload), nil
}

// chunkReader splits its payload into fixed-size reads so a test can place a
// read boundary at an exact offset.
type chunkReader struct {
	data  []byte
	off   int
	chunk int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := min(min(r.chunk, len(p)), len(r.data)-r.off)
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}

// trackingCloser records whether Close reached the upstream body.
type trackingCloser struct {
	io.Reader
	closed bool
}

func (c *trackingCloser) Close() error {
	c.closed = true
	return nil
}

// rwCloser stands in for the io.ReadWriter body net/http hands back on a 101
// upgrade, which goproxy hijacks and speaks raw bytes over.
type rwCloser struct{}

func (rwCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (rwCloser) Write(p []byte) (int, error) { return len(p), nil }
func (rwCloser) Close() error                { return nil }

// discardLogger returns a logger that drops every record, so unit tests on
// scrubResponse do not need to thread a writer.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// requestWithCredential builds a request whose context carries cred the way
// the broker hook leaves it after a successful injection. An empty cred
// models the "nothing was injected" case.
func requestWithCredential(method, cred string) *http.Request {
	req, err := http.NewRequest(method, "https://api.example.com/v1", http.NoBody)
	if err != nil {
		panic(err)
	}
	if cred == "" {
		return req
	}
	return req.WithContext(broker.WithInjectedCredentials(req.Context(), cred))
}

// readAll drains r the way io.Copy would, so a scrubber that returns an error
// surfaces here rather than being silently truncated.
func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

func TestScrubber_RemovesCredential(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "no occurrence", in: `{"ok":true}`, want: `{"ok":true}`},
		{name: "whole body is the credential", in: testCredential, want: scrubbedMarker},
		{name: "single occurrence", in: `{"key":"` + testCredential + `","ok":true}`, want: `{"key":"` + scrubbedMarker + `","ok":true}`},
		{name: "two occurrences", in: testCredential + "-" + testCredential, want: scrubbedMarker + "-" + scrubbedMarker},
		{name: "adjacent occurrences", in: testCredential + testCredential, want: scrubbedMarker + scrubbedMarker},
		{name: "occurrence at the head", in: testCredential + "XYZ", want: scrubbedMarker + "XYZ"},
		{name: "occurrence at the tail", in: "XYZ" + testCredential, want: "XYZ" + scrubbedMarker},
		{name: "near miss is preserved", in: "sk-ant-api03-SUPERSECRE", want: "sk-ant-api03-SUPERSECRE"},
		{name: "empty payload", in: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newScrubber(io.NopCloser(strings.NewReader(tc.in)), testNeedles(), nil)
			require.Equal(t, tc.want, readAll(t, s))
		})
	}
}

// TestScrubber_CredentialSpanningReadBoundary is the case the whole streaming
// design exists for: the payload is split across two upstream reads at every
// offset, including the ones that land mid-needle. A scrubber that scans each
// read independently misses every split and leaks the credential.
func TestScrubber_CredentialSpanningReadBoundary(t *testing.T) {
	t.Parallel()

	const payload = "head:" + testCredential + ":tail"
	const want = "head:" + scrubbedMarker + ":tail"

	for split := 0; split <= len(payload); split++ {
		r := io.MultiReader(strings.NewReader(payload[:split]), strings.NewReader(payload[split:]))
		s := newScrubber(io.NopCloser(r), testNeedles(), nil)
		got := readAll(t, s)
		require.NotContains(t, got, testCredential, "split at %d leaked the credential", split)
		if split == len(payload) {
			continue
		}
		require.Equal(t, want, got, "split at %d", split)
	}

	require.Equal(t, want, readAll(t, newScrubber(io.NopCloser(strings.NewReader(payload)), testNeedles(), nil)))
}

// TestScrubber_ByteAtATimeBoundary is the same invariant under the most
// adversarial chunking a transport can produce: one byte per Read, so the
// needle is reassembled across len(credential)-1 separate reads.
func TestScrubber_ByteAtATimeBoundary(t *testing.T) {
	t.Parallel()

	require.Equal(t, "a"+scrubbedMarker+"b", readAll(t, newScrubber(io.NopCloser(&oneByteReader{data: []byte("a" + testCredential + "b")}), testNeedles(), nil)))
}

// TestScrubber_EmitsWithoutWaitingForMoreUpstreamBytes pins the streaming
// property: when the tail of the available bytes cannot begin an occurrence,
// the scrubber must answer from the bytes it already holds rather than
// withhold them waiting for a needle that will never complete. A scrubber
// that unconditionally retains len(credential)-1 bytes stalls here, which in
// production is every SSE event held back by one credential length.
func TestScrubber_EmitsWithoutWaitingForMoreUpstreamBytes(t *testing.T) {
	t.Parallel()

	src := &erroringReader{payload: []byte("data: chunk-0\n\n")}
	s := newScrubber(io.NopCloser(src), testNeedles(), nil)

	buf := make([]byte, 64)
	n, err := s.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "data: chunk-0\n\n", string(buf[:n]))
	require.Equal(t, 1, src.reads, "scrubber read past the point where it could already answer")
}

// TestScrubber_HoldsBackOnlyAPartialNeedlePrefix documents the other half of
// the boundary handling: a tail that IS a proper prefix of the needle is
// retained, because the rest of the needle may still be in flight.
func TestScrubber_HoldsBackOnlyAPartialNeedlePrefix(t *testing.T) {
	t.Parallel()

	needles := [][]byte{[]byte(testCredential)}
	require.Equal(t, 6, partialSuffixLen([]byte("data: sk-ant"), needles))
	require.Equal(t, 0, partialSuffixLen([]byte("data: chunk-0\n\n"), needles))
	require.Equal(t, 0, partialSuffixLen(nil, needles))

	// "sk-ant" arrives in two reads and is only completed at EOF.
	// The tail is a proper prefix, so it is withheld mid-stream; at EOF the
	// needle never completes, so the withheld bytes are released verbatim
	// rather than dropped. "sk-ant" was never a credential.
	src := &chunkReader{data: []byte("data: sk-ant"), chunk: 11}
	require.Equal(t, "data: sk-ant", readAll(t, newScrubber(io.NopCloser(src), testNeedles(), nil)))
}

func TestScrubber_EmptyNeedlesStreamUntouched(t *testing.T) {
	t.Parallel()

	require.Equal(t, "payload", readAll(t, newScrubber(io.NopCloser(strings.NewReader("payload")), nil, nil)))
}

func TestScrubber_PropagatesUpstreamError(t *testing.T) {
	t.Parallel()

	want := errors.New("upstream read failed")
	s := newScrubber(io.NopCloser(errReader{err: want}), testNeedles(), nil)
	_, err := io.ReadAll(s)
	require.ErrorIs(t, err, want)
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestScrubber_CloseClosesUpstream(t *testing.T) {
	t.Parallel()

	up := &trackingCloser{Reader: strings.NewReader("x")}
	require.NoError(t, newScrubber(up, testNeedles(), nil).Close())
	require.True(t, up.closed)
}

func TestScrubResponse_RemovesCredentialFromHeadersAndBody(t *testing.T) {
	t.Parallel()

	body := `{"token":"` + testCredential + `"}`
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Request:       requestWithCredential(http.MethodGet, testCredential),
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Set-Cookie", "session="+testCredential+"; Path=/")
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("X-Echo", "prefix-"+testCredential+"-suffix")
	resp.Header.Set("Content-Length", "999")

	got := scrubResponse(resp, discardLogger()) //nolint:bodyclose // the scrubber, not the test, owns the body from here
	require.NotNil(t, got)

	require.Empty(t, got.Header.Get("Set-Cookie"), "a Set-Cookie echoing the credential must not reach the agent")
	require.Empty(t, got.Header.Get("X-Echo"))
	require.Equal(t, "application/json", got.Header.Get("Content-Type"))
	require.Equal(t, `{"token":"`+scrubbedMarker+`"}`, readAll(t, got.Body))
	require.Equal(t, int64(-1), got.ContentLength, "the scrubbed body is a different length, so framing must be recomputed")
	require.Empty(t, got.Header.Get("Content-Length"))
}

func TestScrubResponse_ScrubsTrailers(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    requestWithCredential(http.MethodGet, testCredential),
		Header:     http.Header{"Trailer": []string{"X-Audit"}},
		Trailer:    http.Header{"X-Audit": []string{"key=" + testCredential}},
		Body:       http.NoBody,
	}
	scrubResponse(resp, discardLogger()) //nolint:bodyclose // the scrubber, not the test, owns the body from here
	require.Empty(t, resp.Trailer.Get("X-Audit"))
}

// TestScrubResponse_NoInjectedCredentialIsANoOp is the zero-work path: with
// nothing injected the response comes back with the same body reader and the
// same Content-Length, so passthrough traffic pays no scan and no allocation.
func TestScrubResponse_NoInjectedCredentialIsANoOp(t *testing.T) {
	t.Parallel()

	body := io.NopCloser(strings.NewReader("plain body"))
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Request:       requestWithCredential(http.MethodGet, ""),
		Header:        http.Header{"Content-Length": []string{"10"}},
		Body:          body,
		ContentLength: 10,
	}

	got := scrubResponse(resp, discardLogger()) //nolint:bodyclose // the scrubber, not the test, owns the body from here
	require.Equal(t, body, got.Body, "body reader must be untouched when nothing was injected")
	require.Equal(t, int64(10), got.ContentLength)
	require.Equal(t, "10", got.Header.Get("Content-Length"))
}

// TestScrubResponse_LeavesUnscrubbableBodiesAlone protects the two shapes
// where wrapping the body would break framing or the tunnel rather than
// protect anything: a HEAD response (goproxy preserves its Content-Length
// only while the body reader is unchanged) and a 101 upgrade (goproxy
// hijacks the connection and needs the body to still be an io.ReadWriter).
func TestScrubResponse_LeavesUnscrubbableBodiesAlone(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		method string
		body   io.ReadCloser
	}{
		{name: "HEAD keeps its Content-Length", method: http.MethodHead, body: http.NoBody},
		{name: "no body at all", method: http.MethodGet, body: nil},
		{name: "websocket upgrade stays a ReadWriter", method: http.MethodGet, body: rwCloser{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Request:       requestWithCredential(tc.method, testCredential),
				Header:        http.Header{"Content-Length": []string{"42"}},
				Body:          tc.body,
				ContentLength: 42,
			}
			got := scrubResponse(resp, discardLogger()) //nolint:bodyclose // the scrubber, not the test, owns the body from here
			require.Equal(t, tc.body, got.Body)
			require.Equal(t, int64(42), got.ContentLength)
			require.Equal(t, "42", got.Header.Get("Content-Length"))
		})
	}
}

func TestScrubResponse_NilResponseIsSafe(t *testing.T) {
	t.Parallel()

	require.Nil(t, scrubResponse(nil, discardLogger())) //nolint:bodyclose // nil in, nil out
}
