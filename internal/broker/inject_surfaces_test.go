package broker_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
)

// placeholderRule builds a placeholder-mode rule over the given surfaces with
// the canonical token + identity template, the shape every surface test reuses.
func placeholderRule(surfaces ...broker.Surface) broker.Rule {
	return broker.Rule{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Name:     "__tok__",
			Template: "{{ CREDENTIAL }}",
			Surfaces: surfaces,
		},
	}
}

func reqWithBody(t *testing.T, method, rawURL, contentType, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func readBody(t *testing.T, req *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	return string(b)
}

func TestInjectPlaceholder_Path_EscapesValue(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfacePath)
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/__tok__/models", http.NoBody)
	require.NoError(t, err)

	require.NoError(t, r.Inject(req, "a/b c"))

	// url.PathEscape("a/b c") == "a%2Fb%20c"; both Path (decoded) and RawPath
	// (encoded) must be set so url.String() doesn't double-encode.
	require.Equal(t, "/v1/a%2Fb%20c/models", req.URL.EscapedPath())
	require.Equal(t, "/v1/a%2Fb%20c/models", req.URL.RawPath)
	require.Equal(t, "/v1/a/b c/models", req.URL.Path)
	require.Equal(t, "/v1/a%2Fb%20c/models", req.URL.RequestURI())
}

func TestInjectPlaceholder_Query_EscapesValue(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceQuery)
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models?key=__tok__&x=1", http.NoBody)
	require.NoError(t, err)

	require.NoError(t, r.Inject(req, "a b&c"))

	// url.QueryEscape("a b&c") == "a+b%26c".
	require.Equal(t, "key=a+b%26c&x=1", req.URL.RawQuery)
}

func TestInjectPlaceholder_Body_JSONEscaped(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceBody)
	req := reqWithBody(t, http.MethodPost, "https://api.example.com/v1/x", "application/json", `{"api_key":"__tok__"}`)

	require.NoError(t, r.Inject(req, `he said "hi"`+"\n"))

	got := readBody(t, req)
	require.Equal(t, `{"api_key":"he said \"hi\"\n"}`, got)
	require.Equal(t, int64(len(got)), req.ContentLength)
}

func TestInjectPlaceholder_Body_FormURLEncoded(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceBody)
	req := reqWithBody(t, http.MethodPost, "https://api.example.com/v1/x", "application/x-www-form-urlencoded", "grant=__tok__&y=2")

	require.NoError(t, r.Inject(req, "a b&c"))

	require.Equal(t, "grant=a+b%26c&y=2", readBody(t, req))
}

func TestInjectPlaceholder_Body_RawForUnknownContentType(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceBody)
	req := reqWithBody(t, http.MethodPost, "https://api.example.com/v1/x", "text/plain", "secret=__tok__")

	require.NoError(t, r.Inject(req, "p l a i n"))

	require.Equal(t, "secret=p l a i n", readBody(t, req))
}

// A multipart body is forwarded unmodified: postern cannot safely text-splice
// across MIME part boundaries. With body as the only surface and nothing to
// substitute, Inject returns nil (forward untouched), not ErrNoPlaceholder.
func TestInjectPlaceholder_Body_MultipartSkipped(t *testing.T) {
	t.Parallel()

	const body = "--x\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\n__tok__\r\n--x--\r\n"
	r := placeholderRule(broker.SurfaceBody)
	req := reqWithBody(t, http.MethodPost, "https://api.example.com/v1/x", "multipart/form-data; boundary=x", body)

	require.NoError(t, r.Inject(req, "sk-real"))
	require.Equal(t, body, readBody(t, req), "multipart body must be forwarded byte-for-byte")
}

// A compressed body (Content-Encoding set) is forwarded unmodified: postern
// cannot text-substitute into a compressed payload.
func TestInjectPlaceholder_Body_CompressedSkipped(t *testing.T) {
	t.Parallel()

	const body = "this looks like __tok__ but is gzip bytes"
	r := placeholderRule(broker.SurfaceBody)
	req := reqWithBody(t, http.MethodPost, "https://api.example.com/v1/x", "application/json", body)
	req.Header.Set("Content-Encoding", "gzip")

	require.NoError(t, r.Inject(req, "sk-real"))
	require.Equal(t, body, readBody(t, req), "compressed body must be forwarded byte-for-byte")
}

// A rendered value carrying CR/LF must never be spliced into a header value:
// that is request smuggling / header injection. Fail closed, leave headers be.
func TestInjectPlaceholder_Header_RejectsCRLF(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceHeader)
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("x-api-key", "__tok__")

	injErr := r.Inject(req, "evil\r\nX-Injected: 1")
	require.ErrorIs(t, injErr, broker.ErrHeaderInjection)
	require.Equal(t, "__tok__", req.Header.Get("x-api-key"), "header must be untouched on fail closed")
}

// Header inject mode (type: header) must also reject a CR/LF-bearing value.
func TestInjectHeader_RejectsCRLF(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "authorization",
			Template: "Bearer {{ CREDENTIAL }}",
		},
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", http.NoBody)
	require.NoError(t, err)

	require.ErrorIs(t, r.Inject(req, "tok\nevil"), broker.ErrHeaderInjection)
	require.Empty(t, req.Header.Get("authorization"))
}

// Aggregate match: with several surfaces declared, a token found on any one of
// them is success. Here the token is only in the query; the header carries no
// token and must be left untouched.
func TestInjectPlaceholder_MultiSurface_AnyMatchSucceeds(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceHeader, broker.SurfaceQuery)
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1?key=__tok__", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("x-trace", "no-token-here")

	require.NoError(t, r.Inject(req, "sk-real"))
	require.Equal(t, "key=sk-real", req.URL.RawQuery)
	require.Equal(t, "no-token-here", req.Header.Get("x-trace"))
}

// A declared surface with the token nowhere on any eligible surface fails
// closed so the hook returns 502 rather than forward unauthenticated.
func TestInjectPlaceholder_NoTokenOnDeclaredSurface_FailsClosed(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.SurfaceQuery)
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1?key=value", http.NoBody)
	require.NoError(t, err)

	require.ErrorIs(t, r.Inject(req, "sk-real"), broker.ErrNoPlaceholder)
	require.Equal(t, "key=value", req.URL.RawQuery, "query must be untouched on fail closed")
}

// Empty surfaces default to header-only, preserving pre-#17 behavior.
func TestInjectPlaceholder_EmptySurfacesDefaultsToHeader(t *testing.T) {
	t.Parallel()

	r := placeholderRule() // no surfaces
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("x-api-key", "__tok__")

	require.NoError(t, r.Inject(req, "sk-real"))
	require.Equal(t, "sk-real", req.Header.Get("x-api-key"))
}

func TestInjectPlaceholder_UnknownSurface_Errors(t *testing.T) {
	t.Parallel()

	r := placeholderRule(broker.Surface(0))
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", http.NoBody)
	require.NoError(t, err)

	require.Error(t, r.Inject(req, "sk-real"))
}

// Compile-time anchor: surface constants are distinct values.
func TestSurfaceConstants_Distinct(t *testing.T) {
	t.Parallel()

	all := []broker.Surface{broker.SurfaceHeader, broker.SurfaceBody, broker.SurfacePath, broker.SurfaceQuery}
	seen := map[broker.Surface]bool{}
	for _, s := range all {
		require.False(t, seen[s], "surface value %d duplicated", s)
		seen[s] = true
	}
	require.Len(t, seen, 4)
}
