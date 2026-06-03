package broker_test

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

func bodySurfaceHook(t *testing.T, res broker.Resolver, maxBodyBytes int, rule broker.Rule) func(*http.Request) *http.Response {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return broker.Hook(broker.NewEngine([]broker.Rule{rule}), res, config.OnNoMatchPassthrough, maxBodyBytes, logger) //nolint:bodyclose // hook closure; broker owns synthetic bodies
}

// A body over the size cap is a 413 (client error), not a 502, and the
// credential resolver is never called — buffering happens before resolve so a
// flood of oversized bodies can't hammer the credential vendor.
func TestHook_BodyOverCap_Returns413_ResolverNotCalled(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-real"}
	hook := bodySurfaceHook(t, res, 16, placeholderRule(broker.SurfaceBody))

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(strings.Repeat("x", 100)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp := hook(req)
	require.NotNil(t, resp)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	require.Zero(t, res.calls.Load(), "resolver must not be called when the body is rejected for size")
}

// A body within the cap is buffered, the placeholder substituted, and the
// request forwarded (hook returns nil). Content-Length tracks the new body.
func TestHook_BodyUnderCap_SubstitutesAndForwards(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-real"}
	hook := bodySurfaceHook(t, res, 1<<20, placeholderRule(broker.SurfaceBody)) //nolint:bodyclose // closure return type; resp is nil on the forward path

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(`{"k":"__tok__"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp := hook(req) //nolint:bodyclose // nil on the forward path; nothing to close
	require.Nil(t, resp, "hook must return nil to forward the mutated request")
	require.Equal(t, int64(1), res.calls.Load())

	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, `{"k":"sk-real"}`, string(got))
	require.Equal(t, int64(len(got)), req.ContentLength)
}

// A compressed body is skipped by substituteBody (text-splicing opaque bytes
// would corrupt them), so the hook must not buffer or size-cap it: an oversized
// compressed body forwards untouched rather than returning 413.
func TestHook_CompressedBodyOverCap_ForwardsUnbuffered(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-real"}
	hook := bodySurfaceHook(t, res, 16, placeholderRule(broker.SurfaceBody)) //nolint:bodyclose // closure return type; resp is nil on the forward path

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(strings.Repeat("x", 100)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp := hook(req) //nolint:bodyclose // nil on the forward path; nothing to close
	require.Nil(t, resp, "an oversized compressed body must forward untouched, not 413")

	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("x", 100), string(got), "compressed body must stream through unchanged")
}

// A multipart body is likewise skipped by substituteBody, so an oversized
// multipart body forwards untouched rather than returning 413.
func TestHook_MultipartBodyOverCap_ForwardsUnbuffered(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-real"}
	hook := bodySurfaceHook(t, res, 16, placeholderRule(broker.SurfaceBody)) //nolint:bodyclose // closure return type; resp is nil on the forward path

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(strings.Repeat("x", 100)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=abc")

	resp := hook(req) //nolint:bodyclose // nil on the forward path; nothing to close
	require.Nil(t, resp, "an oversized multipart body must forward untouched, not 413")

	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("x", 100), string(got), "multipart body must stream through unchanged")
}

// A per-rule max_body_bytes override takes precedence over the global cap.
func TestHook_PerRuleCapOverridesGlobal(t *testing.T) {
	t.Parallel()

	rule := placeholderRule(broker.SurfaceBody)
	rule.Injection.MaxBodyBytes = 8 // tighter than the generous global below

	res := &fakeResolver{value: "sk-real"}
	hook := bodySurfaceHook(t, res, 1<<20, rule)

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(strings.Repeat("y", 64)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp := hook(req)
	require.NotNil(t, resp)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

// A rule that declares no body surface must not buffer the body at all: the
// hook leaves req.Body as the original stream so the proxy streams it upstream.
func TestHook_NoBodySurface_DoesNotBufferBody(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-real"}
	rule := broker.Rule{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}
	hook := bodySurfaceHook(t, res, 8, rule) //nolint:bodyclose // closure return type; resp is nil on the forward path

	orig := strings.NewReader(strings.Repeat("z", 1000))
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", orig)
	require.NoError(t, err)

	resp := hook(req) //nolint:bodyclose // nil on the forward path; nothing to close
	require.Nil(t, resp, "header-only rule with an oversized body must still forward (body not buffered)")
	require.Equal(t, "sk-real", req.Header.Get("x-api-key"))
}
