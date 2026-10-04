package broker_test

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/broker"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// Greptile P1: a gzipped response hides the credential inside a deflate
// stream, so a byte-matching scrubber cannot see it and the agent recovers the
// credential on decompression. The fix is to stop negotiating client-driven
// compression on brokered requests and let net/http transparently decode.
func TestHook_BrokeredRequestDropsClientAcceptEncoding(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-real"}
	hook := newHookFixture(t, placeholderRule(broker.SurfaceBody), res)

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(`{"k":"__tok__"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	resp := hook(req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}

	require.Nil(t, resp, "the request should have been brokered and forwarded")
	require.Empty(t, req.Header.Get("Accept-Encoding"),
		"a client-chosen Content-Encoding lets the upstream hide a reflected credential from the scrubber")
}

// A request that matches no rule must keep its own encoding: postern is a
// transparent tunnel there and must not rewrite a conversation it is not
// brokering.
func TestHook_UnmatchedRequestKeepsAcceptEncoding(t *testing.T) {
	t.Parallel()

	rule := placeholderRule()
	rule.Host = "other.example.com"
	hook := newHookFixture(t, rule, &fakeResolver{value: "sk-real"})

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/x", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the nil and non-nil cases
	defer closeIfNonNil(t, resp)

	require.Nil(t, resp)
	require.Equal(t, "gzip", req.Header.Get("Accept-Encoding"),
		"postern must not rewrite a request it does not broker")
}

// Turning the scrubber off must be a real opt-out, not a silent downgrade of
// the encoding the client asked for. The Accept-Encoding strip exists only to
// keep the scrubber out of a deflate stream; with no scrubber there is nothing
// to protect, so the header must survive untouched.
func TestHook_ScrubDisabledLeavesAcceptEncodingAlone(t *testing.T) {
	t.Parallel()

	off := false
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hook := broker.Hook(broker.NewEngine([]broker.Rule{placeholderRule(broker.SurfaceBody)}),
		&fakeResolver{value: "sk-real"}, config.OnNoMatchPassthrough, 0, off, logger)

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/x", strings.NewReader(`{"k":"__tok__"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "br, deflate")

	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the nil and non-nil cases
	defer closeIfNonNil(t, resp)

	require.Nil(t, resp)
	require.Equal(t, "br, deflate", req.Header.Get("Accept-Encoding"),
		"scrub_responses: false must not change the representation the client requested")
}
