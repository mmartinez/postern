package broker_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/broker"

	"github.com/stretchr/testify/require"
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
