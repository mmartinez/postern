package broker_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

type fakeResolver struct {
	value  string
	err    error
	calls  atomic.Int64
	lastVR struct {
		vault, ref string
	}
}

func (f *fakeResolver) Resolve(_ context.Context, vaultID, ref string) (string, error) {
	f.calls.Add(1)
	f.lastVR.vault = vaultID
	f.lastVR.ref = ref
	if f.err != nil {
		return "", f.err
	}
	return f.value, nil
}

func newHookFixture(t *testing.T, rule broker.Rule, res broker.Resolver) func(*http.Request) *http.Response {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return broker.Hook(broker.NewEngine([]broker.Rule{rule}), res, config.OnNoMatchPassthrough, 0, logger) //nolint:bodyclose // hook is a closure; bodyclose can't trace ownership across return
}

// closeIfNonNil drains and closes the hook's response body so tests can
// inspect status/body without the bodyclose linter complaining. Returns
// resp unchanged so callers can keep an inline read.
func closeIfNonNil(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp != nil {
		_ = resp.Body.Close()
	}
}

func TestHook_NoMatchReturnsNilForPassthrough(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}, res)

	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp != nil {
		t.Fatalf("hook returned response for unmatched host: %+v, want nil", resp)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (passthrough must not resolve)", got)
	}
}

// Under on_no_match=block the hook must deny an unmatched request: return a
// 502 (fail closed) and never call the resolver, the allowlist-only egress
// containment an operator opts into. Contrast with the passthrough case
// above, which forwards the request untouched.
func TestHook_NoMatchBlocksWhenOnNoMatchBlock(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}}), res, config.OnNoMatchBlock, 0, nil)

	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp == nil {
		t.Fatalf("on_no_match=block: want non-nil 502 for unmatched host, got nil (would leak blocked egress)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (block must not resolve)", got)
	}
}

func TestHook_MatchInjectsCredentialAndReturnsNil(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://Agents/Anthropic/api_key",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp != nil {
		t.Fatalf("hook returned response on match: %+v, want nil (forward to upstream)", resp)
	}
	if got := req.Header.Get("x-api-key"); got != "sk-secret" {
		t.Fatalf("x-api-key = %q, want %q", got, "sk-secret")
	}
	if got := res.lastVR.ref; got != "op://Agents/Anthropic/api_key" {
		t.Fatalf("resolver invoked with ref %q, want %q", got, "op://Agents/Anthropic/api_key")
	}
	if got := res.lastVR.vault; got != "" {
		t.Fatalf("resolver invoked with vaultID %q, want empty (forward-compat)", got)
	}
}

// TestHook_PlainHTTPMatchFailsClosed guards the transport-confidentiality
// invariant: a rule that matches must never get a real credential injected
// when the request arrived over plain http://. The proxy only injects when
// it terminated the TLS itself (scheme https); anything else fails closed
// before the resolver is even called, so the secret never reaches a
// cleartext upstream connection.
func TestHook_PlainHTTPMatchFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "http://api.anthropic.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp == nil {
		t.Fatalf("plain-http matched rule: want non-nil 502, got nil (would inject credential over cleartext)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (must not resolve before the transport check)", got)
	}
	if _, ok := req.Header["X-Api-Key"]; ok {
		t.Fatalf("x-api-key injected over plain http; credential leaked to a cleartext transport")
	}
}

func TestHook_StripsPortFromMatchHost(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}, res)

	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com:443/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp != nil {
		t.Fatalf("hook returned response on host:port match: %+v, want nil", resp)
	}
	if got := req.Header.Get("x-api-key"); got != "sk-secret" {
		t.Fatalf("x-api-key = %q, want %q", got, "sk-secret")
	}
}

func TestHook_ResolverErrorReturns502(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{err: errors.New("token revoked")}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp == nil {
		t.Fatalf("resolver err: want non-nil 502 response, got nil (would leak unauth request upstream)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if _, ok := req.Header["X-Api-Key"]; ok {
		t.Fatalf("x-api-key set on failed resolve; request must not carry partial credential state")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "postern") {
		t.Fatalf("body = %q, want postern-prefixed message", body)
	}
	if strings.Contains(string(body), "token revoked") {
		t.Fatalf("body leaked underlying resolver error: %q", body)
	}
}

// TestHook_NilLoggerDefaultsToNoop guards the convenience that callers
// (including the runtime wiring) can omit the logger during tests without
// triggering a nil dereference inside the hook.
func TestHook_NilLoggerDefaultsToNoop(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk"}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}}), res, config.OnNoMatchPassthrough, 0, nil)

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp != nil {
		t.Fatalf("hook returned non-nil with nil logger: %+v", resp)
	}
	if got := req.Header.Get("x-api-key"); got != "sk" {
		t.Fatalf("x-api-key = %q, want %q", got, "sk")
	}
}

// A multi-header rule injects every declared header from ONE resolve: the
// rule's secret_ref is read exactly once per request no matter how many headers
// it feeds, which is what keeps a two-header host off the vendor's read quota
// twice over.
func TestHook_MultiHeaderInjectsBothFromOneResolve(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.example.com",
		SecretRef: "op://Agents/example/api_key",
		Injections: []broker.InjectSpec{
			{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
			{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp != nil {
		t.Fatalf("hook returned response on match: %+v, want nil (forward to upstream)", resp)
	}
	if got := req.Header.Get("authorization"); got != "Bearer sk-secret" {
		t.Fatalf("authorization = %q, want %q", got, "Bearer sk-secret")
	}
	if got := req.Header.Get("x-api-key"); got != "sk-secret" {
		t.Fatalf("x-api-key = %q, want %q", got, "sk-secret")
	}
	if got := res.calls.Load(); got != 1 {
		t.Fatalf("resolver.calls = %d, want 1 (one secret_ref, one read per request)", got)
	}
}

// A multi-header rule fails closed as a unit: one unusable entry means no
// header is injected and the request never reaches the upstream.
func TestHook_MultiHeaderBadEntryFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.example.com",
		SecretRef: "op://Agents/example/api_key",
		Injections: []broker.InjectSpec{
			{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
			{Type: broker.InjectHeader, Name: "x-api-key", Template: "no placeholder"},
		},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp == nil {
		t.Fatalf("unusable injects entry: want non-nil 502, got nil (would forward half-injected)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if _, ok := req.Header["Authorization"]; ok {
		t.Fatalf("authorization set on a fail-closed inject; request must not carry partial credential state")
	}
}

// A placeholder rule that matches the host but whose placeholder token is
// absent from the request must fail closed (502), not forward the request to
// the authenticated upstream with no credential attached.
func TestHook_PlaceholderNotFoundFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Name: "__api_key__", Template: "{{ CREDENTIAL }}"},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.NoBody)
	req.Header.Set("authorization", "Bearer token-without-the-placeholder")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp == nil {
		t.Fatalf("placeholder absent: want non-nil 502, got nil (would forward unauthenticated)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestHook_InjectErrorReturns502(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	// Zero-value InjectSpec.Type is invalid → Inject returns error.
	hook := newHookFixture(t, broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{},
	}, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch

	defer closeIfNonNil(t, resp)
	if resp == nil {
		t.Fatalf("inject err: want non-nil 502 response, got nil")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}
