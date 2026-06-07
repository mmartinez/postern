package broker_test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

// routedRule is the canonical placeholder-routing rule used across these tests:
// one host, two named routes whose tokens each select a distinct secret. The
// shared inject spec is placeholder mode, header surface (the default).
func routedRule() broker.Rule {
	return broker.Rule{
		Host: "api.telegram.org",
		Routes: []broker.Route{
			{Name: "max", Token: "tg_max_8Kq2Lp9wZ", SecretRef: "op://Agents/telegram-max/token"},
			{Name: "john", Token: "tg_john_3Rt7Yx1mQ", SecretRef: "op://Agents/telegram-john/token"},
		},
		Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Template: "{{ CREDENTIAL }}"},
	}
}

func TestFromConfigRules_TranslatesRoutes(t *testing.T) {
	t.Parallel()

	in := []config.Rule{{
		Host: "api.telegram.org",
		Inject: config.Inject{
			Type:     config.InjectTypePlaceholder,
			Template: "{{ CREDENTIAL }}",
		},
		Routes: []config.Route{
			{Name: "max", Token: "tg_max_8Kq2Lp9wZ", SecretRef: "op://Agents/telegram-max/token"},
			{Name: "john", Token: "tg_john_3Rt7Yx1mQ", SecretRef: "op://Agents/telegram-john/token"},
		},
	}}

	got, err := broker.FromConfigRules(in)
	if err != nil {
		t.Fatalf("FromConfigRules: %v", err)
	}

	want := []broker.Rule{{
		Host: "api.telegram.org",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Template: "{{ CREDENTIAL }}",
		},
		Routes: []broker.Route{
			{Name: "max", Token: "tg_max_8Kq2Lp9wZ", SecretRef: "op://Agents/telegram-max/token"},
			{Name: "john", Token: "tg_john_3Rt7Yx1mQ", SecretRef: "op://Agents/telegram-john/token"},
		},
	}}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("rules diff (-want +got):\n%s", diff)
	}
}

// The token an agent presents selects which secret postern resolves: the
// resolver must be invoked with the matched route's secret_ref, and the token
// in the request must be replaced by the resolved credential.
func TestHook_RouteSelectsSecretByToken(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, routedRule(), res) //nolint:bodyclose // hook is a closure; subtests below close each response

	t.Run("max token routes to max secret", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
		req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
		resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
		defer closeIfNonNil(t, resp)

		if resp != nil {
			t.Fatalf("hook returned response on routed match: %+v, want nil", resp)
		}
		if got := res.lastVR.ref; got != "op://Agents/telegram-max/token" {
			t.Fatalf("resolver ref = %q, want max route ref", got)
		}
		if got := req.Header.Get("authorization"); got != "Bearer sk-secret" {
			t.Fatalf("authorization = %q, want %q (token replaced)", got, "Bearer sk-secret")
		}
	})

	t.Run("john token routes to john secret", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
		req.Header.Set("authorization", "Bearer tg_john_3Rt7Yx1mQ")
		resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
		defer closeIfNonNil(t, resp)

		if resp != nil {
			t.Fatalf("hook returned response on routed match: %+v, want nil", resp)
		}
		if got := res.lastVR.ref; got != "op://Agents/telegram-john/token" {
			t.Fatalf("resolver ref = %q, want john route ref", got)
		}
	})
}

// Routing on the body surface: selection scans the buffered body (and must
// restore it) and the matched token is rewritten in place. Guards the
// read-and-restore path that selection adds before injection re-reads the body.
func TestHook_RouteSelectsByBodyToken(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	rule := routedRule()
	rule.Injection.Surfaces = []broker.Surface{broker.SurfaceBody}
	hook := newHookFixture(t, rule, res)

	body := `{"token":"tg_john_3Rt7Yx1mQ"}`
	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp != nil {
		t.Fatalf("hook returned response on routed body match: %+v, want nil", resp)
	}
	if got := res.lastVR.ref; got != "op://Agents/telegram-john/token" {
		t.Fatalf("resolver ref = %q, want john route ref", got)
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != `{"token":"sk-secret"}` {
		t.Fatalf("body = %q, want token replaced by credential", got)
	}
}

// An unknown token (no configured route) must fail closed without ever calling
// the resolver — the allowlist contract: only enumerated tokens resolve.
func TestHook_RouteUnknownTokenFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, routedRule(), res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_nobody_unknown")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp == nil {
		t.Fatalf("unknown token: want non-nil 502, got nil (would forward unauthenticated)")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (unknown token must not resolve)", got)
	}
}

// A resolver error on a selected route must fail closed (502) and leave no
// partial credential on the request: the route was selected (resolver called)
// but injection never runs.
func TestHook_RouteResolverErrorFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{err: errors.New("token revoked")}
	hook := newHookFixture(t, routedRule(), res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("resolver error on routed match: want 502, got %+v", resp)
	}
	if got := res.calls.Load(); got != 1 {
		t.Fatalf("resolver.calls = %d, want 1 (route was selected then resolve failed)", got)
	}
	if got := req.Header.Get("authorization"); got != "Bearer tg_max_8Kq2Lp9wZ" {
		t.Fatalf("authorization mutated on failed resolve: %q (no partial credential allowed)", got)
	}
}

// A resolver that returns ("", nil) on a selected route must fail closed rather
// than inject an empty credential ("Bearer ").
func TestHook_RouteEmptyCredentialFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: ""}
	hook := newHookFixture(t, routedRule(), res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("empty credential on routed match: want 502, got %+v", resp)
	}
	if got := req.Header.Get("authorization"); got == "Bearer " {
		t.Fatalf("empty credential injected; want fail closed before injection")
	}
}

// Two distinct route tokens present in one request is ambiguous: postern must
// not guess which secret the agent wanted. Fail closed, resolver untouched.
func TestHook_RouteAmbiguousFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := newHookFixture(t, routedRule(), res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	req.Header.Set("x-alt", "tg_john_3Rt7Yx1mQ")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp == nil {
		t.Fatalf("ambiguous tokens: want non-nil 502, got nil")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (ambiguous selection must not resolve)", got)
	}
}

// Routing logs must attribute the request to the route's name for observability
// but must NEVER contain the token value, which is effectively a shared secret.
func TestHook_RouteTokenNeverLogged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hook := broker.Hook(broker.NewEngine([]broker.Rule{routedRule()}), &fakeResolver{value: "sk-secret"}, config.OnNoMatchPassthrough, 0, logger) //nolint:bodyclose // closeIfNonNil handles the non-nil branch

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	logs := buf.String()
	if !contains(logs, "api.telegram.org") {
		t.Fatalf("logs missing host attribution; got %q", logs)
	}
	if !contains(logs, "max") {
		t.Fatalf("logs missing route name attribution; got %q", logs)
	}
	if contains(logs, "tg_max_8Kq2Lp9wZ") {
		t.Fatalf("logs leaked the route token; got %q", logs)
	}
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}

// A body-surface route whose token sits in a body postern won't scan
// (compressed/multipart) must fail closed: the token is unreadable, so no route
// is selected and the resolver is never called.
func TestHook_RouteBodyCompressedFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	rule := routedRule()
	rule.Injection.Surfaces = []broker.Surface{broker.SurfaceBody}
	hook := newHookFixture(t, rule, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage",
		strings.NewReader(`{"token":"tg_max_8Kq2Lp9wZ"}`))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("content-encoding", "gzip") // opaque to postern; body is not scanned
	resp := hook(req)                          //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("compressed-body route: want 502, got %+v", resp)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (an unscannable body must not select or resolve)", got)
	}
}

// Two different route tokens present across different surfaces (one in a header,
// one in the body) is ambiguous and must fail closed — selection aggregates
// across surfaces, so this must not silently pick the first.
func TestHook_RouteCrossSurfaceAmbiguityFailsClosed(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	rule := routedRule()
	rule.Injection.Surfaces = []broker.Surface{broker.SurfaceHeader, broker.SurfaceBody}
	hook := newHookFixture(t, rule, res)

	req, _ := http.NewRequest(http.MethodPost, "https://api.telegram.org/sendMessage",
		strings.NewReader(`{"token":"tg_john_3Rt7Yx1mQ"}`))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("cross-surface ambiguity: want 502, got %+v", resp)
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (ambiguous selection must not resolve)", got)
	}
}

func TestHook_RouteSelectsByPathToken(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	rule := routedRule()
	rule.Injection.Surfaces = []broker.Surface{broker.SurfacePath}
	hook := newHookFixture(t, rule, res)

	req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/v1/tg_max_8Kq2Lp9wZ/models", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp != nil {
		t.Fatalf("hook returned response on path-routed match: %+v, want nil", resp)
	}
	if got := res.lastVR.ref; got != "op://Agents/telegram-max/token" {
		t.Fatalf("resolver ref = %q, want max route ref", got)
	}
	if !strings.Contains(req.URL.EscapedPath(), "sk-secret") {
		t.Fatalf("path = %q, want token replaced by credential", req.URL.EscapedPath())
	}
}

func TestHook_RouteSelectsByQueryToken(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	rule := routedRule()
	rule.Injection.Surfaces = []broker.Surface{broker.SurfaceQuery}
	hook := newHookFixture(t, rule, res)

	req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/v1/models?key=tg_john_3Rt7Yx1mQ", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil handles the non-nil branch
	defer closeIfNonNil(t, resp)

	if resp != nil {
		t.Fatalf("hook returned response on query-routed match: %+v, want nil", resp)
	}
	if got := res.lastVR.ref; got != "op://Agents/telegram-john/token" {
		t.Fatalf("resolver ref = %q, want john route ref", got)
	}
	if !strings.Contains(req.URL.RawQuery, "sk-secret") {
		t.Fatalf("query = %q, want token replaced by credential", req.URL.RawQuery)
	}
}

// InjectRoute carries the same defense-in-depth backstops as Inject: a template
// without {{ CREDENTIAL }} and an empty route token both fail closed without
// mutating the request, even though the validator already rejects both.
func TestInjectRoute_FailsClosedGuards(t *testing.T) {
	t.Parallel()

	noCred := broker.Rule{
		Host:      "api.telegram.org",
		Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Template: "static-no-placeholder"},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	err := noCred.InjectRoute(req, broker.Route{Name: "max", Token: "tg_max_8Kq2Lp9wZ", SecretRef: "op://V/m"}, "sk")
	if !errors.Is(err, broker.ErrNoCredentialPlaceholder) {
		t.Fatalf("template without {{ CREDENTIAL }}: err = %v, want ErrNoCredentialPlaceholder", err)
	}
	if got := req.Header.Get("authorization"); got != "Bearer tg_max_8Kq2Lp9wZ" {
		t.Fatalf("request mutated on guard failure: %q", got)
	}

	emptyTok := broker.Rule{
		Host:      "api.telegram.org",
		Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Template: "{{ CREDENTIAL }}"},
	}
	req2, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/", http.NoBody)
	err = emptyTok.InjectRoute(req2, broker.Route{Name: "x", Token: "", SecretRef: "op://V/x"}, "sk")
	if !errors.Is(err, broker.ErrEmptyPlaceholderToken) {
		t.Fatalf("empty route token: err = %v, want ErrEmptyPlaceholderToken", err)
	}
}

// A routes rule must survive engine.Swap (the atomic ruleset copy) intact: the
// new ruleset's tokens select, and the pre-swap token no longer does.
func TestEngine_SwapPreservesRoutesRule(t *testing.T) {
	t.Parallel()

	eng := broker.NewEngine([]broker.Rule{routedRule()})
	swapped := broker.Rule{
		Host:      "api.telegram.org",
		Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Template: "{{ CREDENTIAL }}"},
		Routes:    []broker.Route{{Name: "alice", Token: "tg_alice_Zz9Qq", SecretRef: "op://Agents/alice/token"}},
	}
	eng.Swap([]broker.Rule{swapped})

	got, ok := eng.Match("api.telegram.org")
	if !ok {
		t.Fatalf("Match after Swap: rule not found")
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/", http.NoBody)
	req.Header.Set("authorization", "Bearer tg_alice_Zz9Qq")
	route, sel := got.SelectRoute(req)
	if !sel || route.Name != "alice" || route.SecretRef != "op://Agents/alice/token" {
		t.Fatalf("SelectRoute after Swap = (%+v, %v), want alice route", route, sel)
	}

	old, _ := http.NewRequest(http.MethodGet, "https://api.telegram.org/", http.NoBody)
	old.Header.Set("authorization", "Bearer tg_max_8Kq2Lp9wZ")
	if _, sel := got.SelectRoute(old); sel {
		t.Fatalf("pre-swap token still selects after Swap (stale ruleset)")
	}
}
