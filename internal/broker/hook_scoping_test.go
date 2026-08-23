package broker_test

import (
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

// The fail-closed body is unexported in the broker package by design; these
// tests pin its exact wire shape through the exported behavior instead.
const wantFailClosedBody = "postern: bad gateway\n"

// scopedRule is a minimal header-injection rule whose Paths/Methods fields
// the caller fills per case; everything else matches the fixtures used by
// the rest of the hook suite.
func scopedRule(paths, methods []string) broker.Rule {
	return broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://Agents/Anthropic/api_key",
		Paths:     paths,
		Methods:   methods,
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}
}

// readAll drains a response body so tests can compare it byte for byte.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	_ = resp.Body.Close()
	return string(b)
}

// assertScopedOut checks the uniform fail-closed contract every scoped-out
// request must satisfy: a 502 carrying exactly the failClosedBody shape and
// no stage-revealing headers, with the resolver provably never called.
func assertScopedOut(t *testing.T, res *fakeResolver, resp *http.Response) {
	t.Helper()
	if resp == nil {
		t.Fatalf("scoped-out request forwarded to upstream (nil response); want fail-closed 502")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if got := readAll(t, resp); got != wantFailClosedBody {
		t.Fatalf("body = %q, want %q (uniform fail-closed body)", got, wantFailClosedBody)
	}
	wantHeader := http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}
	if len(resp.Header) != len(wantHeader) {
		t.Fatalf("header set = %v, want exactly %v (no stage-revealing headers allowed)", resp.Header, wantHeader)
	}
	for k, vs := range wantHeader {
		got := resp.Header.Values(k)
		if len(got) != len(vs) || got[0] != vs[0] {
			t.Fatalf("header %q = %v, want %v", k, got, vs)
		}
	}
	if got := res.calls.Load(); got != 0 {
		t.Fatalf("resolver.calls = %d, want 0 (scoping must fail closed before resolve)", got)
	}
}

// TestHook_PathsScope covers AC1: a rule declaring paths injects under any
// declared prefix and returns the uniform fail-closed 502 for every other
// path, without ever calling the resolver on the 502 path.
func TestHook_PathsScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		paths      []string
		method     string
		path       string
		wantInject bool
	}{
		{"exact prefix hit injects", []string{"/v1/messages"}, http.MethodPost, "/v1/messages", true},
		{"deeper path under prefix injects", []string{"/v1/messages"}, http.MethodPost, "/v1/messages/count_tokens", true},
		{"other path under host fails closed", []string{"/v1/messages"}, http.MethodPost, "/v1/models", false},
		{"path sharing the prefix string still matches", []string{"/v1/messages"}, http.MethodPost, "/v1/messages-beta", true},
		{"percent-encoded path does not match its decoded twin", []string{"/v1/messages"}, http.MethodPost, "/v1/mess%61ges", false},
		{"root path fails closed", []string{"/v1/messages"}, http.MethodGet, "/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := &fakeResolver{value: "sk-secret"}
			hook := broker.Hook(broker.NewEngine([]broker.Rule{scopedRule(tc.paths, nil)}), res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // hook is a closure; broker owns the synthetic body

			req, _ := http.NewRequest(tc.method, "https://api.anthropic.com"+tc.path, http.NoBody)
			resp := hook(req) //nolint:bodyclose // closeIfNonNil/assertScopedOut handles the response

			if tc.wantInject {
				if resp != nil {
					t.Fatalf("path %q declared under %q returned %+v, want injection (nil response)", tc.path, tc.paths, resp)
				}
				if got := req.Header.Get("x-api-key"); got != "sk-secret" {
					t.Fatalf("x-api-key = %q, want injected credential", got)
				}
				if got := res.calls.Load(); got != 1 {
					t.Fatalf("resolver.calls = %d, want 1", got)
				}
				return
			}
			assertScopedOut(t, res, resp)
		})
	}
}

// TestHook_MethodsScope covers AC2: a rule declaring methods injects for a
// listed method (case-insensitively) and 502s every other method with the
// resolver never called.
func TestHook_MethodsScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		method     string
		wantInject bool
	}{
		{"listed method injects", http.MethodPost, true},
		{"unlisted method fails closed", http.MethodGet, false},
		{"another unlisted method fails closed", http.MethodDelete, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := &fakeResolver{value: "sk-secret"}
			hook := broker.Hook(broker.NewEngine([]broker.Rule{scopedRule(nil, []string{"POST"})}), res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))

			req, _ := http.NewRequest(tc.method, "https://api.anthropic.com/v1/messages", http.NoBody)
			resp := hook(req) //nolint:bodyclose // closeIfNonNil/assertScopedOut handles the response

			if tc.wantInject {
				defer closeIfNonNil(t, resp)
				if resp != nil {
					t.Fatalf("%s returned %+v, want injection (nil response)", tc.method, resp)
				}
				if got := req.Header.Get("x-api-key"); got != "sk-secret" {
					t.Fatalf("x-api-key = %q, want injected credential", got)
				}
				if got := res.calls.Load(); got != 1 {
					t.Fatalf("resolver.calls = %d, want 1", got)
				}
				return
			}
			assertScopedOut(t, res, resp)
		})
	}
}

// TestHook_MethodMatchCaseInsensitive pins the case-insensitive comparison
// between the request method and the declared entries.
func TestHook_MethodMatchCaseInsensitive(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{scopedRule(nil, []string{"get", "Post"})}), res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req, _ := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/messages", http.NoBody)
	resp := hook(req) //nolint:bodyclose // closeIfNonNil/assertScopedOut handles the response

	defer closeIfNonNil(t, resp)
	if resp != nil {
		t.Fatalf("lowercase-declared get did not match GET: %+v", resp)
	}
	if got := req.Header.Get("x-api-key"); got != "sk-secret" {
		t.Fatalf("x-api-key = %q, want injected credential", got)
	}
}

// TestHook_CombinedPathsAndMethodsScope covers rules declaring both knobs:
// both scopes must allow the request; satisfying one while missing the
// other still fails closed.
func TestHook_CombinedPathsAndMethodsScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		method     string
		path       string
		wantInject bool
	}{
		{"both scopes satisfied injects", http.MethodPost, "/v1/messages", true},
		{"path ok but method out fails closed", http.MethodGet, "/v1/messages", false},
		{"method ok but path out fails closed", http.MethodPost, "/v1/models", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := &fakeResolver{value: "sk-secret"}
			rule := scopedRule([]string{"/v1/messages"}, []string{"POST"})
			hook := broker.Hook(broker.NewEngine([]broker.Rule{rule}), res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))

			req, _ := http.NewRequest(tc.method, "https://api.anthropic.com"+tc.path, http.NoBody)
			resp := hook(req) //nolint:bodyclose // closeIfNonNil/assertScopedOut handles the response

			if tc.wantInject {
				defer closeIfNonNil(t, resp)
				if resp != nil {
					t.Fatalf("%s %s returned %+v, want injection", tc.method, tc.path, resp)
				}
				if got := req.Header.Get("x-api-key"); got != "sk-secret" {
					t.Fatalf("x-api-key = %q, want injected credential", got)
				}
				return
			}
			assertScopedOut(t, res, resp)
		})
	}
}

// TestHook_UnscopedRuleBehavesAsToday covers AC3 at the unit level: a rule
// with neither paths nor methods brokers every path and method on its host,
// exactly as before the scoping knob existed. The unchanged full suites are
// the system-level proof; this case guards the empty-slice semantics.
func TestHook_UnscopedRuleBehavesAsToday(t *testing.T) {
	t.Parallel()

	res := &fakeResolver{value: "sk-secret"}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{scopedRule(nil, nil)}), res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/anything"},
		{http.MethodPost, "/deeply/nested/path"},
		{http.MethodDelete, "/"},
	} {
		req, _ := http.NewRequest(tc.method, "https://api.anthropic.com"+tc.path, http.NoBody)
		resp := hook(req) //nolint:bodyclose // closeIfNonNil/assertScopedOut handles the response
		closeIfNonNil(t, resp)
		if resp != nil {
			t.Fatalf("%s %s returned %+v, want unscoped forwarding (nil)", tc.method, tc.path, resp)
		}
		if req.Header.Get("x-api-key") == "" {
			t.Fatalf("%s %s not injected on unscoped rule", tc.method, tc.path)
		}
	}
	if got := res.calls.Load(); got != 3 {
		t.Fatalf("resolver.calls = %d, want 3 (one per unscoped request)", got)
	}
}

// TestHook_ScopedOut502IsWireIdenticalToOtherBroker502s covers AC5: a
// scoping refusal must be indistinguishable on the wire from every other
// broker fail-closed 502 — same status line fields, headers, and body —
// because a differential would hand a hostile agent a stage oracle.
func TestHook_ScopedOut502IsWireIdenticalToOtherBroker502s(t *testing.T) {
	t.Parallel()

	// Stage A: scoping refusal (declared prefix misses).
	scopeRes := &fakeResolver{value: "sk-secret"}
	scopeHook := broker.Hook(broker.NewEngine([]broker.Rule{scopedRule([]string{"/v1/messages"}, nil)}), scopeRes, config.OnNoMatchPassthrough, 0, nil)
	scopedReq, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/other", http.NoBody)
	scopedResp := scopeHook(scopedReq) //nolint:bodyclose // closed via closeIfNonNil below

	// Stage B: the pre-existing insecure-transport refusal for the same rule.
	plainRes := &fakeResolver{value: "sk-secret"}
	plainHook := broker.Hook(broker.NewEngine([]broker.Rule{scopedRule(nil, nil)}), plainRes, config.OnNoMatchPassthrough, 0, nil)
	plainReq, _ := http.NewRequest(http.MethodPost, "http://api.anthropic.com/v1/messages", http.NoBody)
	plainResp := plainHook(plainReq) //nolint:bodyclose // closed via closeIfNonNil below

	if scopedResp == nil || plainResp == nil {
		t.Fatalf("expected two 502 responses, got scoped=%v plain=%v", scopedResp, plainResp)
	}
	defer closeIfNonNil(t, scopedResp)
	defer closeIfNonNil(t, plainResp)

	if scopedResp.StatusCode != plainResp.StatusCode ||
		scopedResp.Status != plainResp.Status ||
		scopedResp.ProtoMajor != plainResp.ProtoMajor ||
		scopedResp.ProtoMinor != plainResp.ProtoMinor ||
		scopedResp.ContentLength != plainResp.ContentLength {
		t.Fatalf("scoped-out 502 differs in status framing: scoped=%+v other=%+v", scopedResp, plainResp)
	}
	if strings.Join(scopeSorted(scopedResp.Header), "|") != strings.Join(scopeSorted(plainResp.Header), "|") {
		t.Fatalf("headers differ: scoped=%v other=%v (stage oracle)", scopedResp.Header, plainResp.Header)
	}
	if readAll(t, scopedResp) != readAll(t, plainResp) {
		t.Fatalf("bodies differ between scoping refusal and transport refusal (stage oracle)")
	}
}

// scopeSorted flattens a header map into a stable comparable string.
func scopeSorted(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k, vs := range h {
		out = append(out, k+":"+strings.Join(vs, ","))
	}
	sort.Strings(out)
	return out
}
