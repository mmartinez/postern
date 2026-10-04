package broker_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

// The broker hook must leave the credential it injected on the request
// context so the proxy's response filter can strip it from an upstream
// response. The value must be present on every injection path and absent
// everywhere the hook declines to inject.

func TestHook_InjectedCredentialReachesRequestContext(t *testing.T) {
	t.Parallel()

	const cred = "sk-the-real-secret"
	for _, tc := range []struct {
		name string
		rule broker.Rule
		url  string
	}{
		{
			name: "header injection",
			rule: broker.Rule{
				Host:      "api.anthropic.com",
				SecretRef: "op://V/I/f",
				Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
			},
			url: "https://api.anthropic.com/v1/models",
		},
		{
			name: "header template with a fixed prefix",
			rule: broker.Rule{
				Host:      "api.anthropic.com",
				SecretRef: "op://V/I/f",
				Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
			},
			url: "https://api.anthropic.com/v1/models",
		},
		{
			name: "placeholder injection over the query surface",
			rule: broker.Rule{
				Host:      "api.telegram.org",
				SecretRef: "op://V/I/f",
				Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Name: "tg_token", Surfaces: []broker.Surface{broker.SurfaceQuery}, Template: "{{ CREDENTIAL }}"},
			},
			url: "https://api.telegram.org/send?tg_token=ph",
		},
		{
			name: "placeholder injection over the header surface",
			rule: broker.Rule{
				Host:      "api.telegram.org",
				SecretRef: "op://V/I/f",
				Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Name: "tg_token", Surfaces: []broker.Surface{broker.SurfaceHeader}, Template: "{{ CREDENTIAL }}"},
			},
			url: "https://api.telegram.org/send",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hook := newHookFixture(t, tc.rule, &fakeResolver{value: cred}) //nolint:bodyclose // hook is a closure; it returns nil on success
			req, err := http.NewRequest(http.MethodGet, tc.url, http.NoBody)
			require.NoError(t, err)
			// The header-surface placeholder is a header value the agent
			// presents; the broker replaces it in place.
			if tc.name == "placeholder injection over the header surface" {
				req.Header.Set("Authorization", "Bearer tg_token")
			}
			require.Nil(t, hook(req)) //nolint:bodyclose // nil on success

			got, ok := broker.InjectedCredentials(req.Context())
			require.True(t, ok, "the hook must record the injected credential for the response filter")
			require.Equal(t, []string{cred}, got)
		})
	}
}

// A routed rule resolves a different secret per agent; each request's context
// must carry the secret that request actually injected, not another route's.
func TestHook_RoutedRequestRecordsItsOwnCredential(t *testing.T) {
	t.Parallel()

	rule := broker.Rule{
		Host: "api.telegram.org",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Surfaces: []broker.Surface{broker.SurfaceHeader},
			Template: "{{ CREDENTIAL }}",
		},
		Routes: []broker.Route{
			{Name: "max", Token: "tg_max", SecretRef: "op://V/max"},
			{Name: "john", Token: "tg_john", SecretRef: "op://V/john"},
		},
	}

	hook := newHookFixture(t, rule, &perRouteResolver{byRef: map[string]string{ //nolint:bodyclose // hook is a closure; it returns nil on success
		"op://V/max":  "secret-for-max",
		"op://V/john": "secret-for-john",
	}})

	req, err := http.NewRequest(http.MethodGet, "https://api.telegram.org/sendMessage", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tg_john")
	require.Nil(t, hook(req)) //nolint:bodyclose // nil on success

	got, ok := broker.InjectedCredentials(req.Context())
	require.True(t, ok)
	require.Equal(t, []string{"secret-for-john"}, got)
}

// Every path where the hook does NOT inject must leave the context untouched,
// so the proxy's response filter no-ops instead of scanning for nothing.
func TestHook_NoInjectedCredentialWhenNothingWasInjected(t *testing.T) {
	t.Parallel()

	scoped := broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Paths:     []string{"/v1/messages"},
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}
	plain := broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}

	for _, tc := range []struct {
		name   string
		rule   broker.Rule
		res    broker.Resolver
		method string
		url    string
	}{
		{
			name: "resolver error fails closed",
			rule: plain,
			res:  &fakeResolver{err: context.DeadlineExceeded},
			url:  "https://api.anthropic.com/v1/models",
		},
		{
			name: "empty credential fails closed",
			rule: plain,
			res:  &fakeResolver{value: ""},
			url:  "https://api.anthropic.com/v1/models",
		},
		{
			name: "no matching rule",
			rule: plain,
			res:  &fakeResolver{value: "sk-secret"},
			url:  "https://api.openai.com/v1/models",
		},
		{
			name: "request outside the rule's path scope",
			rule: scoped,
			res:  &fakeResolver{value: "sk-secret"},
			url:  "https://api.anthropic.com/v1/other",
		},
		{
			name: "request outside the rule's method scope",
			rule: broker.Rule{
				Host:      "api.anthropic.com",
				SecretRef: "op://V/I/f",
				Methods:   []string{"POST"},
				Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
			},
			res:    &fakeResolver{value: "sk-secret"},
			method: http.MethodGet,
			url:    "https://api.anthropic.com/v1/messages",
		},
		{
			name: "insecure transport",
			rule: plain,
			res:  &fakeResolver{value: "sk-secret"},
			url:  "http://api.anthropic.com/v1/models",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hook := newHookFixture(t, tc.rule, tc.res)
			req, err := http.NewRequest(tc.method, tc.url, http.NoBody)
			require.NoError(t, err)

			resp := hook(req) //nolint:bodyclose // closeIfNonNil below handles the non-nil branch
			closeIfNonNil(t, resp)

			_, ok := broker.InjectedCredentials(req.Context())
			require.False(t, ok, "a request that never received a credential must not mark one")
		})
	}
}

// The credential must never reach the log stream. This pins the absolute
// project rule against the hook's own output at debug level, where every
// field it emits is populated.
func TestHook_InjectedCredentialNeverLogged(t *testing.T) {
	t.Parallel()

	const cred = "sk-ant-api03-do-not-log-me"
	buf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rule := broker.Rule{
		Host:      "api.anthropic.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{rule}), &fakeResolver{value: cred}, config.OnNoMatchPassthrough, 0, true, logger) //nolint:bodyclose // hook is a closure; it returns nil on success
	req, err := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models", http.NoBody)
	require.NoError(t, err)
	require.Nil(t, hook(req)) //nolint:bodyclose // nil on success

	require.NotContains(t, buf.String(), cred, "the broker logged the credential it injected")
}

// TestInjectedCredential_ContextRoundTrip documents the channel contract the
// proxy relies on: the value survives request-context propagation unchanged,
// and an unmarked context reports absence rather than an empty credential.
func TestInjectedCredential_ContextRoundTrip(t *testing.T) {
	t.Parallel()

	const cred = "sk-round-trip"
	got, ok := broker.InjectedCredentials(broker.WithInjectedCredentials(context.Background(), cred))
	require.True(t, ok)
	require.Equal(t, []string{cred}, got)

	_, ok = broker.InjectedCredentials(context.Background())
	require.False(t, ok, "a context with nothing injected must report absence")
}

// perRouteResolver resolves a different value per secret reference so a
// routed rule's per-agent secrets can be told apart.
type perRouteResolver struct {
	byRef map[string]string
}

func (r *perRouteResolver) Resolve(_ context.Context, _, ref string) (string, error) {
	v, ok := r.byRef[ref]
	if !ok {
		return "", context.Canceled
	}
	return v, nil
}
