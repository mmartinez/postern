package broker_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/mmartinez/postern/internal/broker"
)

// TestRender exercises the {{ CREDENTIAL }} substitution. The config
// validator accepts both spaced and unspaced forms, so both must render.
func TestRender(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		template string
		cred     string
		want     string
	}{
		{"spaced placeholder", "{{ CREDENTIAL }}", "sk-abc", "sk-abc"},
		{"unspaced placeholder", "{{CREDENTIAL}}", "sk-abc", "sk-abc"},
		{"bearer wrapper", "Bearer {{ CREDENTIAL }}", "sk-abc", "Bearer sk-abc"},
		{"repeated placeholder", "{{ CREDENTIAL }}-{{CREDENTIAL}}", "x", "x-x"},
		{"no placeholder is rendered verbatim", "literal", "x", "literal"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := broker.Render(tc.template, tc.cred); got != tc.want {
				t.Fatalf("Render(%q,%q) = %q, want %q", tc.template, tc.cred, got, tc.want)
			}
		})
	}
}

func TestInjectHeader_SetsHeader(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.anthropic.com",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if err := r.Inject(req, "sk-secret"); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	if got := req.Header.Get("x-api-key"); got != "sk-secret" {
		t.Fatalf("x-api-key = %q, want %q", got, "sk-secret")
	}
}

func TestInjectHeader_TemplateOverridesExistingValue(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.openai.com",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "authorization",
			Template: "Bearer {{ CREDENTIAL }}",
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", http.NoBody)
	req.Header.Set("authorization", "Bearer placeholder")

	if err := r.Inject(req, "sk-real"); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	if got := req.Header.Get("authorization"); got != "Bearer sk-real" {
		t.Fatalf("authorization = %q, want %q", got, "Bearer sk-real")
	}
}

// Placeholder mode replaces a literal token (Inject.Name) in every header
// value with the rendered template. Body-level substitution is deferred.
func TestInjectPlaceholder_RewritesHeaderValues(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Name:     "__api_key__",
			Template: "{{ CREDENTIAL }}",
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/ping", http.NoBody)
	req.Header.Set("x-api-key", "__api_key__")
	req.Header.Set("x-trace", "prefix-__api_key__-suffix")
	req.Header.Set("x-untouched", "noplaceholder")

	if err := r.Inject(req, "sk-real"); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	got := map[string]string{
		"x-api-key":   req.Header.Get("x-api-key"),
		"x-trace":     req.Header.Get("x-trace"),
		"x-untouched": req.Header.Get("x-untouched"),
	}
	want := map[string]string{
		"x-api-key":   "sk-real",
		"x-trace":     "prefix-sk-real-suffix",
		"x-untouched": "noplaceholder",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("headers diff (-want +got):\n%s", diff)
	}
}

// A placeholder rule that matches the host but finds no placeholder token in
// any header must fail (so the hook can fail closed) rather than silently
// forward the request unauthenticated. The credential must not leak into any
// header on that path.
func TestInjectPlaceholder_NoMatchReturnsErrNoPlaceholder(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Name:     "__api_key__",
			Template: "{{ CREDENTIAL }}",
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/ping", http.NoBody)
	req.Header.Set("x-other", "no-token-here")

	err := r.Inject(req, "sk-real")
	if !errors.Is(err, broker.ErrNoPlaceholder) {
		t.Fatalf("Inject with no matching placeholder: got %v, want ErrNoPlaceholder", err)
	}
	if got := req.Header.Get("x-other"); got != "no-token-here" {
		t.Fatalf("x-other mutated to %q; credential must not leak when no placeholder matched", got)
	}
}

// A placeholder rule whose token (Inject.Name) is empty must fail closed. An
// empty token matches the empty substring in every header value, so the naive
// strings.ReplaceAll would smear the credential across every header — including
// agent-controlled, agent-readable ones. The request must be left unmutated so
// nothing leaks.
func TestInjectPlaceholder_EmptyTokenFailsClosed(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Name:     "",
			Template: "{{ CREDENTIAL }}",
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/ping", http.NoBody)
	req.Header.Set("user-agent", "agent/1.0")

	err := r.Inject(req, "sk-real-secret")
	if !errors.Is(err, broker.ErrEmptyPlaceholderToken) {
		t.Fatalf("Inject with empty placeholder token: got %v, want ErrEmptyPlaceholderToken", err)
	}
	if got := req.Header.Get("user-agent"); got != "agent/1.0" {
		t.Fatalf("user-agent mutated to %q; credential must not smear into headers", got)
	}
}

// A multi-header rule feeds every declared header from the one credential the
// caller resolved. Both headers must carry the rendered template, and Set must
// override whatever the agent supplied.
func TestInject_MultiHeader_SetsEveryHeader(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		Injections: []broker.InjectSpec{
			{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
			{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		},
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/messages", http.NoBody)
	req.Header.Set("authorization", "Bearer placeholder")

	if err := r.Inject(req, "sk-real"); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	got := map[string]string{
		"authorization": req.Header.Get("authorization"),
		"x-api-key":     req.Header.Get("x-api-key"),
	}
	want := map[string]string{
		"authorization": "Bearer sk-real",
		"x-api-key":     "sk-real",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("headers diff (-want +got):\n%s", diff)
	}
}

// Entries are applied in list order, so a repeated header name resolves to the
// last entry. The config validator rejects such a rule; this pins the runtime
// behavior for anything that reaches Inject without that check.
func TestInject_MultiHeader_PreservesListOrder(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		Injections: []broker.InjectSpec{
			{Type: broker.InjectHeader, Name: "authorization", Template: "first {{ CREDENTIAL }}"},
			{Type: broker.InjectHeader, Name: "authorization", Template: "last {{ CREDENTIAL }}"},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", http.NoBody)

	if err := r.Inject(req, "sk-real"); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if got := req.Header.Get("authorization"); got != "last sk-real" {
		t.Fatalf("authorization = %q, want %q (later entry wins)", got, "last sk-real")
	}
}

// Every fail-closed guard applies per entry, and nothing is written until all
// entries pass: a bad second entry must leave the first header unset rather
// than forward a half-injected request.
func TestInject_MultiHeader_PerEntryGuardsFailClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		second  broker.InjectSpec
		wantErr error
	}{
		{
			name:    "CRLF in the rendered value",
			second:  broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}\r\nx-evil: 1"},
			wantErr: broker.ErrHeaderInjection,
		},
		{
			name:    "template without the CREDENTIAL placeholder",
			second:  broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "static"},
			wantErr: broker.ErrNoCredentialPlaceholder,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := broker.Rule{
				Host: "api.example.com",
				Injections: []broker.InjectSpec{
					{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
					tc.second,
				},
			}
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", http.NoBody)

			err := r.Inject(req, "sk-real")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Inject: got %v, want %v", err, tc.wantErr)
			}
			if _, ok := req.Header["Authorization"]; ok {
				t.Fatalf("authorization set despite a failing entry; a fail-closed inject must not partially mutate the request")
			}
			if _, ok := req.Header["X-Api-Key"]; ok {
				t.Fatalf("x-api-key set from a failing entry")
			}
		})
	}
}

// Non-header entries and empty header names never reach a validated config;
// Inject rejects them anyway rather than write a credential somewhere the
// caller did not intend.
func TestInject_MultiHeader_RejectsUnusableEntry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		entry broker.InjectSpec
	}{
		{"non-header type", broker.InjectSpec{Type: broker.InjectPlaceholder, Name: "__tok__", Template: "{{ CREDENTIAL }}"}},
		{"empty header name", broker.InjectSpec{Type: broker.InjectHeader, Name: "", Template: "{{ CREDENTIAL }}"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := broker.Rule{Host: "api.example.com", Injections: []broker.InjectSpec{tc.entry}}
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", http.NoBody)

			if err := r.Inject(req, "sk-real"); err == nil {
				t.Fatalf("Inject with %s: want error, got nil", tc.name)
			}
			if len(req.Header) != 0 {
				t.Fatalf("headers mutated to %v; nothing must be injected when failing closed", req.Header)
			}
		})
	}
}

func TestInject_UnknownTypeReturnsError(t *testing.T) {
	t.Parallel()

	r := broker.Rule{
		Host: "api.example.com",
		// Valid template so the placeholder guard passes and we reach (and
		// exercise) the inject-type switch's default arm.
		Injection: broker.InjectSpec{Type: 0, Template: "{{ CREDENTIAL }}"},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", http.NoBody)

	err := r.Inject(req, "sk-real")
	if err == nil {
		t.Fatalf("Inject with zero InjectType: want error, got nil")
	}
}

// A template carrying no {{ CREDENTIAL }} placeholder must fail closed in BOTH
// inject modes: rendering would discard the resolved credential and forward an
// unauthenticated request. The request must be left unmutated so nothing leaks.
func TestInject_NoCredentialPlaceholder_FailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		spec broker.InjectSpec
	}{
		{
			name: "header mode",
			spec: broker.InjectSpec{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer "},
		},
		{
			name: "placeholder mode",
			spec: broker.InjectSpec{Type: broker.InjectPlaceholder, Name: "__tok__", Template: "static"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := broker.Rule{Host: "api.example.com", Injection: tc.spec}
			req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/", http.NoBody)
			req.Header.Set("authorization", "Bearer __tok__")

			err := r.Inject(req, "sk-real")
			if !errors.Is(err, broker.ErrNoCredentialPlaceholder) {
				t.Fatalf("Inject with placeholder-free template: got %v, want ErrNoCredentialPlaceholder", err)
			}
			if got := req.Header.Get("authorization"); got != "Bearer __tok__" {
				t.Fatalf("header mutated to %q; nothing must be injected when failing closed", got)
			}
		})
	}
}
