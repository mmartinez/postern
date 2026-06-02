package broker

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrNoPlaceholder is returned by Inject in placeholder mode when the
// placeholder token is absent from every header value. The rule matched and a
// credential was resolved, but there is nowhere to put it, so the broker fails
// closed rather than forward the request to the upstream unauthenticated.
var ErrNoPlaceholder = errors.New("broker: placeholder token not found in any header")

// ErrNoCredentialPlaceholder is returned by Inject when the rule's template
// carries no {{ CREDENTIAL }} placeholder. Rendering would then discard the
// resolved credential and forward an unauthenticated request, so the broker
// fails closed. The config validator already rejects such templates; this is
// the defense-in-depth backstop for any path that reaches Inject without that
// check (a future caller, or a hot-reload edge), and keeps header mode
// symmetric with placeholder mode's ErrNoPlaceholder guard.
var ErrNoCredentialPlaceholder = errors.New("broker: inject template contains no {{ CREDENTIAL }} placeholder")

// ErrEmptyPlaceholderToken is returned by Inject in placeholder mode when the
// placeholder token (InjectSpec.Name) is empty. An empty token is contained in
// every header value, so the substitution would smear the credential across
// every header — including agent-controlled, agent-readable ones — rather than
// replace a single intended token. The broker fails closed instead. The config
// validator rejects an empty placeholder name; this is the defense-in-depth
// backstop for any path (a future caller, or a hot-reload edge) that reaches
// Inject without that check.
var ErrEmptyPlaceholderToken = errors.New("broker: empty placeholder token")

// InjectType selects the strategy used by Rule.Inject. The zero value is
// invalid and signals an unconfigured rule.
type InjectType int

// Injection strategies recognised by Rule.Inject. The integer values are
// internal and may change; consumers should use the named constants.
const (
	// InjectHeader sets a single named header to the rendered template,
	// overriding any value the agent supplied.
	InjectHeader InjectType = iota + 1

	// InjectPlaceholder finds the placeholder token (InjectSpec.Name) in
	// every header value and substitutes the rendered template in place.
	// Body-level substitution is deferred.
	InjectPlaceholder
)

// InjectSpec describes how a resolved credential is attached to an outbound
// request. The exact meaning of Name depends on Type: it is the header name
// for InjectHeader and the placeholder token for InjectPlaceholder.
type InjectSpec struct {
	Type     InjectType
	Name     string
	Template string
}

// Render substitutes the resolved credential into a template. The config
// validator accepts both "{{ CREDENTIAL }}" and "{{CREDENTIAL}}", so both
// forms are recognised here.
func Render(template, credential string) string {
	r := strings.NewReplacer(
		"{{ CREDENTIAL }}", credential,
		"{{CREDENTIAL}}", credential,
	)
	return r.Replace(template)
}

// hasCredentialPlaceholder reports whether template carries a {{ CREDENTIAL }}
// token (spaced or unspaced). Inject fails closed when it does not, since a
// placeholder-free template renders to a constant string that drops the
// resolved credential entirely.
func hasCredentialPlaceholder(template string) bool {
	return strings.Contains(template, "{{ CREDENTIAL }}") || strings.Contains(template, "{{CREDENTIAL}}")
}

// Inject applies the rule's injection spec to req using credential as the
// secret value. Header mode sets a single header; placeholder mode rewrites
// every header value that contains the placeholder token, and returns
// ErrNoPlaceholder when the token is absent from every header so the proxy
// fails closed instead of forwarding the request unauthenticated. An unknown
// InjectType is treated as a configuration error: Inject returns an error
// without mutating req so the proxy can fail closed.
func (r Rule) Inject(req *http.Request, credential string) error {
	// Guard before mutating anything: a template with no placeholder would
	// render to a constant and forward the request without the credential.
	// Reject it so both inject modes fail closed rather than fail open.
	if !hasCredentialPlaceholder(r.Injection.Template) {
		return ErrNoCredentialPlaceholder
	}
	switch r.Injection.Type {
	case InjectHeader:
		req.Header.Set(r.Injection.Name, Render(r.Injection.Template, credential))
		return nil
	case InjectPlaceholder:
		// An empty token matches the empty substring in every header value, so
		// the substitution below would smear the credential across every header.
		// Fail closed rather than leak it.
		if r.Injection.Name == "" {
			return ErrEmptyPlaceholderToken
		}
		value := Render(r.Injection.Template, credential)
		substitutions := 0
		for k, vs := range req.Header {
			for i, v := range vs {
				if strings.Contains(v, r.Injection.Name) {
					vs[i] = strings.ReplaceAll(v, r.Injection.Name, value)
					substitutions++
				}
			}
			req.Header[k] = vs
		}
		if substitutions == 0 {
			return ErrNoPlaceholder
		}
		return nil
	default:
		return fmt.Errorf("broker: unsupported inject type %d", r.Injection.Type)
	}
}
