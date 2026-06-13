package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// ErrNoPlaceholder is returned by Inject in placeholder mode when the
// placeholder token is absent from every eligible surface. The rule matched
// and a credential was resolved, but there is nowhere to put it, so the broker
// fails closed rather than forward the request to the upstream unauthenticated.
var ErrNoPlaceholder = errors.New("broker: placeholder token not found on any declared surface")

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
// every value, so the substitution would smear the credential everywhere
// rather than replace a single intended token. The broker fails closed
// instead. The config validator rejects an empty placeholder name; this is the
// defense-in-depth backstop for any path (a future caller, or a hot-reload
// edge) that reaches Inject without that check.
var ErrEmptyPlaceholderToken = errors.New("broker: empty placeholder token")

// ErrHeaderInjection is returned by Inject when the rendered value contains a
// CR or LF. Splicing such a value into a header would let an attacker inject
// extra headers or smuggle a second request, so the broker fails closed. The
// guard covers both inject modes for any surface that writes a raw header.
var ErrHeaderInjection = errors.New("broker: rendered value contains CR/LF; refusing header injection")

// InjectType selects the strategy used by Rule.Inject. The zero value is
// invalid and signals an unconfigured rule.
type InjectType int

// Injection strategies recognised by Rule.Inject. The integer values are
// internal and may change; consumers should use the named constants.
const (
	// InjectHeader sets a single named header to the rendered template,
	// overriding any value the agent supplied.
	InjectHeader InjectType = iota + 1

	// InjectPlaceholder finds the placeholder token (InjectSpec.Name) on
	// every declared surface (InjectSpec.Surfaces) and substitutes the
	// rendered template in place, with per-surface encoding.
	InjectPlaceholder

	// InjectOAuth1 signs the request with OAuth 1.0a (HMAC-SHA1) and sets the
	// Authorization: OAuth header. It uses InjectSpec.OAuth1 (four resolved
	// secret refs) instead of a credential template, so Hook handles it on a
	// dedicated path rather than through Rule.Inject.
	InjectOAuth1
)

// Surface names a request component placeholder substitution can rewrite. The
// zero value is invalid. Only InjectPlaceholder consults surfaces.
type Surface int

// Substitution surfaces recognised by Rule.Inject in placeholder mode.
const (
	// SurfaceHeader substitutes the token in header values (the default).
	SurfaceHeader Surface = iota + 1
	// SurfaceBody substitutes the token in the request body, with encoding
	// chosen by Content-Type.
	SurfaceBody
	// SurfacePath substitutes the token in the URL path, percent-escaping
	// the value as a path segment.
	SurfacePath
	// SurfaceQuery substitutes the token in the URL query string,
	// percent-escaping the value as a query component.
	SurfaceQuery
)

// InjectSpec describes how a resolved credential is attached to an outbound
// request. The exact meaning of Name depends on Type: it is the header name
// for InjectHeader and the placeholder token for InjectPlaceholder.
type InjectSpec struct {
	Type     InjectType
	Name     string
	Template string

	// Surfaces lists the request components placeholder mode rewrites. An
	// empty slice means header-only, preserving pre-surfaces behavior.
	// Ignored by InjectHeader.
	Surfaces []Surface

	// MaxBodyBytes is the per-rule override for the request-body buffering
	// cap. Zero means inherit the proxy-wide default. Consulted by Hook,
	// not by Inject.
	MaxBodyBytes int

	// OAuth1 holds the four secret references for OAuth 1.0a signing. It is
	// populated only when Type is InjectOAuth1.
	OAuth1 OAuth1Refs
}

// OAuth1Refs names the four secret references an OAuth 1.0a signing rule
// resolves: the application's consumer key/secret and the user's token/token
// secret. Each is a secret_ref URI resolved through the normal credstore path.
type OAuth1Refs struct {
	ConsumerKeyRef    string
	ConsumerSecretRef string
	TokenRef          string
	TokenSecretRef    string
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

// hasCRLF reports whether s contains a carriage return or line feed.
func hasCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// Inject applies the rule's injection spec to req using credential as the
// secret value. Header mode sets a single header. Placeholder mode rewrites
// the token across every declared surface (header, body, path, query) with
// per-surface encoding, and returns ErrNoPlaceholder when the token is absent
// from every eligible surface so the proxy fails closed instead of forwarding
// the request unauthenticated. An unknown InjectType is treated as a
// configuration error: Inject returns an error so the proxy can fail closed.
//
// In placeholder mode body substitution reads req.Body; callers that declare
// the body surface (Hook) must materialize req.Body into an in-memory,
// size-bounded reader before calling Inject.
func (r Rule) Inject(req *http.Request, credential string) error {
	// Guard before mutating anything: a template with no placeholder would
	// render to a constant and forward the request without the credential.
	// Reject it so both inject modes fail closed rather than fail open.
	if !hasCredentialPlaceholder(r.Injection.Template) {
		return ErrNoCredentialPlaceholder
	}
	switch r.Injection.Type {
	case InjectHeader:
		value := Render(r.Injection.Template, credential)
		if hasCRLF(value) {
			return ErrHeaderInjection
		}
		req.Header.Set(r.Injection.Name, value)
		return nil
	case InjectPlaceholder:
		return r.injectPlaceholder(req, credential)
	default:
		return fmt.Errorf("broker: unsupported inject type %d", r.Injection.Type)
	}
}

// injectPlaceholder rewrites the placeholder token across the rule's declared
// surfaces. A surface is "eligible" when it can carry a substitution (a
// compressed or multipart body is ineligible and forwarded untouched). The
// match is aggregate: any one eligible surface carrying the token is success.
// Zero substitutions across one or more eligible surfaces is a fail-closed
// ErrNoPlaceholder. Zero eligible surfaces (e.g. a body-only rule on a
// compressed body) forwards the request untouched.
func (r Rule) injectPlaceholder(req *http.Request, credential string) error {
	// An empty token matches the empty substring everywhere, smearing the
	// credential across every value. Fail closed rather than leak it.
	if r.Injection.Name == "" {
		return ErrEmptyPlaceholderToken
	}
	value := Render(r.Injection.Template, credential)
	return r.substituteToken(req, r.Injection.Name, value)
}

// InjectRoute renders credential into the rule's shared template and
// substitutes it for the route's token across the declared surfaces. It is the
// placeholder-routing counterpart of Inject: the matched route supplies the
// token (and selected the secret), while the rule supplies the template and
// surfaces. Fails closed when the template carries no {{ CREDENTIAL }}
// placeholder or the token is empty.
func (r Rule) InjectRoute(req *http.Request, route Route, credential string) error {
	if !hasCredentialPlaceholder(r.Injection.Template) {
		return ErrNoCredentialPlaceholder
	}
	if route.Token == "" {
		return ErrEmptyPlaceholderToken
	}
	value := Render(r.Injection.Template, credential)
	return r.substituteToken(req, route.Token, value)
}

// substituteToken replaces token with the already-rendered value across the
// rule's declared surfaces, per-surface encoded. The match is aggregate: any
// one eligible surface carrying the token is success; zero substitutions across
// one or more eligible surfaces is a fail-closed ErrNoPlaceholder.
func (r Rule) substituteToken(req *http.Request, token, value string) error {
	surfaces := r.Injection.Surfaces
	if len(surfaces) == 0 {
		surfaces = []Surface{SurfaceHeader}
	}

	subs, eligible := 0, 0
	for _, s := range surfaces {
		switch s {
		case SurfaceHeader:
			if hasCRLF(value) {
				return ErrHeaderInjection
			}
			eligible++
			subs += substituteHeaders(req, token, value)
		case SurfacePath:
			eligible++
			n, err := substitutePath(req, token, value)
			if err != nil {
				return err
			}
			subs += n
		case SurfaceQuery:
			eligible++
			subs += substituteQuery(req, token, value)
		case SurfaceBody:
			n, skipped, err := substituteBody(req, token, value)
			if err != nil {
				return err
			}
			if !skipped {
				eligible++
				subs += n
			}
		default:
			return fmt.Errorf("broker: unsupported surface %d", s)
		}
	}

	if eligible > 0 && subs == 0 {
		return ErrNoPlaceholder
	}
	return nil
}

// substituteHeaders replaces token with value in every header value, returning
// the number of values rewritten.
func substituteHeaders(req *http.Request, token, value string) int {
	subs := 0
	for k, vs := range req.Header {
		for i, v := range vs {
			if strings.Contains(v, token) {
				vs[i] = strings.ReplaceAll(v, token, value)
				subs++
			}
		}
		req.Header[k] = vs
	}
	return subs
}

// substitutePath replaces token in the wire-encoded path with a path-escaped
// value, setting both URL.Path (decoded) and URL.RawPath (encoded) so
// url.String() emits the substituted form without double-encoding.
func substitutePath(req *http.Request, token, value string) (int, error) {
	esc := req.URL.EscapedPath()
	if !strings.Contains(esc, token) {
		return 0, nil
	}
	newEsc := strings.ReplaceAll(esc, token, url.PathEscape(value))
	decoded, err := url.PathUnescape(newEsc)
	if err != nil {
		return 0, fmt.Errorf("broker: rewrite path: %w", err)
	}
	req.URL.Path = decoded
	req.URL.RawPath = newEsc
	return strings.Count(esc, token), nil
}

// substituteQuery replaces token in the raw query string with a
// query-escaped value.
func substituteQuery(req *http.Request, token, value string) int {
	rq := req.URL.RawQuery
	if !strings.Contains(rq, token) {
		return 0
	}
	req.URL.RawQuery = strings.ReplaceAll(rq, token, url.QueryEscape(value))
	return strings.Count(rq, token)
}

// bodySkippable reports whether substituteBody will forward req's body
// untouched instead of rewriting it: a compressed body (Content-Encoding other
// than identity) or a multipart body cannot be safely text-spliced. The hook
// consults this so it skips buffering (and size-capping) a body it would only
// stream through unchanged — otherwise an oversized skippable body would 413
// instead of forwarding, contradicting the documented passthrough.
func bodySkippable(req *http.Request) bool {
	if ce := req.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return true
	}
	return strings.HasPrefix(parseMediaType(req.Header.Get("Content-Type")), "multipart/")
}

// substituteBody replaces token in the request body with a value encoded for
// the body's Content-Type, then rewrites req.Body and Content-Length. It
// reports skipped=true (and leaves the body untouched) for bodies it must not
// rewrite: a compressed body (Content-Encoding set) or a multipart body, which
// cannot be safely text-spliced. Callers must have materialized req.Body into a
// bounded in-memory reader first.
func substituteBody(req *http.Request, token, value string) (subs int, skipped bool, err error) {
	if req.Body == nil || req.Body == http.NoBody {
		return 0, false, nil
	}
	if bodySkippable(req) {
		return 0, true, nil
	}
	mediaType := parseMediaType(req.Header.Get("Content-Type"))

	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return 0, false, fmt.Errorf("broker: read body: %w", err)
	}
	body := string(raw)
	if !strings.Contains(body, token) {
		// Restore the buffer so the unmodified body still forwards.
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		return 0, false, nil
	}

	newBody := strings.ReplaceAll(body, token, encodeBodyValue(mediaType, value))
	req.Body = io.NopCloser(strings.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
	return strings.Count(body, token), false, nil
}

// parseMediaType returns the lowercased media type from a Content-Type header,
// dropping parameters. A malformed header yields "" (treated as raw).
func parseMediaType(ct string) string {
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return mt
}

// encodeBodyValue encodes value for splicing into a body of the given media
// type: form values are query-escaped, JSON values are JSON-string-escaped,
// everything else is spliced raw.
func encodeBodyValue(mediaType, value string) string {
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return url.QueryEscape(value)
	case "application/json":
		// json.Marshal of a string yields a quoted, fully-escaped JSON
		// string; strip the surrounding quotes to get the escaped contents.
		b, err := json.Marshal(value)
		if err != nil || len(b) < 2 {
			return value
		}
		return string(b[1 : len(b)-1])
	default:
		return value
	}
}
