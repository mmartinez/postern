// Package broker implements the request-time credential broker: matching
// outbound HTTPS requests against host rules, resolving the matched rule's
// secret reference, and injecting the credential before the proxy forwards
// the request upstream.
package broker

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// Rule is the runtime representation of a single host-broker entry. It is
// derived from config.Rule by callers (typically the runtime wiring).
type Rule struct {
	// Host is the host pattern: either a literal hostname ("api.example.com")
	// or a single-* glob in the form "*.example.com". Validated upstream by
	// config.isValidHostPattern, so Match assumes the pattern is well-formed.
	Host string

	// SecretRef is the vendor-agnostic secret reference URI the resolver
	// looks up when this rule matches an outbound request (e.g.,
	// "op://Agents/Anthropic/api_key"). Validated upstream against the
	// secret-reference URI grammar. Empty for a placeholder-routing rule (see
	// Routes), where each route carries its own ref.
	SecretRef string

	// Injection describes how the resolved credential is attached to the
	// outbound request. See InjectSpec and Rule.Inject.
	Injection InjectSpec

	// Injections, when non-empty, makes this a multi-header rule: every entry
	// is a header injection applied with the same credential, resolved once
	// from SecretRef. It replaces Injection, which is then the zero value.
	Injections []InjectSpec

	// Routes, when non-empty, makes this a placeholder-routing rule: the token
	// an agent presents on a declared surface selects (and is replaced by) the
	// route's secret. See SelectRoute and InjectRoute.
	Routes []Route

	// Paths scopes injection to request URL paths: each entry is a prefix
	// matched via strings.HasPrefix against the request path, and injection
	// happens only when at least one entry matches. A request outside every
	// declared prefix fails closed before the resolver is called. Empty
	// means the rule brokers every path on the host.
	Paths []string

	// Methods scopes injection to HTTP methods, compared case-insensitively
	// against the declared entries. A request whose method matches no entry
	// fails closed before the resolver is called. Empty means the rule
	// brokers every method.
	Methods []string
}

// Route is one entry of a placeholder-routing rule: presenting Token selects
// SecretRef and replaces Token in place with the resolved value. Name is the
// log-safe label for the agent; the token value is never logged.
type Route struct {
	Name      string
	Token     string
	SecretRef string
}

// SelectRoute scans the rule's declared surfaces for route tokens and returns
// the single route whose token is present in the request. ok is false when no
// route token is found or when more than one distinct route token is present
// (ambiguous); the caller fails closed in both cases rather than guess. For a
// body-surface rule the caller must have materialized req.Body into a bounded
// in-memory reader first (Hook does).
func (r Rule) SelectRoute(req *http.Request) (Route, bool) {
	surfaces := r.Injection.Surfaces
	if len(surfaces) == 0 {
		surfaces = []Surface{SurfaceHeader}
	}

	// Read the body at most once for the whole selection: scanning it per route
	// would copy the (already buffered) body N times. body is nil when no
	// surface scans it or the body is one we never rewrite (nil, compressed,
	// multipart); req.Body is restored exactly once here for later injection.
	var body []byte
	if scansBody(surfaces) {
		body = readBodyForScan(req)
	}

	var matched Route
	found := 0
	for _, rt := range r.Routes {
		if rt.Token == "" {
			continue
		}
		if tokenPresent(req, surfaces, rt.Token, body) {
			matched = rt
			found++
		}
	}
	if found != 1 {
		return Route{}, false
	}
	return matched, true
}

// scansBody reports whether the surface list includes the body surface.
func scansBody(surfaces []Surface) bool {
	for _, s := range surfaces {
		if s == SurfaceBody {
			return true
		}
	}
	return false
}

// tokenPresent reports whether token appears on any of the declared surfaces.
// body is the once-read request body (nil if the body surface is not scanned or
// the body is not text-rewritable); the header/path/query scans are cheap and
// read directly from req.
func tokenPresent(req *http.Request, surfaces []Surface, token string, body []byte) bool {
	for _, s := range surfaces {
		switch s {
		case SurfaceHeader:
			for _, vs := range req.Header {
				for _, v := range vs {
					if strings.Contains(v, token) {
						return true
					}
				}
			}
		case SurfacePath:
			if strings.Contains(req.URL.EscapedPath(), token) {
				return true
			}
		case SurfaceQuery:
			if strings.Contains(req.URL.RawQuery, token) {
				return true
			}
		case SurfaceBody:
			if body != nil && bytes.Contains(body, []byte(token)) {
				return true
			}
		}
	}
	return false
}

// readBodyForScan reads the request body once for token scanning and restores
// it so a later injection can read it again. It returns nil for a body that
// must not be scanned (nil, NoBody, compressed, or multipart), matching
// substituteBody's passthrough.
func readBodyForScan(req *http.Request) []byte {
	if req.Body == nil || req.Body == http.NoBody || bodySkippable(req) {
		return nil
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	return raw
}

// usesBodySurface reports whether the rule rewrites the request body. The hook
// uses this to decide whether to buffer (and size-bound) the body before
// injecting; rules that don't touch the body stream their bodies untouched.
func (r Rule) usesBodySurface() bool {
	if r.Injection.Type != InjectPlaceholder {
		return false
	}
	for _, s := range r.Injection.Surfaces {
		if s == SurfaceBody {
			return true
		}
	}
	return false
}

// canonicalHost normalizes a hostname for comparison by stripping exactly one
// trailing dot — the RFC 3986 §3.2.2 fully-qualified spelling of the same
// name, which curl and Go's net/http put on the wire verbatim. More than one
// trailing dot is left alone: that is a malformed name, not an FQDN, and must
// not silently match.
//
// This helper is deliberately duplicated in internal/proxy and internal/ca:
// the packages are decoupled by design (the broker must not import the proxy
// package, and neither may import ca's callers), and a one-line string op is
// not worth a new coupling point.
func canonicalHost(host string) string {
	return strings.TrimSuffix(host, ".")
}

// Match reports whether the rule's host pattern matches host. Comparison is
// case-insensitive (DNS hostnames are case-insensitive per RFC 4343) and
// purely canonical-to-canonical: r.Host was canonicalized once at rule
// construction (FromConfigRules), and callers must canonicalize host exactly
// once at their entry boundary — never inside Match. Stacked transformations
// would strip a malformed multi-dot authority one dot per layer until it
// matched a brokered host. The glob form follows TLS-wildcard semantics: "*"
// matches exactly one DNS label and never crosses a dot, so "*.example.com"
// matches "api.example.com" but neither "example.com" nor "a.b.example.com".
//
// host should be the bare, canonicalized hostname without a port. Callers
// that hold a host:port value (e.g. CONNECT targets) must strip the port and
// apply canonicalHost first.
func (r Rule) Match(host string) bool {
	pattern := strings.ToLower(r.Host)
	h := strings.ToLower(host)

	if !strings.HasPrefix(pattern, "*.") {
		return pattern == h
	}

	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(h, suffix) {
		return false
	}
	label := h[:len(h)-len(suffix)]
	if label == "" {
		return false
	}
	return !strings.Contains(label, ".")
}
