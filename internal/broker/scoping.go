package broker

import (
	"net/http"
	"strings"
)

// scopeAllows reports whether req falls within the rule's declared request
// scoping: every declared knob must allow the request for injection to
// proceed. Each knob is any-of within itself (any prefix in Paths; any
// method in Methods) and the knobs combine conjunctively, so a rule
// declaring both only brokers requests satisfying both.
//
// Path matching runs against the ESCAPED wire form (req.URL.EscapedPath):
// the bytes actually forwarded upstream. Matching the decoded form instead
// would let an encoded path the upstream never decodes the same way appear
// in scope while the request lands elsewhere, handing the credential to an
// endpoint the rule never declared. With the raw form, what matched is
// byte-identical to what is forwarded; anything else fails closed. Prefixes
// are plain string prefixes from the root, so a declared "/v1/messages"
// also matches "/v1/messages-beta" — operators wanting a segment boundary
// declare it explicitly ("/v1/messages/").
//
// An empty slice means that knob is unrestricted — the historical behavior
// for rules declaring neither field. A scoped-out result sends the caller
// (Hook) to failClosed before the resolver is ever consulted, mirroring the
// fail-closed posture of unknown/ambiguous route selection.
func (r Rule) scopeAllows(req *http.Request) bool {
	if len(r.Paths) > 0 {
		pathAllowed := false
		wirePath := req.URL.EscapedPath()
		for _, prefix := range r.Paths {
			if strings.HasPrefix(wirePath, prefix) {
				pathAllowed = true
				break
			}
		}
		if !pathAllowed {
			return false
		}
	}
	if len(r.Methods) > 0 {
		methodAllowed := false
		for _, m := range r.Methods {
			// Method comparison is case-insensitive: RFC 9110 methods are
			// case-sensitive on the wire, but configs conventionally declare
			// uppercase tokens while nothing forbids "post" in YAML, and a
			// case mismatch silently 502ing every request would be a config
			// trap rather than a security property.
			if strings.EqualFold(req.Method, m) {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			return false
		}
	}
	return true
}
