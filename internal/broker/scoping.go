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
// An empty slice means that knob is unrestricted — the historical behavior
// for rules declaring neither field. A scoped-out result sends the caller
// (Hook) to failClosed before the resolver is ever consulted, mirroring the
// fail-closed posture of unknown/ambiguous route selection.
func (r Rule) scopeAllows(req *http.Request) bool {
	if len(r.Paths) > 0 {
		pathAllowed := false
		for _, prefix := range r.Paths {
			if strings.HasPrefix(req.URL.Path, prefix) {
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
