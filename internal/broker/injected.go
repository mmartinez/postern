package broker

import (
	"context"
	"net/http"
)

// injectedKey is the private context key under which the broker records the
// credential values it placed on an outbound request. It is an unexported
// struct type rather than a string so no other package can collide with or
// forge the key by accident.
type injectedKey struct{}

// WithInjectedCredentials returns a copy of ctx carrying creds as the
// credential values the broker placed on this request. Empty values are
// dropped and duplicates collapsed, so the recorded set is exactly the values
// that can appear on the wire.
//
// This is the hand-off channel between the two halves of the broker: the
// request hook knows which credential it injected, while the response filter
// (internal/proxy) runs later, in a separate goproxy hook, and needs the same
// values to stop an upstream that reflects them back from handing them to the
// agent. A request-context value is the right carrier because it is already
// request-scoped, already survives the round trip to the transport (net/http
// copies the request it sent onto resp.Request), and needs no package-level map
// or lock.
//
// The values are credentials. Neither they nor anything derived from them —
// not a hash, not a fingerprint — may ever be logged.
func WithInjectedCredentials(ctx context.Context, creds ...string) context.Context {
	set := make([]string, 0, len(creds))
	for _, c := range creds {
		if c == "" || slicesContains(set, c) {
			continue
		}
		set = append(set, c)
	}
	if len(set) == 0 {
		return ctx
	}
	return context.WithValue(ctx, injectedKey{}, set)
}

// InjectedCredentials returns the credential values the broker recorded on ctx
// and whether any were recorded. ok is false for every request the broker did
// not inject a credential on, which is the caller's signal to leave the
// response path completely untouched.
//
// A recorded set never contains an empty value: the hook fails closed rather
// than inject an empty credential, so callers never have to treat "" as a
// match.
func InjectedCredentials(ctx context.Context) ([]string, bool) {
	if ctx == nil {
		return nil, false
	}
	creds, ok := ctx.Value(injectedKey{}).([]string)
	if !ok || len(creds) == 0 {
		return nil, false
	}
	return creds, true
}

// markInjectedCredentials records creds on req's own context in place.
//
// Hook's signature hands it a *http.Request it cannot replace, and the
// pointer is what goproxy forwards upstream, so the context has to be
// swapped through the pointed-to struct. This is safe because it happens
// before the transport has seen the request, and net/http copies the
// request onto resp.Request, which is where the proxy's response filter
// reads the values from.
func markInjectedCredentials(req *http.Request, creds ...string) {
	ctx := WithInjectedCredentials(req.Context(), creds...)
	if ctx == req.Context() {
		return
	}
	*req = *req.WithContext(ctx)
}

// slicesContains reports whether set already holds v. The recorded sets are
// one to four elements, so a linear scan beats pulling in a map for a value
// that is compared once per injection.
func slicesContains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
