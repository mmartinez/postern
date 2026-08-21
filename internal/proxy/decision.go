package proxy

// connectMode is the interception decision for a single CONNECT: terminate TLS
// and broker the request (modeMITM), relay the encrypted bytes untouched
// (modeTunnel), or refuse the tunnel at connect time (modeReject).
type connectMode int

const (
	modeMITM connectMode = iota
	modeTunnel
	modeReject
)

// decideConnect chooses how to handle a CONNECT to host (a host:port target).
// shouldIntercept reports whether the bare host is brokered; a nil func means
// intercept every host, preserving the pre-selective-MITM behavior for callers
// that do not opt in. A non-brokered host is tunneled unless blockNonBrokered
// is set, in which case its CONNECT is rejected.
//
// The host is canonicalized (single trailing dot stripped, per RFC 3986
// §3.2.2) before matching: clients put the dotted FQDN on the wire verbatim,
// and a dotted spelling must decide identically to its bare form.
// Canonicalization is applied exactly once, here: shouldIntercept receives
// the already-canonical host and must not strip again, or a malformed
// multi-dot authority loses one dot per layer until it matches a brokered
// host and undergoes MITM instead of falling through to policy.
func decideConnect(host string, shouldIntercept func(string) bool, blockNonBrokered bool) connectMode {
	if shouldIntercept == nil || shouldIntercept(canonicalHost(stripPort(host))) {
		return modeMITM
	}
	if blockNonBrokered {
		return modeReject
	}
	return modeTunnel
}
