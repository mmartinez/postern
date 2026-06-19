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
func decideConnect(host string, shouldIntercept func(string) bool, blockNonBrokered bool) connectMode {
	if shouldIntercept == nil || shouldIntercept(stripPort(host)) {
		return modeMITM
	}
	if blockNonBrokered {
		return modeReject
	}
	return modeTunnel
}
