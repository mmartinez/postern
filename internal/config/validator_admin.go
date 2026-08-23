package config

import (
	"fmt"
	"net"
	"strconv"
)

// checkAdminListen validates proxy.admin_listen. Unset (empty) is fine and
// leaves behavior unchanged; when set, the address must parse as host:port
// with the host a loopback IP (127.0.0.0/8 or ::1). The admin endpoint
// exposes internal state (ruleset version, credstore health), so binding it
// to a routable interface would hand that state to anything that can reach
// the interface — rejected with a line-numbered error so `postern config
// validate` points at the offending address before the server can start.
//
// Hostnames are deliberately not accepted, including "localhost": name
// resolution could map to a non-loopback address depending on resolver
// configuration, and an explicit IP keeps the security property verifiable
// by inspection.
func (v *validator) checkAdminListen(addr string) {
	if addr == "" {
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		v.add("proxy.admin_listen", fmt.Sprintf("invalid admin_listen address %q: %v (want host:port)", addr, err), SeverityError)
		return
	}
	// SplitHostPort accepts non-numeric and out-of-range port strings (the
	// failure would otherwise surface at boot); reject them here so `postern
	// config validate` remains the single gate before the server starts.
	if p, perr := strconv.ParseUint(port, 10, 16); perr != nil || p == 0 {
		v.add("proxy.admin_listen", fmt.Sprintf("admin_listen %q must include a numeric port in 1-65535", addr), SeverityError)
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		v.add("proxy.admin_listen",
			fmt.Sprintf("admin_listen %q must bind a loopback address (127.0.0.0/8 or ::1); the admin endpoint exposes internal state", addr),
			SeverityError)
	}
}
