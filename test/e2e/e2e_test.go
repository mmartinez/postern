//go:build e2e

package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// failClosedBody is the exact body every postern fail-closed 502 carries.
const failClosedBody = "postern: bad gateway\n"

// TestHTTPSBrokeredInjection covers the full brokered flow over real TLS:
// the client CONNECTs through postern to an https upstream, postern
// terminates TLS with a leaf minted from its CA, resolves the rule's OAuth2
// credential at the stub IdP, injects the Authorization header, and forwards
// upstream. The token is fetched exactly once (boot ping + first use) and
// reused for subsequent requests.
func TestHTTPSBrokeredInjection(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	idp := startIdP(t, e)
	up := startUpstream(t, e)
	proc := startPostern(t, e, renderConfig(idp.URL, "127.0.0.1", "passthrough"))
	client := proxiedClient(t, proc.proxyURL, e.caPEM)

	target := fmt.Sprintf("https://127.0.0.1:%s/", up.port)
	status, body := get(t, client, target)
	require.Equal(t, 200, status, "body: %q", body)
	require.Equal(t, "upstream-ok\n", body)

	// The boot-time credential ping consumes mint #1; the runtime resolver's
	// first use consumes mint #2 and is then reused from x/oauth2's cache.
	require.Equal(t, int64(2), idp.Fetches())
	require.Equal(t, 1, up.Requests())
	require.Equal(t, "Bearer "+idp.Token(2), up.AuthHeader(0))

	// Second request: same injected token, still no new token exchange.
	status, body = get(t, client, target)
	require.Equal(t, 200, status)
	require.Equal(t, "upstream-ok\n", body)
	require.Equal(t, int64(2), idp.Fetches(), "token must be reused, not re-minted")
	require.Equal(t, 2, up.Requests())
	require.Equal(t, "Bearer "+idp.Token(2), up.AuthHeader(1))

	// The response arrived over a TLS connection whose leaf chains to
	// postern's planted CA (the client trusts nothing else).
	resp, err := client.Get(target)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.NotNil(t, resp.TLS)
	require.NotEmpty(t, resp.TLS.PeerCertificates)
	require.Equal(t, caCommonName, resp.TLS.PeerCertificates[0].Issuer.CommonName)
}

// TestPlainHTTPInjectionFailsClosed documents why the plain-HTTP brokered
// injection scenario is not implementable against this binary without a
// production change: the broker refuses to inject on any non-https hop by
// design (internal/broker/hook.go), so a matched plain-http request fails
// closed with the uniform 502 before the resolver is called or the upstream
// is contacted.
func TestPlainHTTPInjectionFailsClosed(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	idp := startIdP(t, e)
	up := startUpstream(t, e)
	proc := startPostern(t, e, renderConfig(idp.URL, "127.0.0.1", "passthrough"))
	client := proxiedClient(t, proc.proxyURL, e.caPEM)

	target := fmt.Sprintf("http://127.0.0.1:%s/", up.port)
	status, body := get(t, client, target)
	require.Equal(t, 502, status)
	require.Equal(t, failClosedBody, body)

	require.Equal(t, 0, up.Requests(), "upstream must never be contacted")
	require.Equal(t, int64(1), idp.Fetches(), "only the boot ping may hit the IdP; the request path must not resolve")
}

// TestFailClosedOnResolverFailure proves the fail-closed guarantee when the
// credential source is unreachable: the client gets the uniform 502 with the
// exact body and the stub upstream records zero requests.
//
// Deviation from the original scenario shape: postern pings the token
// endpoint once at boot (fail-closed-at-boot provider validation), so a
// config pointing at an already-closed port never boots. Instead the server
// boots against a live stub IdP and the IdP listener is closed before the
// request, which leaves the token URL pointing at a closed port at request
// time.
func TestFailClosedOnResolverFailure(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	idp := startIdP(t, e)
	up := startUpstream(t, e)
	proc := startPostern(t, e, renderConfig(idp.URL, "127.0.0.1", "passthrough"))
	client := proxiedClient(t, proc.proxyURL, e.caPEM)

	idp.srv.Close() // token URL now points at a closed port

	status, body := get(t, client, fmt.Sprintf("https://127.0.0.1:%s/", up.port))
	require.Equal(t, 502, status)
	require.Equal(t, failClosedBody, body)
	require.Equal(t, 0, up.Requests(), "unauthenticated request must never reach the upstream")
}

// TestHotReloadSwapsRuleHost rewrites the watched config in place, swapping
// the rule's host, and asserts the new host brokers while the old host stops
// doing so — without restarting the process.
func TestHotReloadSwapsRuleHost(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	idp := startIdP(t, e)
	up := startUpstream(t, e)
	proc := startPostern(t, e, renderConfig(idp.URL, "localhost", "block"))
	client := proxiedClient(t, proc.proxyURL, e.caPEM)

	oldURL := fmt.Sprintf("https://localhost:%s/", up.port)
	newURL := fmt.Sprintf("https://127.0.0.1:%s/", up.port)

	// Baseline: the old host brokers.
	status, body := get(t, client, oldURL)
	require.Equal(t, 200, status, "body: %q", body)
	require.Equal(t, "upstream-ok\n", body)
	require.Equal(t, "Bearer "+idp.Token(2), up.AuthHeader(0))

	// Only requests after the reload are held to the no-old-host invariant.
	baselineReqs := up.Requests()

	// Swap the rule's host; credstores stay identical so the reload applies.
	proc.rewriteConfig(t, renderConfig(idp.URL, "127.0.0.1", "block"))

	// Poll within the watcher's poll interval + debounce window until the
	// new host brokers. During the transition the old ruleset still serves,
	// so a 502 here just means "not swapped yet".
	var swapped bool
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, body := get(t, client, newURL)
		if status == 200 && body == "upstream-ok\n" {
			swapped = true
			break
		}
		// 10ms poll cadence against a 10s cap; the watcher's stat-poll
		// fallback runs on a 5s interval, so no fixed delay coordinates us
		// with the server — each attempt observes current ruleset state.
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, swapped, "new host never brokered after reload\nlogs:\n%s", proc.logs.String())

	newReqs := up.Requests()
	require.GreaterOrEqual(t, newReqs, 2)
	require.Equal(t, "Bearer "+idp.Token(2), up.AuthHeader(newReqs-1))

	// The old host no longer brokers: on_no_match block rejects its CONNECT
	// with the uniform 502 and it never reaches the upstream again.
	status, body = get(t, client, oldURL)
	require.Equal(t, 502, status)
	require.Equal(t, failClosedBody, body)

	for _, h := range up.Hosts()[baselineReqs:] {
		require.NotEqual(t, "localhost:"+up.port, h, "old host must not be forwarded after reload")
	}
}
