// Package proxy is the HTTPS forward-proxy front end. It builds an
// elazarl/goproxy server pre-wired for MITM against a postern-issued CA
// and exposes the resulting http.Handler: the trust chain (CONNECT +
// per-host leaf via ca.Minter), the request-rewriting handler with
// streaming and panic recovery, and the broker resolve+inject step that
// plugs into the same handler chain.
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"

	"github.com/mmartinez/postern/internal/ca"
)

// Config bundles the dependencies New needs to construct a Proxy. Plumbing
// these as an explicit struct (rather than positional args) keeps cmd/postern
// wiring stable as later slices add fields.
type Config struct {
	// CA is the local certificate authority used to sign per-host leaf
	// certificates during MITM. Required.
	CA *ca.CA

	// Minter issues TLS leaves on demand and caches them by SNI. Required.
	Minter *ca.Minter

	// Logger receives request/response trace events. A nil logger is
	// replaced with a no-op slog handler so callers can omit it during
	// tests without a panic.
	Logger *slog.Logger

	// UpstreamTLS configures the proxy's outbound TLS transport. A nil
	// value uses the Go default (system trust). Tests pass a custom
	// RootCAs that trusts httptest.NewTLSServer.
	UpstreamTLS *tls.Config

	// PreUpstreamHandler, when non-nil, runs after MITM decrypt and before
	// the proxy forwards the request upstream. Returning a non-nil
	// *http.Response short-circuits the proxy: the response is returned
	// to the client and the upstream is not contacted. A panic in this
	// hook is caught and converted to 502 to preserve the fail-closed
	// invariant.
	//
	// The broker plugs into this slot to perform match → resolve → inject.
	PreUpstreamHandler func(req *http.Request) *http.Response
}

// Proxy is the postern HTTPS proxy. Construct one with New; expose its
// http.Handler to an http.Server (or httptest server in tests).
type Proxy struct {
	cfg    Config
	server *goproxy.ProxyHttpServer
}

// New validates cfg and returns a ready-to-serve Proxy. Required fields
// (CA, Minter) error fast so misconfiguration surfaces at startup rather
// than the first CONNECT.
func New(cfg Config) (*Proxy, error) {
	if cfg.CA == nil {
		return nil, errors.New("ca is required")
	}
	if cfg.Minter == nil {
		return nil, errors.New("minter is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false
	// goproxy's default logger writes to stderr; mute it — we log via slog.
	gp.Logger = mutedLogger{}

	if cfg.UpstreamTLS != nil {
		// goproxy reuses its Tr for upstream dials, so cloning preserves
		// any other defaults (proxy chain, MaxIdleConns) the package set.
		gp.Tr.TLSClientConfig = cfg.UpstreamTLS.Clone()
	} else {
		// Production path: dial upstreams with system trust. Set the verifying
		// config explicitly rather than inheriting goproxy's transport default
		// — this proxy injects a real credential before forwarding, so upstream
		// certificate verification is a load-bearing security invariant and
		// must not silently depend on a library default that a future version
		// could flip. InsecureSkipVerify stays false (the zero value).
		gp.Tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	tlsConfig := mitmTLSConfig(cfg.Minter)
	gp.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// Returning host (not "") preserves the destination so goproxy's
		// downstream dial uses the correct target — the second return is
		// the upstream connect address, not a label.
		return &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: tlsConfig,
		}, host
	}))

	installHandlers(gp, cfg.Logger)
	installPreUpstream(gp, cfg.Logger, cfg.PreUpstreamHandler)

	return &Proxy{cfg: cfg, server: gp}, nil
}

// Handler returns the proxy's net/http handler. Mount it on any http.Server
// (postern uses a 127.0.0.1-bound server in production; tests use httptest).
func (p *Proxy) Handler() http.Handler { return p.server }

// mitmTLSConfig builds the per-CONNECT TLS config factory that goproxy hands
// the client. Each invocation mints (or cache-hits) a leaf for the requested
// host via the postern Minter — goproxy's own TLSConfigFromCA is bypassed so
// we keep a single source of truth for leaf shape.
func mitmTLSConfig(minter *ca.Minter) func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
		sni := stripPort(host)
		leaf, err := minter.Mint(sni)
		if err != nil {
			return nil, fmt.Errorf("mint leaf for %s: %w", sni, err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*leaf},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
}

// stripPort drops the :port suffix from a CONNECT target, leaving just the
// host. CONNECT targets are always host:port per RFC 7230, so a missing
// colon means the upstream is misbehaving — return the input unchanged and
// let TLS surface the real error.
func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// mutedLogger silences goproxy's internal stderr chatter. Its log lines
// duplicate what we surface via slog in the handler chain and would otherwise
// double-print every request during tests.
type mutedLogger struct{}

func (mutedLogger) Printf(string, ...any) {}
