// Package runtime owns the long-lived postern server process: it binds
// the listener, wires the proxy onto a *http.Server, watches for context
// cancellation, and drains in-flight requests within a shutdown budget.
// The CLI layer (internal/cli/server.go) hands runtime a fully-resolved
// Options struct so this package never reaches into config or env on its
// own; that separation keeps Run cleanly unit-testable.
package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/proxy"
)

// shutdownBudget is the upper bound on graceful drain time: SIGTERM must
// finish shutting down within 10s. net/http's Shutdown ignores hijacked
// connections entirely, and goproxy hijacks every CONNECT — so no 504 can
// ever be surfaced to a live tunnel. Instead the runtime tracks hijacked
// conns (see conntrack.go), waits out the remaining budget for them to
// finish naturally, and force-closes any still alive when it expires.
const shutdownBudget = 10 * time.Second

// idleTimeout reaps silent keep-alive connections on the inbound server.
// With IdleTimeout unset net/http never closes an idle conn (ReadTimeout is
// deliberately unset so streaming responses are never cut), so agents that
// hold connections open would accumulate server goroutines forever. Not
// configurable via YAML; a knob can be added later if ever needed.
const idleTimeout = 2 * time.Minute

// Options carries the resolved configuration runtime needs. CLI populates
// it from cobra flags and config files; tests construct it inline.
type Options struct {
	// CA is the local certificate authority used to MITM TLS. Required.
	CA *ca.CA

	// Addr is the listen address in host:port form. Use ":0" or
	// "127.0.0.1:0" to let the OS assign a port (mostly for tests).
	Addr string

	// Logger receives runtime + proxy events. Defaults to a discard
	// logger when nil so callers can omit it during unit tests.
	Logger *slog.Logger

	// UpstreamTLS configures the proxy's outbound TLS transport. nil
	// means use system trust — the production default.
	UpstreamTLS *tls.Config

	// PreUpstreamHandler is the broker insertion point. nil keeps
	// the proxy in passthrough mode.
	PreUpstreamHandler func(req *http.Request) *http.Response

	// ShouldIntercept reports whether a host is brokered and must be MITM'd;
	// hosts it declines are tunneled (or blocked). nil intercepts every host,
	// matching the always-MITM behavior used when no broker is active.
	ShouldIntercept func(host string) bool

	// BlockNonBrokered rejects the CONNECT for non-brokered hosts instead of
	// tunneling them — the connect-time form of on_no_match: block.
	BlockNonBrokered bool

	// TestIdleTimeout overrides the inbound server's 2m IdleTimeout for
	// tests that cannot wait out the production default. Zero keeps the
	// default. Test-only: production wiring never sets it and it is not
	// exposed through YAML configuration.
	TestIdleTimeout time.Duration

	// TestStalledConnTimeout overrides the inbound reaper's 30s
	// zero-progress threshold for tests that cannot wait out the production
	// default. Zero keeps the default. Test-only: production wiring never
	// sets it and it is deliberately not exposed through YAML configuration.
	TestStalledConnTimeout time.Duration

	// TestTunnelIdleTimeout overrides the inbound reaper's 10m
	// sustained-inactivity threshold, like TestStalledConnTimeout.
	// Zero keeps the default. Test-only.
	TestTunnelIdleTimeout time.Duration

	// TestReapInterval overrides the inbound reaper's 30s scan interval,
	// like TestStalledConnTimeout. Zero keeps the default. Test-only.
	TestReapInterval time.Duration

	// TestShutdownBudget overrides the 10s graceful shutdown budget, like
	// TestStalledConnTimeout. Zero keeps the default. Test-only.
	TestShutdownBudget time.Duration
}

// Runtime is the constructed-but-not-yet-running postern server. Build it
// with New and start it with Run.
type Runtime struct {
	opts   Options
	proxy  *proxy.Proxy
	srv    *http.Server
	minter *ca.Minter

	addr atomic.Value // string, populated once the listener is up

	conns *connRegistry // live accepted conns; drain barrier at shutdown

	stalledConnTimeout time.Duration
	tunnelIdleTimeout  time.Duration
	reapInterval       time.Duration
	shutdownBudget     time.Duration
}

// New constructs a Runtime from opts. It performs validation but does not
// bind the listener — that happens in Run so callers can react to bind
// failures by returning a non-zero exit from the CLI.
func New(opts Options) (*Runtime, error) {
	if opts.CA == nil {
		return nil, errors.New("ca is required")
	}
	if opts.Addr == "" {
		return nil, errors.New("addr is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}

	minter, err := ca.NewMinter(opts.CA, 1024, time.Now)
	if err != nil {
		return nil, fmt.Errorf("init minter: %w", err)
	}

	p, err := proxy.New(proxy.Config{
		CA:                 opts.CA,
		Minter:             minter,
		Logger:             opts.Logger,
		UpstreamTLS:        opts.UpstreamTLS,
		PreUpstreamHandler: opts.PreUpstreamHandler,
		ShouldIntercept:    opts.ShouldIntercept,
		BlockNonBrokered:   opts.BlockNonBrokered,
	})
	if err != nil {
		return nil, fmt.Errorf("init proxy: %w", err)
	}

	idle := idleTimeout
	if opts.TestIdleTimeout > 0 {
		idle = opts.TestIdleTimeout
	}

	rt := &Runtime{
		opts:   opts,
		proxy:  p,
		minter: minter,
		conns:  newConnRegistry(),
		srv: &http.Server{
			Addr:              opts.Addr,
			Handler:           p.Handler(),
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       idle,
		},

		stalledConnTimeout: stalledConnTimeout,
		tunnelIdleTimeout:  tunnelIdleTimeout,
		reapInterval:       reapInterval,
		shutdownBudget:     shutdownBudget,
	}
	if opts.TestStalledConnTimeout > 0 {
		rt.stalledConnTimeout = opts.TestStalledConnTimeout
	}
	if opts.TestTunnelIdleTimeout > 0 {
		rt.tunnelIdleTimeout = opts.TestTunnelIdleTimeout
	}
	if opts.TestReapInterval > 0 {
		rt.reapInterval = opts.TestReapInterval
	}
	if opts.TestShutdownBudget > 0 {
		rt.shutdownBudget = opts.TestShutdownBudget
	}
	return rt, nil
}

// Addr returns the listener's actual bind address, or "" if Run hasn't yet
// finished setting up. Tests poll this to know when to start sending
// requests against an OS-assigned port.
func (r *Runtime) Addr() string {
	if v := r.addr.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Run binds the listener and serves until ctx is cancelled or the server
// errors. On cancellation it gracefully shuts down within shutdownBudget:
// http.Server.Shutdown first for non-hijacked traffic, then a bounded wait
// on live tunnels, then force-close of whatever is left. The returned error
// is nil for clean shutdowns and non-nil for bind failures or serve-level
// errors.
func (r *Runtime) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", r.opts.Addr, err)
	}
	r.addr.Store(listener.Addr().String())
	r.opts.Logger.Info("proxy listening", slog.String("addr", listener.Addr().String()))

	reapCtx, stopReaper := context.WithCancel(context.Background())
	defer stopReaper()
	go r.reapLoop(reapCtx)

	serveErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := r.srv.Serve(&trackingListener{Listener: listener, reg: r.conns})
		if errors.Is(err, http.ErrServerClosed) {
			serveErr <- nil
			return
		}
		serveErr <- err
	}()

	select {
	case <-ctx.Done():
		r.opts.Logger.Info("shutdown requested", slog.Duration("budget", r.shutdownBudget))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), r.shutdownBudget)
		defer cancel()
		var shutdownErr error
		if err := r.srv.Shutdown(shutdownCtx); err != nil {
			r.opts.Logger.Warn("shutdown error", slog.Any("err", err))
			shutdownErr = err
		}
		drained, forced := r.drainConns(shutdownCtx)
		r.opts.Logger.Info("shutdown drain complete",
			slog.Int("drained", drained),
			slog.Int("force_closed", forced))
		wg.Wait()
		return shutdownErr
	case err := <-serveErr:
		wg.Wait()
		return err
	}
}

// reapLoop evicts stalled and idle conns until ctx is cancelled. Closing a
// tracked conn unblocks whichever goproxy goroutine (MITM read loop, tunnel
// relay) is parked inside it, so eviction tears down the whole tunnel.
func (r *Runtime) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(r.reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reapOnce()
		}
	}
}

func (r *Runtime) reapOnce() {
	now := time.Now()
	var stale []*trackedConn
	r.conns.each(func(c *trackedConn) {
		idle, zeroProgress := c.idleFor(now)
		limit := r.tunnelIdleTimeout
		if zeroProgress {
			limit = r.stalledConnTimeout
		}
		if idle > limit {
			stale = append(stale, c)
		}
	})
	for _, c := range stale {
		r.opts.Logger.Debug("reaped idle connection",
			slog.String("remote", c.RemoteAddr().String()))
		_ = c.Close()
	}
}

// drainConns waits for tracked conns to finish naturally within ctx's
// remaining budget, then force-closes the rest. It returns how many drained
// versus how many were force-closed.
func (r *Runtime) drainConns(ctx context.Context) (drained, forced int) {
	total := r.conns.count()
	if total == 0 {
		return 0, 0
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			forced = r.conns.closeAll()
			return total - forced, forced
		case <-ticker.C:
			if r.conns.count() == 0 {
				return total, 0
			}
		}
	}
}

// discardWriter is the fallback io.Writer for the Options.Logger default.
// Using a dedicated zero-size type instead of io.Discard keeps the runtime
// import surface narrow.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
