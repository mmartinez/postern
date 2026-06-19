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
// drain in-flight requests within 10s — anything still in-flight after the
// budget gets a 504 from the http.Server.
const shutdownBudget = 10 * time.Second

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
}

// Runtime is the constructed-but-not-yet-running postern server. Build it
// with New and start it with Run.
type Runtime struct {
	opts   Options
	proxy  *proxy.Proxy
	srv    *http.Server
	minter *ca.Minter

	addr atomic.Value // string, populated once the listener is up
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

	return &Runtime{
		opts:   opts,
		proxy:  p,
		minter: minter,
		srv: &http.Server{
			Addr:              opts.Addr,
			Handler:           p.Handler(),
			ReadHeaderTimeout: 30 * time.Second,
		},
	}, nil
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
// errors. On cancellation it gracefully shuts down within shutdownBudget.
// The returned error is nil for clean shutdowns and non-nil for bind
// failures or serve-level errors.
func (r *Runtime) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", r.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", r.opts.Addr, err)
	}
	r.addr.Store(listener.Addr().String())
	r.opts.Logger.Info("proxy listening", slog.String("addr", listener.Addr().String()))

	serveErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := r.srv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			serveErr <- nil
			return
		}
		serveErr <- err
	}()

	select {
	case <-ctx.Done():
		r.opts.Logger.Info("shutdown requested", slog.Duration("budget", shutdownBudget))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		if err := r.srv.Shutdown(shutdownCtx); err != nil {
			r.opts.Logger.Warn("shutdown error", slog.Any("err", err))
			wg.Wait()
			return err
		}
		wg.Wait()
		return nil
	case err := <-serveErr:
		wg.Wait()
		return err
	}
}

// discardWriter is the fallback io.Writer for the Options.Logger default.
// Using a dedicated zero-size type instead of io.Discard keeps the runtime
// import surface narrow.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
