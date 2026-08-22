package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/runtime"
)

// probeTimeout bounds a single async credstore revalidation triggered by a
// /healthz scrape. Providers are remote services that may rate-limit, which
// is exactly why revalidation is asynchronous and bounded: a slow or
// rate-limiting vendor must not stall the probe response or pile up
// unbounded concurrent pings under aggressive scrapers.
const probeTimeout = 5 * time.Second

// healthStatusDetail values reported per credstore. Raw provider errors are
// deliberately NOT propagated to the wire: vendor error strings can echo
// request material, and the health contract is names + status only. The
// boolean carries the signal; the operator debugs the failure through logs.
const (
	detailOK   = "ok"
	detailFail = "validation failed"
)

// revalidateCooldown throttles scrape-triggered revalidations per
// credstore: once a probe completes, further scrapes reuse its result for
// this long before pinging the vendor again. Without it, a fast vendor
// would leave every scrape marked stale (a fresh probe in flight each
// time) and an aggressive monitor could still hammer a rate-limited one.
const revalidateCooldown = 30 * time.Second

// HealthTracker is the status source behind runtime.Options.HealthStatus:
// it aggregates the boot-time credstore validation outcomes (buildOneResolver's
// fail-closed-at-boot ping) and the reloader's ruleset version into a
// runtime.HealthReport for GET /healthz.
//
// Freshness semantics: providers may rate-limit, so a scrape NEVER probes
// synchronously. Each scrape reports the last-known state immediately and,
// for every credstore neither already mid-probe nor revalidated within the
// cooldown window, triggers one async revalidation whose result lands in
// time for a later scrape. Entries mid-revalidation
// carry Stale=true so consumers can tell fresh results from pending ones.
// A killed or expired credstore token therefore becomes observable within
// two scrapes: the first triggers the failing ping, the next reports it.
//
// Credential hygiene: reports contain credstore names and status flags
// only — never token values, secret references, or resolved material.
type HealthTracker struct {
	brokered bool
	version  func() uint64

	// cooldown throttles scrape-triggered revalidation per credstore;
	// defaults to revalidateCooldown.
	cooldown time.Duration

	mu     sync.Mutex
	stores map[string]*storeHealth
	order  []string
}

// storeHealth is one credstore's tracked state. probe is the closure that
// re-runs the same validation call boot used (capturing provider, token,
// and settings); stale marks a probe in flight.
type storeHealth struct {
	ok          bool
	detail      string
	probe       func(ctx context.Context) error
	stale       bool
	lastAttempt time.Time
}

// NewHealthTracker constructs a tracker. brokered reports whether a ruleset
// is active (false = brokerless passthrough, which is degraded by
// definition: nothing is loaded and no credential is validated). version
// sources the ruleset version from the reloader's counter; nil reports 0.
func NewHealthTracker(brokered bool, version func() uint64) *HealthTracker {
	return &HealthTracker{
		brokered: brokered,
		version:  version,
		stores:   make(map[string]*storeHealth),
		cooldown: revalidateCooldown,
	}
}

// RecordBootValidation records that the named credstore passed its
// fail-closed-at-boot ping. Boot failures never reach here: buildOneResolver
// errors out and the server refuses to start, so a tracked store is always
// boot-healthy.
func (t *HealthTracker) RecordBootValidation(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stores[name]
	if s == nil {
		s = &storeHealth{}
		t.stores[name] = s
		t.order = append(t.order, name)
	}
	s.ok = true
	s.detail = detailOK
}

// RegisterProbe installs the async revalidation closure for a credstore.
// The closure re-runs the boot-time validation call (Provider.Validate, or
// ValidateWithSecondary for refresh-grant credstores) against the same
// resolved token.
func (t *HealthTracker) RegisterProbe(name string, probe func(ctx context.Context) error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stores[name]
	if s == nil {
		s = &storeHealth{}
		t.stores[name] = s
		t.order = append(t.order, name)
	}
	s.probe = probe
}

// Report builds the current snapshot and triggers async revalidation for
// any credstore with a registered probe that isn't already mid-probe. It is
// safe for concurrent scrapes: at most one probe per credstore is in flight
// at a time, so aggressive monitoring cannot stampede a rate-limited vendor.
func (t *HealthTracker) Report() runtime.HealthReport {
	t.mu.Lock()
	stores := make([]runtime.CredStoreHealth, 0, len(t.order))
	degraded := !t.brokered
	for _, name := range t.order {
		s := t.stores[name]
		if !s.ok {
			degraded = true
		}
		// Claim the probe slot before snapshotting so the scrape that
		// triggers a revalidation reports its own entry as stale — consumers
		// see last-known state plus the pending-refresh marker atomically.
		if s.probe != nil && !s.stale && time.Since(s.lastAttempt) >= t.cooldown {
			s.stale = true
			go t.revalidate(name, s.probe)
		}
		stores = append(stores, runtime.CredStoreHealth{
			Name:   name,
			OK:     s.ok,
			Stale:  s.stale,
			Detail: s.detail,
		})
	}
	var version uint64
	if t.version != nil {
		version = t.version()
	}
	t.mu.Unlock()

	status := runtime.StatusOK
	if degraded {
		status = runtime.StatusDegraded
	}
	return runtime.HealthReport{
		Status:         status,
		RulesetVersion: version,
		CredStores:     stores,
	}
}

// revalidate runs one probe to completion and records the outcome. Runs on
// its own goroutine; the scrape that triggered it has already returned the
// last-known state.
func (t *HealthTracker) revalidate(name string, probe func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	ok := probe(ctx) == nil

	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.stores[name]; s != nil {
		s.ok = ok
		s.stale = false
		s.lastAttempt = time.Now()
		if ok {
			s.detail = detailOK
		} else {
			s.detail = detailFail
		}
	}
}

// newHealthcheckCmd builds `postern server healthcheck`, the probe the
// container healthcheck invokes. The production image is distroless (no
// shell, no curl/wget), so the postern binary itself is the only thing in
// the container that can perform an HTTP GET; this subcommand exists to be
// that probe. It exits 0 only when /healthz answers 200.
func newHealthcheckCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Probe the admin /healthz endpoint (used by container healthchecks)",
		Long: "GET http://<addr>/healthz and exit 0 only on a 200 response.\n" +
			"The admin listener is loopback-only, so this runs inside the\n" +
			"server's container/network namespace — which is exactly what the\n" +
			"distroless image's healthcheck needs, since it ships no shell or curl.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := "http://" + addr + "/healthz"
			client := &http.Client{Timeout: probeTimeout}
			//nolint:gosec,noctx // addr is an operator-supplied loopback address by design (validator enforces loopback); request is bounded by the client timeout
			resp, err := client.Get(url)
			if err != nil {
				return fmt.Errorf("healthcheck %s: %w", url, err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("healthcheck %s: status %d", url, resp.StatusCode)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "healthy\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:1702", "Admin listener address to probe")
	return cmd
}

// healthStatus adapts the bundle's tracker for runtime.Options.HealthStatus,
// returning nil when no tracker exists so the runtime refuses to start an
// admin listener without a status source.
func (b brokerBundle) healthStatus() func() runtime.HealthReport {
	if b.health == nil {
		return nil
	}
	return b.health.Report
}
