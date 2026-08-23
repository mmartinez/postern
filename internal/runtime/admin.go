package runtime

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// Health status values the admin endpoint reports. "ok" means the proxy is
// serving with a loaded ruleset and every credstore's last validation
// succeeded; anything else is degraded and rendered as a 503 so orchestrator
// probes fail closed.
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
)

// HealthReport is one snapshot of postern's service health, as rendered by
// GET /healthz on the admin listener. The CLI builds it from boot-time and
// refreshed credstore validation outcomes plus the reloader's ruleset
// version; this package only renders it.
//
// Credential hygiene contract: reports carry credstore NAMES and status
// flags only. Token values, secret references, and resolved credential
// material must never be placed in any field — the response crosses trust
// boundaries (container probes, monitoring scrapes) that must not see them.
type HealthReport struct {
	Status         string            `json:"status"`
	RulesetVersion uint64            `json:"ruleset_version"`
	CredStores     []CredStoreHealth `json:"credstores"`
}

// CredStoreHealth is one credstore's last-known validation state. Stale is
// set while an async revalidation triggered by a scrape is still in flight:
// providers may rate-limit, so /healthz reports the last-known result
// immediately and refreshes out-of-band rather than probing synchronously.
type CredStoreHealth struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Stale  bool   `json:"stale"`
	Detail string `json:"detail,omitempty"`
}

// Probe-endpoint timeouts. A health probe should never hold a connection or
// a handler long: reads are bounded tighter than the proxy server (which
// needs 30s for CONNECT setup), and writes are bounded because the JSON
// body is tiny and local.
const (
	adminReadHeaderTimeout = 5 * time.Second
	adminReadTimeout       = 5 * time.Second
	adminWriteTimeout      = 10 * time.Second
	adminIdleTimeout       = 30 * time.Second
)

// newAdminServer constructs the loopback HTTP server exposing the health
// surface. It serves exactly one route (GET /healthz); everything else 404s
// via ServeMux, keeping the listener from becoming an accidental debug
// surface. There are no request bodies to log by construction, and the
// handler logs nothing per-request, so no credential-adjacent material can
// reach the log stream through this path.
func newAdminServer(addr string, status func() HealthReport) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           newAdminHandler(status),
		ReadHeaderTimeout: adminReadHeaderTimeout,
		ReadTimeout:       adminReadTimeout,
		WriteTimeout:      adminWriteTimeout,
		IdleTimeout:       adminIdleTimeout,
	}
}

// newAdminHandler builds the mux behind the admin listener.
func newAdminHandler(status func() HealthReport) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz(status))
	return mux
}

// handleHealthz renders a HealthReport as JSON. The mapping is deliberate
// and simple: StatusOK → 200, anything else → 503, so adding future states
// fails closed for orchestrators instead of inventing a new success code.
func handleHealthz(status func() HealthReport) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report := status()
		code := http.StatusOK
		if report.Status != StatusOK {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		enc := json.NewEncoder(w)
		// Reports are built from names and booleans only (see HealthReport);
		// if a caller ever violates that, an encoding failure is better than
		// half-written JSON on the wire.
		if err := enc.Encode(report); err != nil && slog.Default().Enabled(r.Context(), slog.LevelError) {
			slog.Error("admin healthz encode failed", slog.Any("err", err))
		}
	}
}
