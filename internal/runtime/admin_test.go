package runtime_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/runtime"
)

// okReport is a healthy snapshot used by the happy-path tests.
func okReport() runtime.HealthReport {
	return runtime.HealthReport{
		Status:         "ok",
		RulesetVersion: 7,
		CredStores: []runtime.CredStoreHealth{
			{Name: "team", OK: true, Detail: "ok"},
		},
	}
}

// startWithAdmin constructs and runs a Runtime with an OS-assigned admin
// port, returning the runtime plus the admin base URL once the listener is
// up. The runtime is stopped via t.Cleanup so every test leaves no
// listeners behind.
func startWithAdmin(t *testing.T, report runtime.HealthReport) (*runtime.Runtime, string) {
	t.Helper()
	rt, err := runtime.New(runtime.Options{
		CA:           fixtureCA(t),
		Addr:         "127.0.0.1:0",
		AdminListen:  "127.0.0.1:0",
		HealthStatus: func() runtime.HealthReport { return report },
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	t.Cleanup(func() {
		select {
		case err := <-done:
			require.NoError(t, err, "graceful shutdown should not surface an error")
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return within 10s of cleanup cancellation")
		}
	})

	require.NoError(t, waitForListening(rt, 2*time.Second))
	adminAddr := rt.AdminAddr()
	require.NotEmpty(t, adminAddr, "admin listener address must be published once up")
	return rt, "http://" + adminAddr
}

func adminGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	client := &http.Client{
		Timeout: 2 * time.Second,
		// The admin endpoint is plain HTTP on loopback; never send proxy
		// env-derived traffic there if the test host sets HTTP_PROXY.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{}},
	}
	resp, err := client.Get(url) //nolint:noctx // bounded by the client Timeout above
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

// TestRuntime_AdminHealthzOK covers the acceptance criterion: GET /healthz
// returns 200 with JSON carrying status, the ruleset version, and per-
// credstore health entries.
func TestRuntime_AdminHealthzOK(t *testing.T) {
	t.Parallel()
	_, base := startWithAdmin(t, okReport())

	code, body := adminGet(t, base+"/healthz")
	require.Equal(t, http.StatusOK, code, "healthy report must yield 200; body: %s", body)

	var got struct {
		Status         string `json:"status"`
		RulesetVersion uint64 `json:"ruleset_version"`
		CredStores     []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Stale  bool   `json:"stale"`
			Detail string `json:"detail"`
		} `json:"credstores"`
	}
	require.NoError(t, json.Unmarshal(body, &got), "body must be the documented JSON shape: %s", body)
	require.Equal(t, "ok", got.Status)
	require.Equal(t, uint64(7), got.RulesetVersion)
	require.Len(t, got.CredStores, 1)
	require.Equal(t, "team", got.CredStores[0].Name)
	require.True(t, got.CredStores[0].OK)
}

// TestRuntime_AdminHealthzDegraded503 confirms the degraded semantics: any
// non-"ok" status maps to 503 with the same JSON shape (never a bare body).
func TestRuntime_AdminHealthzDegraded503(t *testing.T) {
	t.Parallel()
	report := runtime.HealthReport{
		Status:         "degraded",
		RulesetVersion: 3,
		CredStores: []runtime.CredStoreHealth{
			{Name: "corp", OK: false, Detail: "validation failed"},
		},
	}
	_, base := startWithAdmin(t, report)

	code, body := adminGet(t, base+"/healthz")
	require.Equal(t, http.StatusServiceUnavailable, code, "degraded report must yield 503; body: %s", body)
	require.Contains(t, string(body), `"status":"degraded"`)
	require.Contains(t, string(body), `"name":"corp"`)
}

// TestRuntime_AdminOtherPaths404 confirms the admin listener serves the
// probe surface only: every non-/healthz path is a 404, so the endpoint
// cannot become an accidental information leak.
func TestRuntime_AdminOtherPaths404(t *testing.T) {
	t.Parallel()
	_, base := startWithAdmin(t, okReport())

	for _, path := range []string{"/", "/debug", "/healthz/extra"} {
		code, _ := adminGet(t, base+path)
		require.Equal(t, http.StatusNotFound, code, "path %s must 404", path)
	}
}

// TestRuntime_AdminRejectsNonGET keeps the probe surface strict: methods
// other than GET are refused with 405.
func TestRuntime_AdminRejectsNonGET(t *testing.T) {
	t.Parallel()
	_, base := startWithAdmin(t, okReport())

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(base+"/healthz", "application/json", nil) //nolint:noctx // bounded timeout
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// TestRuntime_AdminUnsetStartsNoListener proves the unset-field zero-change
// guarantee at the runtime layer: no AdminListen means no second listener
// and no published admin address.
func TestRuntime_AdminUnsetStartsNoListener(t *testing.T) {
	t.Parallel()
	rt, err := runtime.New(runtime.Options{
		CA:     fixtureCA(t),
		Addr:   "127.0.0.1:0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()

	require.NoError(t, waitForListening(rt, 2*time.Second))
	require.Empty(t, rt.AdminAddr(), "no admin listener must exist when AdminListen is unset")
}

// TestRuntime_AdminBindFailureFailsRun mirrors the proxy bind-failure
// contract for the admin listener: a bound admin port makes Run fail rather
// than silently running without a health surface.
func TestRuntime_AdminBindFailureFailsRun(t *testing.T) {
	t.Parallel()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	rt, err := runtime.New(runtime.Options{
		CA:           fixtureCA(t),
		Addr:         "127.0.0.1:0",
		AdminListen:  occupied.Addr().String(),
		HealthStatus: okReport,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	err = rt.Run(t.Context())
	require.Error(t, err, "binding an already-bound admin address should fail")
}

// TestRuntime_AdminShutsDownWithinBudget confirms the admin server drains
// with the proxy under the same shutdown budget instead of outliving it.
func TestRuntime_AdminShutsDownWithinBudget(t *testing.T) {
	t.Parallel()
	rt, err := runtime.New(runtime.Options{
		CA:           fixtureCA(t),
		Addr:         "127.0.0.1:0",
		AdminListen:  "127.0.0.1:0",
		HealthStatus: okReport,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "shutdown must be graceful with both listeners up")
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of context cancellation")
	}
}

// TestNew_AdminListenRequiresHealthStatus fails fast on a miswired Options:
// an admin listener without a status source would serve a probe that lies.
func TestNew_AdminListenRequiresHealthStatus(t *testing.T) {
	t.Parallel()
	_, err := runtime.New(runtime.Options{
		CA:          fixtureCA(t),
		Addr:        "127.0.0.1:0",
		AdminListen: "127.0.0.1:1702",
	})
	require.Error(t, err, "AdminListen without HealthStatus must be rejected at construction")
}
