package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/runtime"
	"github.com/mmartinez/postern/internal/token"
)

// flakyProvider is a plainProvider whose validation outcome can be flipped
// after boot — the "killed credstore token" scenario the health endpoint
// must make observable.
type flakyProvider struct {
	plainProvider

	mu  sync.Mutex
	err error
}

func (p *flakyProvider) Validate(_ context.Context, _ string, _ map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *flakyProvider) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = errors.New("validation failed")
}

// TestHealthTracker_BrokerlessIsDegraded covers the acceptance criterion
// that a brokerless passthrough deployment reports degraded: no ruleset is
// loaded, so the version is 0, there are no credstores, and the status is
// degraded (the admin handler maps that to 503).
func TestHealthTracker_BrokerlessIsDegraded(t *testing.T) {
	t.Parallel()

	tracker := NewHealthTracker(false, nil)
	report := tracker.Report()

	require.Equal(t, "degraded", report.Status)
	require.Equal(t, uint64(0), report.RulesetVersion)
	require.Empty(t, report.CredStores)
}

// TestHealthTracker_KilledTokenObservable covers the acceptance criterion
// that the response to a killed credstore token is observable in /healthz:
// after boot validated OK, flipping the provider's validation outcome must
// surface as ok=false on a subsequent scrape (async revalidation triggered
// by the scrape itself) and degrade the overall status.
func TestHealthTracker_KilledTokenObservable(t *testing.T) {
	t.Parallel()

	reg := credstore.NewRegistry()
	prov := &flakyProvider{plainProvider: plainProvider{scheme: "flaky"}}
	reg.Register(prov)

	stores := []config.CredStore{{
		Name:     "corp",
		Provider: prov.Name(),
		Token:    keychainToken("primary"),
	}}

	health := NewHealthTracker(true, func() uint64 { return 4 })
	_, err := buildCredStoreResolvers(context.Background(), reg, stores, seededStore(t), discardLogger(), health)
	require.NoError(t, err)

	first := health.Report()
	require.Equal(t, "ok", first.Status)
	require.Len(t, first.CredStores, 1)
	require.True(t, first.CredStores[0].OK, "boot ping passed; health must start ok")

	// The service-account token is revoked out from under the running proxy.
	prov.kill()

	require.Eventually(t, func() bool {
		report := health.Report()
		return len(report.CredStores) == 1 && !report.CredStores[0].OK
	}, 2*time.Second, 10*time.Millisecond,
		"a scrape must trigger revalidation and surface the killed token")

	report := health.Report()
	require.Equal(t, "degraded", report.Status)
	require.False(t, report.CredStores[0].OK)
}

// TestHealthTracker_StaleFlagDuringRevalidation confirms the documented
// semantics: a scrape reports the last-known state immediately while an
// async revalidation is in flight, marking the entry stale so consumers can
// tell fresh results from pending ones.
func TestHealthTracker_StaleFlagDuringRevalidation(t *testing.T) {
	t.Parallel()

	health := NewHealthTracker(true, func() uint64 { return 1 })
	health.RecordBootValidation("team")
	release := make(chan struct{})
	health.RegisterProbe("team", func(_ context.Context) error {
		<-release
		return nil
	})

	inFlight := health.Report()
	require.Len(t, inFlight.CredStores, 1)
	require.True(t, inFlight.CredStores[0].Stale, "pending revalidation must mark the entry stale")
	require.True(t, inFlight.CredStores[0].OK, "last-known state must be reported while revalidating")

	close(release)
	require.Eventually(t, func() bool {
		return !health.Report().CredStores[0].Stale
	}, 2*time.Second, 10*time.Millisecond, "completed revalidation must clear the stale flag")
}

// bootFixtureYAML is a credential-bearing config: the token value below is
// the secret the hygiene assertion greps the wire response against, and the
// rule carries a secret_ref the endpoint must also never echo.
const bootFixtureYAML = `
credstores:
  - name: team-vault
    provider: plain-op3
    token:
      source: keychain
      keychain_account: primary
proxy:
  listen: 127.0.0.1:1701
  admin_listen: 127.0.0.1:1702
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op3://TeamVault/API/prod-key
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

const (
	fixtureTokenValue = "primary-secret-value-do-not-leak"
	fixtureSecretRef  = "op3://TeamVault/API/prod-key"
)

// buildBootFixture registers a plain provider under the name the fixture
// YAML references and builds the broker bundle for it.
func buildBootFixture(t *testing.T) brokerBundle {
	t.Helper()

	reg := credstore.NewRegistry()
	prov := &plainProvider{scheme: "op3"}
	reg.Register(prov)

	path := writeConfig(t, bootFixtureYAML)
	bundle, err := buildBrokerHook(context.Background(), reg, path, true, seededStore(t), discardLogger()) //nolint:bodyclose // hook is a closure; broker owns the synthetic body
	require.NoError(t, err)
	return bundle
}

// TestBuildBrokerHook_WiresAdminHealth verifies the CLI-side status source:
// the bundle surfaces admin_listen, a seeded version counter, and a tracker
// whose first report is healthy with the credstore listed by name.
func TestBuildBrokerHook_WiresAdminHealth(t *testing.T) {
	t.Parallel()

	bundle := buildBootFixture(t)

	require.Equal(t, "127.0.0.1:1702", bundle.adminListen)
	require.NotNil(t, bundle.version)
	require.NotNil(t, bundle.health)

	report := bundle.health.Report()
	require.Equal(t, "ok", report.Status)
	require.Equal(t, uint64(1), report.RulesetVersion, "boot load seeds version 1")
	require.Len(t, report.CredStores, 1)
	require.Equal(t, "team-vault", report.CredStores[0].Name)
	require.True(t, report.CredStores[0].OK)
}

// TestBuildBrokerHook_PassthroughHealthIsDegraded proves the brokerless
// branch still produces a usable status source: passthrough mode reports
// degraded with version 0 even though admin_listen is configured.
func TestBuildBrokerHook_PassthroughHealthIsDegraded(t *testing.T) {
	t.Parallel()

	reg := credstore.NewRegistry()
	path := writeConfig(t, `
proxy:
  listen: 127.0.0.1:1701
  admin_listen: 127.0.0.1:1702
  cache_ttl: 5m
  on_no_match: passthrough
`)

	bundle, err := buildBrokerHook(context.Background(), reg, path, true, token.NewMemoryStore(), discardLogger())
	require.NoError(t, err)
	require.Nil(t, bundle.hook, "no rules means passthrough")

	report := bundle.health.Report()
	require.Equal(t, "degraded", report.Status)
	require.Equal(t, uint64(0), report.RulesetVersion)
}

// TestHealthzWireResponse_NeverContainsCredentialMaterial covers the
// acceptance criterion end to end: the /healthz response body produced from
// a credential-bearing fixture contains credstore names and statuses only —
// never the token value, the secret_ref, or any resolved material.
func TestHealthzWireResponse_NeverContainsCredentialMaterial(t *testing.T) {
	t.Parallel()

	bundle := buildBootFixture(t)

	root, err := ca.Generate(time.Now())
	require.NoError(t, err)
	rt, err := runtime.New(runtime.Options{
		CA:           root,
		Addr:         "127.0.0.1:0",
		AdminListen:  bundle.adminListen,
		HealthStatus: bundle.healthStatus(),
		Logger:       discardLogger(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for rt.AdminAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.NotEmpty(t, rt.AdminAddr(), "admin listener must come up")

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + rt.AdminAddr() + "/healthz") //nolint:noctx // bounded timeout; loopback test URL
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotContains(t, string(body), fixtureTokenValue, "resolved token value must never appear on the wire")
	require.NotContains(t, string(body), fixtureSecretRef, "secret refs must never appear on the wire")
	require.Contains(t, string(body), `"name":"team-vault"`, "credstore names are the allowed identifier")
	require.Contains(t, string(body), `"status":"ok"`)
	require.Contains(t, string(body), `"ruleset_version":1`)
}

// TestHealthcheckCmd probes the subcommand the container healthcheck uses:
// exit success on 200, failure on 503, failure when the listener is down.
func TestHealthcheckCmd(t *testing.T) {
	t.Parallel()

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ok.Close)

	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(sick.Close)

	down, err := os.MkdirTemp("", "postern-hc-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(down) })

	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "healthy endpoint succeeds", addr: hostOf(ok.URL)},
		{name: "degraded endpoint fails", addr: hostOf(sick.URL), wantErr: true},
		{name: "unreachable endpoint fails", addr: filepath.Join(down, "none"), wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := newHealthcheckCmd()
			cmd.SetArgs([]string{"--addr", tc.addr})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if tc.wantErr {
				require.Error(t, cmd.Execute())
				return
			}
			require.NoError(t, cmd.Execute())
		})
	}
}

// hostOf strips the scheme from an httptest URL, leaving host:port for the
// --addr flag.
func hostOf(url string) string {
	if len(url) > 7 && url[:7] == "http://" {
		return url[7:]
	}
	return url
}

// TestBundleVersionIncrementsAfterReload wires the whole status chain at the
// CLI level: the bundle's version counter must advance when the reloader
// applies a swap, which is what makes /healthz's ruleset_version increase
// per hot reload.
func TestBundleVersionIncrementsAfterReload(t *testing.T) {
	t.Parallel()

	bundle := buildBootFixture(t)
	engine := bundle.engine

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 2)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, discardLogger(), bundle.baseline, bundle.version)
	}()
	t.Cleanup(func() {
		cancel()
		close(events)
		wg.Wait()
	})

	require.Equal(t, uint64(1), bundle.version.Load())

	events <- config.Event{
		New: &config.Config{
			Rules: []config.Rule{{
				Host:      "api.second.test",
				SecretRef: fixtureSecretRef,
				Inject: config.Inject{
					Type:     config.InjectTypeHeader,
					Name:     "x-api-key",
					Template: "{{ CREDENTIAL }}",
				},
			}},
		},
	}
	require.Eventually(t, func() bool { return bundle.version.Load() == 2 },
		2*time.Second, 10*time.Millisecond, "applied reload must increment the reported version")
	require.Equal(t, uint64(2), bundle.health.Report().RulesetVersion,
		"/healthz must surface the incremented version")
}
