package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	// bitwarden and onepassword are imported for their init() side effect: each
	// registers its provider (scheme "bw" / "op") in the process-wide credstore
	// registry. pickProvider falls back to "op" for the legacy default
	// credstore. The cli package depends on those schemes existing, so the
	// anchors belong here rather than only in the binary's main package.
	_ "github.com/mmartinez/postern/internal/credstore/bitwarden"
	_ "github.com/mmartinez/postern/internal/credstore/oauth2"
	_ "github.com/mmartinez/postern/internal/credstore/onepassword"
	"github.com/mmartinez/postern/internal/logging"
	"github.com/mmartinez/postern/internal/runtime"
	"github.com/mmartinez/postern/internal/token"
)

// daemonEnvFlag marks a re-exec'd child so it knows not to re-daemonize.
// The flag is intentionally specific to postern so unrelated re-exec
// patterns from the user's shell don't accidentally trip the check.
const daemonEnvFlag = "POSTERN_DAEMONIZED"

// NewServerCmd builds `postern server`. caDir is where the persisted CA
// lives; reg is the credstore provider registry the broker resolves against;
// store is the OS keychain wrapper used by the token-resolution chain when
// source=auto or source=keychain.
func NewServerCmd(caDir string, reg *credstore.Registry, store token.Store) *cobra.Command {
	var (
		addr       string
		daemon     bool
		configPath string
		logFormat  string
		logLevel   string
		noColor    bool
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the postern HTTPS forward proxy",
		Long: "Run the proxy listener. The config file is optional: without\n" +
			"--config (and no default file at ~/.postern/config.yaml) the\n" +
			"proxy runs in passthrough mode — every request is forwarded\n" +
			"untouched. With a config that declares rules, postern brokers\n" +
			"matching requests through the credential vendor.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Construct the logger up front so bad --log-format / --log-level
			// values fail in the foreground process. If we deferred this past
			// daemonize, the parent would print "started in background" and
			// only the now-headless child would discover the typo.
			logger, err := logging.New(logging.Options{
				Format:  logFormat,
				Level:   logLevel,
				NoColor: noColor,
				Output:  cmd.ErrOrStderr(),
			})
			if err != nil {
				return err
			}

			if daemon && os.Getenv(daemonEnvFlag) != "1" {
				return daemonize()
			}

			authority, err := ca.Load(caDir)
			if err != nil {
				return fmt.Errorf("load ca from %s: %w (run `postern ca install` first)", caDir, err)
			}

			cfgPath := configPath
			cfgRequired := cfgPath != ""
			if cfgPath == "" {
				cfgPath = config.DefaultPath()
			}

			bundle, err := buildBrokerHook(cmd.Context(), reg, cfgPath, cfgRequired, store, logger) //nolint:bodyclose // hook is a closure; broker owns the synthetic body
			if err != nil {
				return err
			}

			addr = resolveListenAddr(cmd.Flags().Changed("addr"), addr, bundle.listen)

			rt, err := runtime.New(runtime.Options{
				CA:                 authority,
				Addr:               addr,
				Logger:             logger,
				PreUpstreamHandler: bundle.hook,
				ShouldIntercept:    bundle.shouldIntercept,
				BlockNonBrokered:   bundle.blockNonBrokered,
			})
			if err != nil {
				return fmt.Errorf("init runtime: %w", err)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if cmd.Context() == nil {
				ctx, stop = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
				defer stop()
			}

			// Hot-reload: wire the watcher only when a broker is actually
			// active. A passthrough-only server has nothing to swap, and
			// watching a non-existent default-path file would just log noise.
			var reloadWG sync.WaitGroup
			if bundle.engine != nil && bundle.cfgPath != "" {
				watcher := config.NewWatcherWithLogger(bundle.cfgPath, logger)
				events, werr := watcher.Watch(ctx)
				if werr != nil {
					logger.Warn("hot reload disabled",
						slog.String("path", bundle.cfgPath),
						slog.Any("err", werr),
					)
				} else {
					reloadWG.Add(1)
					go func() {
						defer reloadWG.Done()
						broker.RunReloader(ctx, bundle.engine, events, logger, bundle.baseline)
					}()
					defer func() {
						_ = watcher.Close()
						reloadWG.Wait()
					}()
					logger.Info("hot reload enabled", slog.String("path", bundle.cfgPath))
				}
			}

			return rt.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", config.DefaultListenAddr, "Listener bind address")
	cmd.Flags().BoolVarP(&daemon, "daemon", "d", false, "Detach and run in the background")
	cmd.Flags().StringVar(&configPath, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "Log format: text|json")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level: quiet|info|debug")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI colour (NO_COLOR env also honored)")
	return cmd
}

// brokerBundle is what buildBrokerHook returns when a broker is wired up.
// hook is the PreUpstreamHandler the runtime plumbs into goproxy; engine
// is the live ruleset the hot-reload watcher swaps into; cfgPath is the
// file that should be watched (empty if no config was found). baseline
// captures proxy + token at boot so the reloader can warn when an edit
// touches a field that needs a restart.
type brokerBundle struct {
	hook     func(*http.Request) *http.Response
	engine   *broker.Engine
	cfgPath  string
	listen   string
	baseline *broker.Baseline

	// shouldIntercept reports whether a host is brokered, so the proxy MITMs
	// only those and tunnels the rest. nil (the no-broker bundle) leaves the
	// proxy intercepting every host, unchanged from before selective MITM.
	shouldIntercept func(string) bool

	// blockNonBrokered mirrors on_no_match: block — reject non-brokered
	// CONNECTs instead of tunneling them.
	blockNonBrokered bool
}

// resolveListenAddr applies the listen-address precedence for `postern
// server`: an explicit --addr flag wins; otherwise the config's
// proxy.listen; otherwise config.DefaultListenAddr. This mirrors bootstrap's
// config-first resolution so the port the server binds matches the port
// bootstrap advertises in its HTTPS_PROXY/SSL_CERT_FILE snippets.
func resolveListenAddr(flagChanged bool, flagAddr, cfgListen string) string {
	if flagChanged {
		return flagAddr
	}
	if cfgListen != "" {
		return cfgListen
	}
	return config.DefaultListenAddr
}

// buildBrokerHook materialises the request-time broker (config → token →
// credential vendor client → cached resolver → engine → hook). The returned
// bundle carries everything the caller needs to start hot-reload alongside
// the proxy. A zero bundle (hook=nil, engine=nil) is the "no broker" signal:
// the proxy runs in passthrough mode, which is what we want when no config
// file exists (path optional and missing) or when the config has no rules
// to broker.
//
// Required=true forces the config file to exist; the caller passes true
// when the user supplied --config explicitly so a typo doesn't silently
// downgrade the proxy to passthrough.
func buildBrokerHook(ctx context.Context, reg *credstore.Registry, cfgPath string, required bool, store token.Store, logger *slog.Logger) (brokerBundle, error) {
	cfg, err := config.LoadForCLI(cfgPath, required)
	if err != nil {
		return brokerBundle{}, err
	}
	if cfg == nil || len(cfg.Rules) == 0 {
		if cfg != nil && cfgPath != "" {
			// User has a config file but no rules. Hot-reload bootstrap (the
			// path that resolves a token and constructs the resolver on the
			// fly) is not yet implemented — tell the operator so they don't
			// expect adding a rule to take effect without a restart.
			logger.Warn("hot reload disabled until restart",
				slog.String("reason", "broker bootstrap (token + resolver) requires at least one rule at startup"),
				slog.String("path", cfgPath),
			)
		}
		logger.Info("broker disabled", slog.String("reason", "no rules in config; running in passthrough mode"))
		// Even in passthrough mode the config's listen address must reach the
		// caller so the server binds the configured port (cfg is nil only when
		// no config file was found, in which case listen stays empty).
		listen := ""
		if cfg != nil {
			listen = cfg.Proxy.Listen
		}
		return brokerBundle{listen: listen}, nil
	}

	rules, err := broker.FromConfigRules(cfg.Rules)
	if err != nil {
		return brokerBundle{}, fmt.Errorf("translate rules: %w", err)
	}
	engine := broker.NewEngine(rules)

	resolvers, err := buildCredStoreResolvers(ctx, reg, cfg.CredStores, store, logger)
	if err != nil {
		return brokerBundle{}, err
	}
	// Fail closed at boot if any rule's secret_ref scheme has no configured
	// resolver. Without this the mismatch would only surface as a 502 on the
	// first request that matches the rule — in production, at request time.
	if err := assertRulesRoutable(rules, resolvers); err != nil {
		return brokerBundle{}, err
	}
	router, err := credstore.NewSchemeRouter(resolvers)
	if err != nil {
		return brokerBundle{}, fmt.Errorf("init credstore router: %w", err)
	}

	cacheSettings := cfg.Proxy.CacheSettings()
	cached, err := credstore.NewCachedResolver(router, credstore.CacheConfig{
		TTL:          cacheSettings.TTL,
		RefreshAhead: cacheSettings.RefreshAhead,
		MaxStale:     cacheSettings.MaxStale,
		ShouldCache:  newShouldCacheRef(reg),
		Logger:       logger,
	})
	if err != nil {
		return brokerBundle{}, fmt.Errorf("init resolver cache: %w", err)
	}

	logger.Info("broker enabled",
		slog.Int("rules", len(rules)),
		slog.Int("credstores", len(cfg.CredStores)),
		slog.Duration("cache_ttl", cacheSettings.TTL),
		slog.Duration("cache_refresh_ahead", cacheSettings.RefreshAhead),
		slog.Duration("cache_max_stale", cacheSettings.MaxStale),
	)
	return brokerBundle{
		hook:    broker.Hook(engine, cached, cfg.Proxy.OnNoMatch, cfg.Proxy.MaxBodyBytes, logger), //nolint:bodyclose // hook is a closure; broker owns the synthetic body
		engine:  engine,
		cfgPath: cfgPath,
		listen:  cfg.Proxy.Listen,
		baseline: &broker.Baseline{
			Proxy:      cfg.Proxy,
			CredStores: cfg.CredStores,
		},
		shouldIntercept: func(host string) bool { _, ok := engine.Match(host); return ok },
		// on_no_match is captured here and in broker.Hook above; both bind it at
		// startup. A hot-reload edit does not take effect until restart — the
		// reloader's baseline comparison warns when on_no_match changes.
		blockNonBrokered: cfg.Proxy.OnNoMatch == config.OnNoMatchBlock,
	}, nil
}

// buildCredStoreResolvers walks the multi-credstore config and constructs
// one broker.Resolver per credstore, keyed by the provider's URI scheme.
// Each credstore's token is resolved through the standard token chain; the
// provider is selected by Name from the process-wide credstore registry.
// An empty Provider field signals a synthesized legacy default credstore;
// the function looks up the sole registered provider in that case so the
// existing single-credstore config files keep working unchanged.
//
// Returns an error when two credstores would claim the same scheme (the
// multi-credstores-per-provider routing flag is not yet implemented) or
// when an unknown provider is referenced.
func buildCredStoreResolvers(ctx context.Context, reg *credstore.Registry, stores []config.CredStore, store token.Store, logger *slog.Logger) (map[string]broker.Resolver, error) {
	resolvers := make(map[string]broker.Resolver, len(stores))
	schemeOwner := make(map[string]string, len(stores))
	for i := range stores {
		cs := &stores[i]
		provider, err := pickProvider(reg, *cs)
		if err != nil {
			return nil, err
		}
		scheme := provider.Scheme()
		if other, dup := schemeOwner[scheme]; dup {
			return nil, fmt.Errorf("credstores %q and %q both resolve to scheme %q (multiple credstores per provider not yet supported)", other, cs.Name, scheme)
		}

		tok, src, err := token.Resolve(ctx, cs.Token, store)
		if err != nil {
			return nil, fmt.Errorf("credstore %q: resolve service-account token: %w", cs.Name, err)
		}
		logger.Info("token resolved",
			slog.String("credstore", cs.Name),
			slog.String("provider", provider.Name()),
			slog.String("source", src),
		)

		resolver, err := buildOneResolver(ctx, provider, cs, tok, store)
		if err != nil {
			return nil, err
		}
		resolvers[scheme] = resolver
		schemeOwner[scheme] = cs.Name
	}
	return resolvers, nil
}

// buildOneResolver runs the boot-time credential ping and constructs the
// resolver for one credstore. The ping is fail-closed-at-boot (Provider.Validate
// semantics) so a bad credential surfaces here rather than as a 502 on the first
// brokered request.
//
// A credstore that declares a refresh_token block needs a second secret, so its
// provider must implement credstore.SecondarySecretProvider: the refresh token
// is resolved through the same chain as the primary token and passed alongside
// it. A provider that does not implement the interface rejects the block at boot.
func buildOneResolver(ctx context.Context, provider credstore.Provider, cs *config.CredStore, primary string, store token.Store) (broker.Resolver, error) {
	if cs.RefreshToken.IsZero() {
		if err := provider.Validate(ctx, primary, cs.Settings); err != nil {
			return nil, fmt.Errorf("credstore %q: validate %s: %w", cs.Name, provider.Name(), err)
		}
		resolver, err := provider.NewResolver(ctx, primary, cs.Settings)
		if err != nil {
			return nil, fmt.Errorf("credstore %q: init resolver: %w", cs.Name, err)
		}
		return resolver, nil
	}

	sp, ok := provider.(credstore.SecondarySecretProvider)
	if !ok {
		return nil, fmt.Errorf("credstore %q: provider %q does not accept a refresh_token block", cs.Name, provider.Name())
	}
	secondary, _, err := token.Resolve(ctx, cs.RefreshToken, store)
	if err != nil {
		return nil, fmt.Errorf("credstore %q: resolve refresh token: %w", cs.Name, err)
	}
	if err := sp.ValidateWithSecondary(ctx, primary, secondary, cs.Settings); err != nil {
		return nil, fmt.Errorf("credstore %q: validate %s: %w", cs.Name, provider.Name(), err)
	}
	resolver, err := sp.NewResolverWithSecondary(ctx, primary, secondary, cs.Settings)
	if err != nil {
		return nil, fmt.Errorf("credstore %q: init resolver: %w", cs.Name, err)
	}
	return resolver, nil
}

// pickProvider resolves a config.CredStore to its credstore.Provider.
// User-authored entries look up by Provider name. Loader-synthesized
// entries (built from a legacy top-level `token:` block) late-bind to
// the canonical legacy provider — looked up by the op scheme so adding a
// second provider to the binary (e.g., the bitwarden provider) doesn't break
// existing single-token configs.
func pickProvider(reg *credstore.Registry, cs config.CredStore) (credstore.Provider, error) {
	if cs.IsSynthesized() {
		p, ok := reg.ForScheme(legacyDefaultScheme)
		if !ok {
			return nil, fmt.Errorf("credstore %q: no registered provider for the legacy default scheme %q", cs.Name, legacyDefaultScheme)
		}
		return p, nil
	}
	p, ok := reg.ForName(cs.Provider)
	if !ok {
		return nil, fmt.Errorf("credstore %q: unknown provider %q", cs.Name, cs.Provider)
	}
	return p, nil
}

// assertRulesRoutable fails closed at boot if any rule's secret_ref scheme
// has no resolver in resolvers (keyed by scheme). Malformed refs are left to
// the schema validator; this guard is specifically the scheme-without-a-
// credstore case, which the per-scheme router would otherwise only reject at
// the first matching request.
func assertRulesRoutable(rules []broker.Rule, resolvers map[string]broker.Resolver) error {
	for i := range rules {
		r := &rules[i]
		// A placeholder-routing rule has an empty rule-level SecretRef and one
		// ref per route; an oauth1 rule has an empty SecretRef and four refs in
		// its inject block. Check every ref the rule can resolve to.
		refs := []string{r.SecretRef}
		for _, rt := range r.Routes {
			refs = append(refs, rt.SecretRef)
		}
		if r.Injection.Type == broker.InjectOAuth1 {
			o := r.Injection.OAuth1
			refs = append(refs, o.ConsumerKeyRef, o.ConsumerSecretRef, o.TokenRef, o.TokenSecretRef)
		}
		for _, ref := range refs {
			scheme, _, ok := strings.Cut(ref, "://")
			if !ok || scheme == "" {
				continue
			}
			if _, ok := resolvers[scheme]; !ok {
				return fmt.Errorf("rule %q references secret_ref scheme %q but no credstore resolves it", r.Host, scheme)
			}
		}
	}
	return nil
}

// newProviderFacts builds the config.ProviderFactsFunc that derives the
// registry-aware validation facts for a parsed config against reg: the
// provider names the binary has registered, and the secret-ref schemes the
// config's credstores resolve to. It mirrors the runtime wiring (pickProvider)
// so `postern config validate` flags the same unknown-provider and
// unroutable-scheme conditions the server would otherwise only hit at boot or
// first request.
func newProviderFacts(reg *credstore.Registry) config.ProviderFactsFunc {
	return func(cfg *config.Config) config.ProviderFacts {
		known := make(map[string]bool)
		for _, p := range reg.Providers() {
			known[p.Name()] = true
		}
		schemes := make(map[string]bool)
		for i := range cfg.CredStores {
			// An unknown provider here is reported separately via
			// KnownProviders; skip it rather than guess a scheme.
			if p, err := pickProvider(reg, cfg.CredStores[i]); err == nil {
				schemes[p.Scheme()] = true
			}
		}
		return config.ProviderFacts{
			KnownProviders:    known,
			ConfiguredSchemes: schemes,
			ValidateSettings: func(name string, settings map[string]string) error {
				// An unknown provider is reported via KnownProviders; we
				// can't validate its settings, so skip rather than panic.
				p, ok := reg.ForName(name)
				if !ok {
					return nil
				}
				return p.ValidateSettings(settings)
			},
		}
	}
}

// newShouldCacheRef builds the broker cache's per-reference cacheability
// predicate against reg. It routes a secret reference to its owning provider
// and defers to that provider's ShouldCache, so each vendor keeps ownership of
// its own non-cacheable-ref rule (e.g. the op scheme's OTP refs). An
// unroutable reference is treated as non-cacheable: it cannot resolve anyway,
// and caching a miss would be pointless.
func newShouldCacheRef(reg *credstore.Registry) func(secretRef string) bool {
	return func(secretRef string) bool {
		p, ok := reg.ForSecretRef(secretRef)
		if !ok {
			return false
		}
		return p.ShouldCache(secretRef)
	}
}

// legacyDefaultScheme is the URI scheme the loader assumes when it
// synthesizes a credstore from a top-level `token:` block. The single-vendor
// configuration predates the multi-vendor credstore registry, when the only
// credential vendor was the one that owns this scheme, so all legacy configs
// implicitly meant it.
const legacyDefaultScheme = "op"

// daemonize re-execs the current binary with the same arguments, sets the
// daemon-marker env var on the child, and exits the parent. On Linux we
// use Setsid so the child survives shell termination; on platforms that
// don't expose Setsid through syscall.SysProcAttr the call returns an
// error and the user can fall back to systemd or `nohup &`.
func daemonize() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	child := exec.Command(exe, os.Args[1:]...) //nolint:gosec // re-exec of self with own args is the canonical daemonize pattern
	child.Env = append(os.Environ(), daemonEnvFlag+"=1")
	child.Stdout = nil
	child.Stderr = nil
	child.Stdin = nil
	if err := setDaemonAttrs(child); err != nil {
		return fmt.Errorf("set daemon attrs: %w", err)
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	// Parent exits with code 0; the child carries the work. We can't use
	// a tidy return here because cobra would print "Removed" etc on top
	// of whatever the child prints; matching the conventional daemon
	// shape is more important than the RunE contract.
	_, _ = fmt.Fprintf(os.Stdout, "postern: started in background (pid=%d)\n", child.Process.Pid)
	os.Exit(0)
	return errors.New("unreachable")
}
