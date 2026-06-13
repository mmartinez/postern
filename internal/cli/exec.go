package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/logging"
	"github.com/mmartinez/postern/internal/token"
)

// execFn is the process-replacement seam. Production wires it to the
// platform syscall.Exec wrapper (exec_unix.go); tests swap in a recorder so
// they can assert what the child would launch with — including that it never
// launches when resolution fails closed.
var execFn = execProcess

// NewExecCmd builds `postern exec`. It resolves the config's env: block through
// the same credstore path the proxy uses and replaces the current process with
// the given command, exporting the resolved values into the child's
// environment. reg is the credstore provider registry; store is the OS keychain
// wrapper feeding the token-resolution chain.
//
// Unlike the proxy — where the agent never holds the credential — env injection
// hands the secret to the launched process. It is the fallback for tools and
// protocols the proxy cannot intercept (a database driver, git over SSH, a CLI
// that reads $ENV); prefer routing HTTPS traffic through `postern server`.
func NewExecCmd(reg *credstore.Registry, store token.Store) *cobra.Command {
	var (
		configPath string
		logFormat  string
		logLevel   string
		noColor    bool
	)
	cmd := &cobra.Command{
		Use:   "exec [flags] -- command [args...]",
		Short: "Resolve declared secrets into a child process's environment",
		Long: "Resolve the config's env: block through the credential vendor and\n" +
			"replace postern with the given command, exporting the resolved values\n" +
			"into its environment. Use it for tools the proxy cannot intercept\n" +
			"(database drivers, git over SSH, CLIs that read environment variables).\n" +
			"\n" +
			"The resolved secret lives in the child's environment for its lifetime —\n" +
			"a weaker posture than the proxy, where the agent never holds the\n" +
			"credential. Prefer `postern server` for anything that speaks HTTPS.\n" +
			"\n" +
			"  postern exec -- node server.js\n" +
			"  postern exec --config ./postern.yaml -- devcontainer up --workspace-folder .",
		// Everything after `--` is the child command; cobra stops flag parsing
		// at the dash and hands the remainder through as args.
		Args:                  cobra.MinimumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, err := logging.New(logging.Options{
				Format:  logFormat,
				Level:   logLevel,
				NoColor: noColor,
				Output:  cmd.ErrOrStderr(),
			})
			if err != nil {
				return err
			}

			cfgPath := configPath
			if cfgPath == "" {
				cfgPath = config.DefaultPath()
			}
			// The env: block lives in the config, so unlike `server` there is no
			// useful zero-config mode: a missing file is an error, not a silent
			// no-op that would exec the child with nothing injected.
			cfg, err := config.LoadForCLI(cfgPath, true)
			if err != nil {
				return err
			}
			if cfg == nil || len(cfg.Env) == 0 {
				return fmt.Errorf("config %s declares no env: block; `postern exec` has nothing to inject", cfgPath)
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			resolvers, err := buildCredStoreResolvers(ctx, reg, cfg.CredStores, store, logger)
			if err != nil {
				return err
			}
			if err := assertEnvRoutable(cfg.Env, resolvers); err != nil {
				return err
			}
			router, err := credstore.NewSchemeRouter(resolvers)
			if err != nil {
				return fmt.Errorf("init credstore router: %w", err)
			}

			return runExec(ctx, router, cfg.Env, os.Environ(), newShouldCacheRef(reg), logger, execFn, args)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "Log format: text|json")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level: quiet|info|debug")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI colour (NO_COLOR env also honored)")
	return cmd
}

// runExec resolves refs into the child environment and hands off to exec. It is
// the testable core of `postern exec`: router and exec are injected so a test
// can drive it with a fake resolver and assert the child is launched only when
// every secret resolves. On any failure it returns before calling exec — fail
// closed, mirroring the proxy's 502-on-resolver-error rule.
func runExec(
	ctx context.Context,
	router broker.Resolver,
	refs map[string]string,
	inherited []string,
	shouldCache func(string) bool,
	logger *slog.Logger,
	exec func(command string, argv, env []string) error,
	args []string,
) error {
	if len(args) == 0 {
		return errors.New("exec requires a command to run")
	}
	childEnv, err := resolveExecEnv(ctx, router, refs, inherited, shouldCache, logger)
	if err != nil {
		return err
	}
	return exec(args[0], args, childEnv)
}

// resolveExecEnv resolves every ref in refs and returns the child environment:
// inherited overlaid with the resolved values. It fails closed — the first
// resolve error aborts and returns it, so the caller never execs a child with a
// half-populated secret set. A ref the owning provider marks non-cacheable
// (e.g. an OTP) is rejected up front: an exec'd child cannot re-resolve a
// short-lived secret. Resolved values are logged only as masked fingerprints.
func resolveExecEnv(
	ctx context.Context,
	router broker.Resolver,
	refs map[string]string,
	inherited []string,
	shouldCache func(string) bool,
	logger *slog.Logger,
) ([]string, error) {
	resolved := make(map[string]string, len(refs))
	for _, name := range sortedRefNames(refs) {
		ref := refs[name]
		if !shouldCache(ref) {
			return nil, fmt.Errorf("env %s: secret_ref %q is non-cacheable (e.g. a one-time password) and cannot be injected as an environment variable; route it through the proxy instead", name, ref)
		}
		val, err := router.Resolve(ctx, "", ref)
		if err != nil {
			return nil, fmt.Errorf("env %s: resolve %s: %w", name, ref, err)
		}
		resolved[name] = val
		logger.Info("env resolved",
			slog.String("name", name),
			slog.String("value", token.Fingerprint(val)),
		)
	}
	return mergeEnv(inherited, resolved), nil
}

// mergeEnv overlays resolved onto inherited, dropping any inherited entry whose
// name a resolved value replaces so the child sees exactly one binding per name.
// Resolved entries are appended in sorted order for deterministic output.
func mergeEnv(inherited []string, resolved map[string]string) []string {
	out := make([]string, 0, len(inherited)+len(resolved))
	for _, kv := range inherited {
		name, _, _ := strings.Cut(kv, "=")
		if _, overridden := resolved[name]; overridden {
			continue
		}
		out = append(out, kv)
	}
	for _, name := range sortedRefNames(resolved) {
		out = append(out, name+"="+resolved[name])
	}
	return out
}

// assertEnvRoutable fails closed if any env value's scheme has no resolver in
// resolvers (keyed by scheme). It mirrors assertRulesRoutable so an unroutable
// env ref errors before any resolve rather than mid-injection. Malformed refs
// are left to the schema validator.
func assertEnvRoutable(env map[string]string, resolvers map[string]broker.Resolver) error {
	for _, name := range sortedRefNames(env) {
		scheme, _, ok := strings.Cut(env[name], "://")
		if !ok || scheme == "" {
			continue
		}
		if _, ok := resolvers[scheme]; !ok {
			return fmt.Errorf("env %s references secret_ref scheme %q but no credstore resolves it", name, scheme)
		}
	}
	return nil
}

// sortedRefNames returns m's keys in lexical order so resolution, logging, and
// the assembled environment are deterministic regardless of map iteration.
func sortedRefNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
