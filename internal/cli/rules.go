package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/config"
)

// NewRulesCmd builds `postern rules`, the parent for rule introspection
// subcommands. `list` is the only one defined so far.
func NewRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect loaded broker rules",
		Long: "Read-only views of the rules postern would apply if it were running.\n" +
			"Useful for confirming what a config file declares before starting\n" +
			"the proxy. Never prints resolved credentials.",
	}
	cmd.AddCommand(newRulesListCmd())
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var (
		path   string
		format string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List rules with host pattern, secret_ref, and injection spec",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target := path
			if target == "" {
				target = config.DefaultPath()
			}

			cfg, lints, err := config.LoadFile(target)
			if err != nil {
				return fmt.Errorf("load config %s: %w", target, err)
			}

			// Surface schema errors (unknown template, bad secret_ref, etc.)
			// before the table so a typo doesn't show up as a row with empty
			// columns and zero diagnostic. Warnings are advisory and don't
			// short-circuit the listing.
			var fatal int
			for _, l := range lints {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", target, l.Error())
				if l.Severity == config.SeverityError {
					fatal++
				}
			}
			if fatal > 0 {
				return fmt.Errorf("%s: %d schema error(s); run `postern config validate` for details", target, fatal)
			}

			switch format {
			case "table", "":
				return writeRulesTable(cmd.OutOrStdout(), cfg.Rules)
			case "json":
				return writeRulesJSON(cmd.OutOrStdout(), cfg.Rules)
			default:
				return fmt.Errorf("unknown --format %q (want table|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")
	return cmd
}

// writeRulesTable emits a tab-separated table. CRITICAL: only surface the
// secret reference, never the resolved credential. The CLI
// cannot resolve credentials anyway (no token chain runs here) — this
// constraint is documented so future refactors don't add a "resolve and
// show" convenience that would defeat the trust boundary.
func writeRulesTable(out io.Writer, rules []config.Rule) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "HOST\tSECRET REF\tINJECT\tNAME\tTEMPLATE"); err != nil {
		return err
	}
	if len(rules) == 0 {
		if _, err := fmt.Fprintln(w, "(no rules)\t-\t-\t-\t-"); err != nil {
			return err
		}
		return w.Flush()
	}
	for _, r := range rules {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.Host, r.SecretRef, r.Inject.Type, r.Inject.Name, r.Inject.Template,
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ruleJSON mirrors the YAML schema rather than the runtime broker.Rule so
// scripts consuming the output match the keys they see in the config file.
type ruleJSON struct {
	Host      string     `json:"host"`
	SecretRef string     `json:"secret_ref"`
	Inject    injectJSON `json:"inject"`
}

type injectJSON struct {
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Template string `json:"template"`
}

func writeRulesJSON(out io.Writer, rules []config.Rule) error {
	jr := make([]ruleJSON, len(rules))
	for i, r := range rules {
		jr[i] = ruleJSON{
			Host:      r.Host,
			SecretRef: r.SecretRef,
			Inject: injectJSON{
				Type:     string(r.Inject.Type),
				Name:     r.Inject.Name,
				Template: r.Inject.Template,
			},
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}
