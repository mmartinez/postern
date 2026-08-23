package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
)

// NewRulesCmd builds `postern rules`, the parent for rule introspection
// subcommands. `list` is the only one defined so far. reg is the credstore
// provider registry the listing resolves each rule's secret_ref against to
// show which configured credstore it routes to; pass a populated registry
// so qualified refs (`op+team://...`) and unambiguous unqualified refs can
// be attributed to a store name.
func NewRulesCmd(reg *credstore.Registry) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect loaded broker rules",
		Long: "Read-only views of the rules postern would apply if it were running.\n" +
			"Useful for confirming what a config file declares before starting\n" +
			"the proxy. Never prints resolved credentials.",
	}
	cmd.AddCommand(newRulesListCmd(reg))
	return cmd
}

func newRulesListCmd(reg *credstore.Registry) *cobra.Command {
	var (
		path   string
		format string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List rules with hosts, secret refs, credstores, and injects",
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

			schemeOwners := buildSchemeOwners(reg, cfg.CredStores)

			switch format {
			case "table", "":
				return writeRulesTable(cmd.OutOrStdout(), cfg.Rules, schemeOwners)
			case "json":
				return writeRulesJSON(cmd.OutOrStdout(), cfg.Rules, schemeOwners)
			default:
				return fmt.Errorf("unknown --format %q (want table|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table|json")
	return cmd
}

// ruleCredstoreNames returns the credstore NAMES every reference the rule
// carries (rule-level secret_ref, route refs, oauth1 refs) resolves
// against, in first-appearance order and deduplicated. A qualified ref
// contributes its named qualifier; an unqualified ref contributes the sole
// owner of its scheme, or nothing when the scheme is unroutable or
// ambiguous between stores. Only names are returned — never credential
// material.
func ruleCredstoreNames(r config.Rule, schemeOwners map[string][]string) []string {
	refs := []string{r.SecretRef}
	for _, rt := range r.Routes {
		refs = append(refs, rt.SecretRef)
	}
	if r.Inject.Type == config.InjectTypeOAuth1 {
		refs = append(refs,
			r.Inject.ConsumerKeyRef,
			r.Inject.ConsumerSecretRef,
			r.Inject.TokenRef,
			r.Inject.TokenSecretRef,
		)
	}
	seen := make(map[string]bool)
	var names []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, ref := range refs {
		scheme, name, ok := credstore.ParseQualifiedRef(ref)
		if !ok {
			continue
		}
		if name != "" {
			add(name)
			continue
		}
		if owners := schemeOwners[scheme]; len(owners) == 1 {
			add(owners[0])
		}
	}
	return names
}

// writeRulesTable emits a tab-separated table. CRITICAL: only surface the
// secret reference and the credstore NAME each ref routes to, never the
// resolved credential. The CLI cannot resolve credentials anyway (no token
// chain runs here) — this constraint is documented so future refactors
// don't add a "resolve and show" convenience that would defeat the trust
// boundary.
func writeRulesTable(out io.Writer, rules []config.Rule, schemeOwners map[string][]string) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "HOST\tSECRET REF\tCREDSTORE\tINJECT\tNAME\tTEMPLATE"); err != nil {
		return err
	}
	if len(rules) == 0 {
		if _, err := fmt.Fprintln(w, "(no rules)\t-\t-\t-\t-\t-"); err != nil {
			return err
		}
		return w.Flush()
	}
	for i := range rules {
		r := rules[i]
		storeCell := "-"
		if names := ruleCredstoreNames(r, schemeOwners); len(names) > 0 {
			storeCell = strings.Join(names, ", ")
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Host, r.SecretRef, storeCell, r.Inject.Type, r.Inject.Name, r.Inject.Template,
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
	Credstore []string   `json:"credstores"`
	Inject    injectJSON `json:"inject"`
}

type injectJSON struct {
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Template string `json:"template"`
}

func writeRulesJSON(out io.Writer, rules []config.Rule, schemeOwners map[string][]string) error {
	jr := make([]ruleJSON, len(rules))
	for i := range rules {
		r := rules[i]
		names := ruleCredstoreNames(r, schemeOwners)
		if names == nil {
			names = []string{}
		}
		jr[i] = ruleJSON{
			Host:      r.Host,
			SecretRef: r.SecretRef,
			Credstore: names,
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
