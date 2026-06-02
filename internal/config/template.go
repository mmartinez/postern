package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mmartinez/postern/internal/templates"
)

// expandTemplates walks cfg.Rules and, for every rule that names a built-in
// template (via the `template:` field), folds the template's host + inject
// defaults into any field the user left blank. The user always wins: if the
// rule already supplies a Host, Inject.Type, Inject.Name, or Inject.Template,
// those values pass through untouched.
//
// Unknown template names are returned as fatal LintErrors so the validator
// can fold them into its existing lint surface. Returned skipIdx names the
// indices of rules expansion could not resolve; the validator skips those
// rules so a single typo doesn't produce a cascade of misleading 'host is
// required' / 'inject.type is required' lints with line=0.
//
// Returned cfg is the same pointer mutated in place — expansion is an
// effective-config transform rather than a separate stage so downstream
// consumers (FromConfigRules, the broker engine, `rules list`) see the
// fully-resolved rule shape without an extra plumbing hop.
func expandTemplates(cfg *Config, root *yaml.Node) (lints []LintError, skipIdx map[int]struct{}) {
	if cfg == nil {
		return nil, nil
	}
	skipIdx = make(map[int]struct{})
	v := newValidator(root)
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Template == "" {
			continue
		}
		tpl, ok := templates.Lookup(r.Template)
		if !ok {
			line, col := v.locate(fmt.Sprintf("rules[%d].template", i))
			lints = append(lints, LintError{
				Line:     line,
				Column:   col,
				Severity: SeverityError,
				Path:     fmt.Sprintf("rules[%d].template", i),
				Message: fmt.Sprintf(
					"unknown template %q (valid templates: %s)",
					r.Template, strings.Join(templates.Names(), ", "),
				),
			})
			skipIdx[i] = struct{}{}
			continue
		}
		applyTemplate(r, tpl)
	}
	return lints, skipIdx
}

// applyTemplate fills only the rule fields the user left empty. Order
// matters: Host, Inject.Type, Inject.Name, Inject.Template can each be
// individually overridden.
func applyTemplate(r *Rule, tpl templates.Template) {
	if r.Host == "" {
		r.Host = tpl.Host
	}
	if r.Inject.Type == "" {
		r.Inject.Type = InjectType(tpl.InjectType)
	}
	if r.Inject.Name == "" {
		r.Inject.Name = tpl.HeaderName
	}
	if r.Inject.Template == "" {
		r.Inject.Template = tpl.Template
	}
}
