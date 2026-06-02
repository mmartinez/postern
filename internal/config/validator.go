package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity classifies a LintError as a fatal error or a warning. A missing
// CREDENTIAL placeholder is a warning; everything else is an error.
type Severity int

// Severity values returned by Validate.
const (
	SeverityError Severity = iota
	SeverityWarning
)

// LintError describes a single schema-level finding. Line/Column are 1-based
// and refer to the source YAML document; both are 0 when no location is known.
type LintError struct {
	Line     int
	Column   int
	Severity Severity
	Path     string // dotted path: rules[0].inject.name
	Message  string
}

func (e LintError) Error() string {
	sev := "error"
	if e.Severity == SeverityWarning {
		sev = "warning"
	}
	if e.Line > 0 {
		return fmt.Sprintf("%d:%d: %s: %s: %s", e.Line, e.Column, sev, e.Path, e.Message)
	}
	return fmt.Sprintf("%s: %s: %s", sev, e.Path, e.Message)
}

// secretRefPattern is the scheme-agnostic shape every secret_ref must
// match: an RFC-3986-style URI scheme followed by `://` and a non-empty
// path. Per-vendor grammar (e.g., the three-segment op://VAULT/ITEM/FIELD
// shape for the op scheme) is each provider's responsibility — keeping
// the schema layer brand-agnostic lets new providers ship without
// editing the config validator.
var secretRefPattern = regexp.MustCompile(`^[a-z][a-z0-9+.\-]*://.+$`)

// Validate walks cfg and returns the slice of findings. Root is the AST from
// Load and supplies line numbers; pass nil to skip location info.
func Validate(cfg *Config, root *yaml.Node) []LintError {
	return validateSkipping(cfg, root, nil)
}

// validateSkipping is Validate but with an additional set of rule indices to
// bypass. LoadAndValidate passes the indices of rules whose `template:` name
// could not be resolved so the validator doesn't pile a cascade of misleading
// 'host is required' / 'inject.type is required' lints on top of the single
// root cause.
func validateSkipping(cfg *Config, root *yaml.Node, skipRule map[int]struct{}) []LintError {
	if cfg == nil {
		return nil
	}
	v := newValidator(root)
	v.checkProxy(&cfg.Proxy)
	v.checkCredStores(cfg.CredStores)
	v.checkRulesSkipping(cfg.Rules, skipRule)
	// Rules without any credstore can never be brokered. Flagging this at
	// validate time turns the otherwise-cryptic boot error "scheme router
	// requires at least one resolver" into a line-numbered lint.
	if len(cfg.Rules) > 0 && len(cfg.CredStores) == 0 {
		v.add("credstores", "at least one credstore is required when rules are non-empty (set top-level `token:` or `credstores:`)", SeverityError)
	}
	return v.out
}

type validator struct {
	root *yaml.Node
	out  []LintError
}

func newValidator(root *yaml.Node) *validator {
	return &validator{root: root}
}

func (v *validator) add(path, msg string, sev Severity) {
	line, col := v.locate(path)
	v.out = append(v.out, LintError{
		Line:     line,
		Column:   col,
		Severity: sev,
		Path:     path,
		Message:  msg,
	})
}

func (v *validator) checkProxy(p *Proxy) {
	if p.Listen != "" {
		if _, _, err := net.SplitHostPort(p.Listen); err != nil {
			v.add("proxy.listen", fmt.Sprintf("invalid listen address %q: %v", p.Listen, err), SeverityError)
		}
	} else {
		v.add("proxy.listen", "listen is required", SeverityError)
	}
	if p.CacheTTL <= 0 {
		v.add("proxy.cache_ttl", "cache_ttl must be > 0", SeverityError)
	}
	switch p.OnNoMatch {
	case OnNoMatchPassthrough, OnNoMatchBlock, "":
	default:
		v.add("proxy.on_no_match", fmt.Sprintf("invalid on_no_match value %q (want passthrough|block)", p.OnNoMatch), SeverityError)
	}
}

// checkCredStores enforces the multi-credstore form's structural rules:
// every entry must have a name and a provider, and names must be unique.
// Provider-name-is-registered is intentionally not checked here so the
// config package stays decoupled from the credstore registry; the runtime
// surfaces unknown-provider errors at server boot with a clear message.
// Loader-synthesized credstores are exempt; user-authored entries are
// always validated regardless of their Name/Provider values (so a user
// who hand-writes the synthesized shape cannot bypass required-field
// checks).
func (v *validator) checkCredStores(cs []CredStore) {
	seenName := make(map[string]int, len(cs))
	for i, c := range cs {
		if c.IsSynthesized() {
			// The loader produced this from a legacy top-level token:
			// block; required fields will be late-bound at runtime.
			continue
		}
		base := fmt.Sprintf("credstores[%d]", i)
		if c.Name == "" {
			v.add(base+".name", "name is required", SeverityError)
		} else if prev, dup := seenName[c.Name]; dup {
			v.add(base+".name", fmt.Sprintf("duplicate credstore name %q (first declared at credstores[%d])", c.Name, prev), SeverityError)
		} else {
			seenName[c.Name] = i
		}
		if c.Provider == "" {
			v.add(base+".provider", "provider is required", SeverityError)
		}
	}
}

func (v *validator) checkRulesSkipping(rules []Rule, skip map[int]struct{}) {
	seenHosts := make(map[string]int, len(rules))
	for i, r := range rules {
		if _, skipRule := skip[i]; skipRule {
			continue
		}
		base := fmt.Sprintf("rules[%d]", i)
		v.checkRule(base, r)
		if r.Host != "" {
			if prev, dup := seenHosts[r.Host]; dup {
				v.add(base+".host", fmt.Sprintf("duplicate host %q (first declared at rules[%d])", r.Host, prev), SeverityError)
			} else {
				seenHosts[r.Host] = i
			}
		}
	}
}

func (v *validator) checkRule(base string, r Rule) {
	if r.Host == "" {
		v.add(base+".host", "host is required", SeverityError)
	} else if !isValidHostPattern(r.Host) {
		v.add(base+".host", fmt.Sprintf("host %q must be a literal hostname or a single-* glob (e.g. *.example.com)", r.Host), SeverityError)
	}

	if r.SecretRef == "" {
		v.add(base+".secret_ref", "secret_ref is required", SeverityError)
	} else if !secretRefPattern.MatchString(r.SecretRef) {
		v.add(base+".secret_ref", fmt.Sprintf("secret_ref %q must be a URI of the form <scheme>://<rest> (e.g., op://VAULT/ITEM/FIELD)", r.SecretRef), SeverityError)
	}

	v.checkInject(base+".inject", r.Inject)
}

func (v *validator) checkInject(base string, in Inject) {
	switch in.Type {
	case InjectTypeHeader:
		if in.Name == "" {
			v.add(base+".name", "name is required when inject.type=header", SeverityError)
		}
	case InjectTypePlaceholder:
		// no name needed
	case "":
		v.add(base+".type", "inject.type is required (header|placeholder)", SeverityError)
	default:
		v.add(base+".type", fmt.Sprintf("invalid inject.type %q (want header|placeholder)", in.Type), SeverityError)
	}
	if in.Template == "" {
		v.add(base+".template", "template is required", SeverityError)
	} else if !strings.Contains(in.Template, "{{ CREDENTIAL }}") && !strings.Contains(in.Template, "{{CREDENTIAL}}") {
		// Fatal, not a warning: a template with no placeholder discards the
		// resolved credential, so the request would be forwarded to the upstream
		// unauthenticated — a silent fail-open. Reject it at validate time so the
		// proxy never boots (or hot-reloads) into that state.
		v.add(base+".template", "template must contain a {{ CREDENTIAL }} placeholder; without it the resolved credential is discarded and the request is forwarded unauthenticated", SeverityError)
	}
}

// isValidHostPattern accepts a literal hostname or a single-* glob like
// "*.example.com". No regex; no multiple stars.
func isValidHostPattern(h string) bool {
	starCount := strings.Count(h, "*")
	switch starCount {
	case 0:
		return strings.IndexFunc(h, func(r rune) bool {
			return r == '/' || r == ' '
		}) == -1
	case 1:
		// Must be of the form *.something
		return strings.HasPrefix(h, "*.") && !strings.Contains(h[2:], "*")
	default:
		return false
	}
}

// locate walks the AST to the dotted path (e.g. "rules[0].inject.name") and
// returns its Line/Column. Returns (0, 0) when the node can't be found.
func (v *validator) locate(path string) (line, col int) {
	if v.root == nil {
		return 0, 0
	}
	// yaml.v3 wraps the doc in a DocumentNode; descend once.
	node := v.root
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	for _, step := range parsePath(path) {
		node = step(node)
		if node == nil {
			return 0, 0
		}
	}
	return node.Line, node.Column
}

// parsePath converts "rules[2].inject.name" into a sequence of descent
// functions over yaml.Node.
func parsePath(path string) []func(*yaml.Node) *yaml.Node {
	if path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	steps := make([]func(*yaml.Node) *yaml.Node, 0, len(parts))
	for _, p := range parts {
		// Pull index suffixes off, e.g. "rules[2]" → key "rules" + index 2.
		key := p
		idx := -1
		if open := strings.IndexByte(p, '['); open != -1 && strings.HasSuffix(p, "]") {
			key = p[:open]
			numStr := p[open+1 : len(p)-1]
			n := 0
			for _, ch := range numStr {
				if ch < '0' || ch > '9' {
					n = -1
					break
				}
				n = n*10 + int(ch-'0')
			}
			idx = n
		}
		if key != "" {
			k := key
			steps = append(steps, func(n *yaml.Node) *yaml.Node { return mappingChild(n, k) })
		}
		if idx >= 0 {
			i := idx
			steps = append(steps, func(n *yaml.Node) *yaml.Node { return sequenceChild(n, i) })
		}
	}
	return steps
}

func mappingChild(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func sequenceChild(n *yaml.Node, idx int) *yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode || idx < 0 || idx >= len(n.Content) {
		return nil
	}
	return n.Content[idx]
}
