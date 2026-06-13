package config

import (
	"fmt"
	"math"
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

// unreservedTokenPattern matches a placeholder token built only from RFC 3986
// unreserved characters. Such a token survives URL path/query escaping
// unchanged, so its encoded and decoded forms are identical — a prerequisite
// for stable substitution outside header values.
var unreservedTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

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
	v.checkCache(p)
	switch p.OnNoMatch {
	case OnNoMatchPassthrough, OnNoMatchBlock, "":
	default:
		v.add("proxy.on_no_match", fmt.Sprintf("invalid on_no_match value %q (want passthrough|block)", p.OnNoMatch), SeverityError)
	}
	if p.MaxBodyBytes < 0 {
		v.add("proxy.max_body_bytes", fmt.Sprintf("max_body_bytes must be >= 0 (got %d); 0 means use the default", p.MaxBodyBytes), SeverityError)
	}
}

// checkCache validates the credential-cache configuration. Without a cache
// block the legacy scalar cache_ttl is required and must be positive. With a
// cache block, cache_ttl becomes an optional alias for cache.ttl (setting both
// to different values is rejected), and the effective settings must satisfy
// 0 < refresh_ahead < ttl <= max_stale.
func (v *validator) checkCache(p *Proxy) {
	if p.Cache == nil {
		if p.CacheTTL <= 0 {
			v.add("proxy.cache_ttl", "cache_ttl must be > 0", SeverityError)
		}
		return
	}

	c := p.Cache
	if c.TTL > 0 && p.CacheTTL > 0 && c.TTL != p.CacheTTL {
		v.add("proxy.cache.ttl",
			fmt.Sprintf("cache.ttl (%s) and cache_ttl (%s) disagree; set only one", c.TTL, p.CacheTTL),
			SeverityError)
	}
	if c.TTL < 0 {
		v.add("proxy.cache.ttl", "cache.ttl must be > 0", SeverityError)
	}
	if c.RefreshAhead < 0 {
		v.add("proxy.cache.refresh_ahead", "cache.refresh_ahead must be > 0", SeverityError)
	}
	if c.MaxStale < 0 {
		v.add("proxy.cache.max_stale", "cache.max_stale must be > 0", SeverityError)
	}

	ttl := p.CacheSettings().TTL
	if c.RefreshAhead > 0 && c.RefreshAhead >= ttl {
		v.add("proxy.cache.refresh_ahead",
			fmt.Sprintf("cache.refresh_ahead (%s) must be less than ttl (%s)", c.RefreshAhead, ttl),
			SeverityError)
	}
	if c.MaxStale > 0 && c.MaxStale < ttl {
		v.add("proxy.cache.max_stale",
			fmt.Sprintf("cache.max_stale (%s) must be >= ttl (%s)", c.MaxStale, ttl),
			SeverityError)
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
	for i := range cs {
		c := &cs[i]
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

		// Cross-field consistency between settings.grant_type and the
		// refresh_token block. grant_type is settings-opaque to the config
		// package, but its relationship to the schema-level refresh_token block
		// is generic enough to validate offline (with a line number) rather than
		// only at boot: a refresh-token grant needs the block, and the block is
		// meaningless without that grant.
		grantType := c.Settings["grant_type"]
		hasRefreshBlock := !c.RefreshToken.IsZero()
		switch {
		case grantType == "refresh_token" && !hasRefreshBlock:
			v.add(base+".settings", "grant_type refresh_token requires a refresh_token block", SeverityError)
		case hasRefreshBlock && grantType != "refresh_token":
			v.add(base+".refresh_token", "a refresh_token block requires grant_type: refresh_token in settings", SeverityError)
		}
	}
}

func (v *validator) checkRulesSkipping(rules []Rule, skip map[int]struct{}) {
	seenHosts := make(map[string]int, len(rules))
	for i := range rules {
		r := rules[i]
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

	if len(r.Routes) > 0 {
		v.checkRoutes(base, r)
		return
	}

	if r.SecretRef == "" {
		v.add(base+".secret_ref", "secret_ref is required", SeverityError)
	} else if !secretRefPattern.MatchString(r.SecretRef) {
		v.add(base+".secret_ref", fmt.Sprintf("secret_ref %q must be a URI of the form <scheme>://<rest> (e.g., op://VAULT/ITEM/FIELD)", r.SecretRef), SeverityError)
	}

	v.checkInject(base+".inject", r.Inject)
}

// checkRoutes validates a placeholder-routing rule. Routes mode replaces the
// rule-level secret_ref and inject.name: each route carries its own token (the
// placeholder) and secret_ref (the secret that token selects). The shared
// inject block still supplies the template and surfaces, so its template is
// validated here while its name must be empty.
func (v *validator) checkRoutes(base string, r Rule) {
	in := r.Inject
	if r.SecretRef != "" {
		v.add(base+".secret_ref", "secret_ref must be empty when routes is set; each route's secret_ref selects the secret", SeverityError)
	}
	if in.Type != InjectTypePlaceholder {
		v.add(base+".inject.type", fmt.Sprintf("inject.type must be placeholder when routes is set (got %q)", in.Type), SeverityError)
	}
	if in.Name != "" {
		v.add(base+".inject.name", "inject.name must be empty when routes is set; each route's token is the placeholder", SeverityError)
	}
	if in.Template == "" {
		v.add(base+".inject.template", "template is required", SeverityError)
	} else if !strings.Contains(in.Template, "{{ CREDENTIAL }}") && !strings.Contains(in.Template, "{{CREDENTIAL}}") {
		v.add(base+".inject.template", "template must contain a {{ CREDENTIAL }} placeholder; without it the resolved credential is discarded and the request is forwarded unauthenticated", SeverityError)
	}

	v.checkInjectSurfaces(base+".inject", in)
	v.checkRouteEntries(base, r.Routes, surfacesHaveNonHeader(in.In))
}

// checkRouteEntries validates each route: required fields, a well-formed
// secret_ref, a token charset that round-trips outside headers, and that tokens
// are mutually unique and non-overlapping (no token a substring of another).
// Overlap is fatal because substitution matches by substring: an agent's token
// contained in another's would route to the wrong secret.
func (v *validator) checkRouteEntries(base string, routes []Route, hasNonHeader bool) {
	seenToken := make(map[string]int, len(routes))
	seenName := make(map[string]int, len(routes))
	for i, rt := range routes {
		rb := fmt.Sprintf("%s.routes[%d]", base, i)
		if rt.Name == "" {
			v.add(rb+".name", "name is required", SeverityError)
		} else if prev, dup := seenName[rt.Name]; dup {
			// Names are the log/metric attribution handle; duplicates make a
			// request impossible to attribute to one agent. Not a secret, so
			// echo it plainly.
			v.add(rb+".name", fmt.Sprintf("duplicate route name %q (first declared at %s.routes[%d])", rt.Name, base, prev), SeverityError)
		} else {
			seenName[rt.Name] = i
		}
		if rt.Token == "" {
			v.add(rb+".token", "token is required", SeverityError)
		}
		if rt.SecretRef == "" {
			v.add(rb+".secret_ref", "secret_ref is required", SeverityError)
		} else if !secretRefPattern.MatchString(rt.SecretRef) {
			v.add(rb+".secret_ref", fmt.Sprintf("secret_ref %q must be a URI of the form <scheme>://<rest> (e.g., op://VAULT/ITEM/FIELD)", rt.SecretRef), SeverityError)
		}
		if hasNonHeader && rt.Token != "" && !unreservedTokenPattern.MatchString(rt.Token) {
			v.add(rb+".token", "token must use only RFC 3986 unreserved characters (A-Z a-z 0-9 - . _ ~) when substituting outside headers", SeverityError)
		}
		if rt.Token != "" {
			if prev, dup := seenToken[rt.Token]; dup {
				v.add(rb+".token", fmt.Sprintf("duplicate token %s (first declared at %s.routes[%d])", maskToken(rt.Token), base, prev), SeverityError)
			} else {
				seenToken[rt.Token] = i
			}
			// A guessable token lets a co-tenant agent reach another route's
			// secret. Warn (not fatal) — the operator owns the trust decision.
			if bits := tokenEntropyBits(rt.Token); bits < minRecommendedTokenEntropyBits {
				v.add(rb+".token", fmt.Sprintf("token %s looks low-entropy (~%.0f bits); a guessable token lets a co-tenant agent reach another route's secret — use a high-entropy token (>= %d bits, e.g. 16+ random characters)", maskToken(rt.Token), bits, minRecommendedTokenEntropyBits), SeverityWarning)
			}
		}
	}

	for i := range routes {
		ti := routes[i].Token
		if ti == "" {
			continue
		}
		for j := range routes {
			if i == j {
				continue
			}
			tj := routes[j].Token
			if tj == "" || ti == tj {
				continue
			}
			if strings.Contains(ti, tj) {
				v.add(fmt.Sprintf("%s.routes[%d].token", base, i),
					fmt.Sprintf("token %s overlaps token %s (one is a substring of the other); routing matches by substring, so tokens must be mutually non-overlapping", maskToken(ti), maskToken(tj)),
					SeverityError)
			}
		}
	}
}

// surfacesHaveNonHeader reports whether the surface list names any surface other
// than header, which tightens the token charset (the token is percent-escaped
// outside header values and must round-trip).
func surfacesHaveNonHeader(in []InjectSurface) bool {
	for _, s := range in {
		if s == InjectSurfaceBody || s == InjectSurfacePath || s == InjectSurfaceQuery {
			return true
		}
	}
	return false
}

// minRecommendedTokenEntropyBits is the estimated-entropy floor below which a
// route token earns a warning. 64 bits is the common "strong shared secret"
// bar; below it a token starts to look human-named or short enough that a
// co-tenant agent could guess it. The estimate (see tokenEntropyBits) is
// length times log2 of the character-class alphabet, so it catches short or
// low-diversity tokens, not dictionary words.
const minRecommendedTokenEntropyBits = 64

// tokenEntropyBits estimates a token's entropy as len * log2(alphabet), where
// alphabet is the union of the character classes the token uses (lowercase,
// uppercase, digits, other). It is a deliberately rough upper bound used only
// to flag obviously-guessable tokens; it cannot detect a long dictionary word.
func tokenEntropyBits(s string) float64 {
	var lower, upper, digit, other bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	alphabet := 0
	if lower {
		alphabet += 26
	}
	if upper {
		alphabet += 26
	}
	if digit {
		alphabet += 10
	}
	if other {
		alphabet += 32
	}
	if alphabet == 0 {
		return 0
	}
	return float64(len([]rune(s))) * math.Log2(float64(alphabet))
}

// maskToken returns a log-safe fingerprint of a route token in the form
// "first4…last4", fully masking anything too short to reveal safely. A route
// token can be a shared secret in multi-agent deployments, so validator
// messages identify it by fingerprint rather than echoing it whole (a failing
// `config validate` may land in CI logs). Duplicated from token.Fingerprint
// because config cannot import token (token imports config).
func maskToken(s string) string {
	const reveal = 4
	if s == "" {
		return "<empty>"
	}
	// Rune-aware so a multi-byte token (allowed on the header surface) is never
	// sliced mid-rune into invalid UTF-8.
	r := []rune(s)
	if len(r) < 2*reveal+1 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:reveal]) + "…" + string(r[len(r)-reveal:])
}

func (v *validator) checkInject(base string, in Inject) {
	switch in.Type {
	case InjectTypeHeader:
		if in.Name == "" {
			v.add(base+".name", "name is required when inject.type=header", SeverityError)
		}
	case InjectTypePlaceholder:
		if in.Name == "" {
			// An empty placeholder token matches the empty substring in every
			// header value, smearing the credential across every header. Reject
			// it so the proxy never boots (or hot-reloads) into that state.
			v.add(base+".name", "name (the placeholder token to replace) is required when inject.type=placeholder", SeverityError)
		}
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

	v.checkInjectSurfaces(base, in)
}

// checkInjectSurfaces validates the per-rule substitution surface list and its
// dependent fields. Surfaces are valid only in placeholder mode; substituting
// outside headers tightens the token charset and brings the body-buffering cap
// into play.
func (v *validator) checkInjectSurfaces(base string, in Inject) {
	if len(in.In) > 0 && in.Type != InjectTypePlaceholder {
		v.add(base+".in", "inject.in is valid only with inject.type=placeholder", SeverityError)
		return
	}

	hasNonHeader, hasBody := false, false
	for _, s := range in.In {
		switch s {
		case InjectSurfaceHeader:
		case InjectSurfaceBody:
			hasNonHeader, hasBody = true, true
		case InjectSurfacePath, InjectSurfaceQuery:
			hasNonHeader = true
		default:
			v.add(base+".in", fmt.Sprintf("invalid surface %q (want any of header|body|path|query)", s), SeverityError)
		}
	}

	// Outside header values the token is percent-escaped; a token containing
	// reserved characters would not round-trip, so restrict it to the RFC 3986
	// unreserved set. Header-only rules keep the looser charset for back-compat.
	if hasNonHeader && in.Name != "" && !unreservedTokenPattern.MatchString(in.Name) {
		v.add(base+".name", "placeholder token must use only RFC 3986 unreserved characters (A-Z a-z 0-9 - . _ ~) when substituting outside headers", SeverityError)
	}

	if in.MaxBodyBytes != nil {
		if *in.MaxBodyBytes < 0 {
			v.add(base+".max_body_bytes", fmt.Sprintf("max_body_bytes must be >= 0 (got %d); 0 means inherit proxy.max_body_bytes", *in.MaxBodyBytes), SeverityError)
		}
		if !hasBody {
			v.add(base+".max_body_bytes", "max_body_bytes is meaningful only when inject.in includes \"body\"", SeverityError)
		}
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
