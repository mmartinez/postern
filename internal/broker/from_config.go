package broker

import (
	"fmt"

	"github.com/mmartinez/postern/internal/config"
)

// FromConfigRules translates the YAML schema's rule list into the runtime
// broker rule list the Engine consumes. It is the only crossing point
// between the config schema and the broker's internal representation, so
// adding a new InjectType requires updating both sides here.
//
// Each rule's Host pattern is canonicalized exactly once here (a single
// RFC 3986 §3.2.2 trailing dot stripped), so Rule.Match compares
// canonical-to-canonical with no per-call transformation. The validator
// keeps accepting dotted literals; runtime normalizes.
//
// Validation (line-numbered, user-facing) is the config validator's job;
// FromConfigRules trusts that the config has already passed validation
// and only rejects values it cannot translate.
func FromConfigRules(in []config.Rule) ([]Rule, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]Rule, len(in))
	for i := range in {
		src := in[i]
		if len(src.Injects) > 0 {
			specs, err := injectionsFromConfig(src.Injects)
			if err != nil {
				return nil, fmt.Errorf("rules[%d] (%s): %w", i, src.Host, err)
			}
			out[i] = Rule{Host: canonicalHost(src.Host), SecretRef: src.SecretRef, Injections: specs}
			continue
		}
		t, err := injectTypeFromConfig(src.Inject.Type)
		if err != nil {
			// A template-only rule has no Host yet; fall back to the template
			// name so the error still identifies which rule failed.
			label := src.Host
			if label == "" {
				label = "template:" + src.Template
			}
			return nil, fmt.Errorf("rules[%d] (%s): %w", i, label, err)
		}
		surfaces, err := surfacesFromConfig(src.Inject.In)
		if err != nil {
			return nil, fmt.Errorf("rules[%d] (%s): %w", i, src.Host, err)
		}
		out[i] = Rule{
			Host:      canonicalHost(src.Host),
			SecretRef: src.SecretRef,
			Injection: InjectSpec{
				Type:         t,
				Name:         src.Inject.Name,
				Template:     src.Inject.Template,
				Surfaces:     surfaces,
				MaxBodyBytes: derefBodyCap(src.Inject.MaxBodyBytes),
				OAuth1: OAuth1Refs{
					ConsumerKeyRef:    src.Inject.ConsumerKeyRef,
					ConsumerSecretRef: src.Inject.ConsumerSecretRef,
					TokenRef:          src.Inject.TokenRef,
					TokenSecretRef:    src.Inject.TokenSecretRef,
				},
			},
			Routes: routesFromConfig(src.Routes),
		}
	}
	return out, nil
}

// injectionsFromConfig translates a multi-header rule's inject list into
// runtime specs. Every entry shares the rule's secret_ref, so an entry carries
// only the header name and its template. Header mode is the only type the
// list supports; the validator rejects anything else, and so does this rather
// than translate a spec Inject could not apply.
func injectionsFromConfig(in []config.Inject) ([]InjectSpec, error) {
	out := make([]InjectSpec, len(in))
	for i := range in {
		e := &in[i]
		if e.Type != config.InjectTypeHeader {
			return nil, fmt.Errorf("injects[%d]: unsupported inject.type %q (header mode only)", i, e.Type)
		}
		out[i] = InjectSpec{Type: InjectHeader, Name: e.Name, Template: e.Template}
	}
	return out, nil
}

// routesFromConfig translates the YAML route list into broker routes. An empty
// list yields nil (a non-routing rule).
func routesFromConfig(in []config.Route) []Route {
	if len(in) == 0 {
		return nil
	}
	out := make([]Route, len(in))
	for i, r := range in {
		out[i] = Route{Name: r.Name, Token: r.Token, SecretRef: r.SecretRef}
	}
	return out
}

// surfacesFromConfig maps the YAML surface list to broker surfaces. An empty
// list yields nil, which Inject treats as header-only.
func surfacesFromConfig(in []config.InjectSurface) ([]Surface, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]Surface, len(in))
	for i, s := range in {
		switch s {
		case config.InjectSurfaceHeader:
			out[i] = SurfaceHeader
		case config.InjectSurfaceBody:
			out[i] = SurfaceBody
		case config.InjectSurfacePath:
			out[i] = SurfacePath
		case config.InjectSurfaceQuery:
			out[i] = SurfaceQuery
		default:
			return nil, fmt.Errorf("unknown inject.in surface %q", s)
		}
	}
	return out, nil
}

// derefBodyCap unwraps the optional per-rule body cap; a nil pointer (or a
// non-positive value) means inherit the proxy-wide cap, signalled as 0.
func derefBodyCap(p *int) int {
	if p == nil || *p <= 0 {
		return 0
	}
	return *p
}

func injectTypeFromConfig(t config.InjectType) (InjectType, error) {
	switch t {
	case config.InjectTypeHeader:
		return InjectHeader, nil
	case config.InjectTypePlaceholder:
		return InjectPlaceholder, nil
	case config.InjectTypeOAuth1:
		return InjectOAuth1, nil
	default:
		return 0, fmt.Errorf("unknown inject.type %q", t)
	}
}
