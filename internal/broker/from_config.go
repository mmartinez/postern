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
// Validation (line-numbered, user-facing) is the config validator's job;
// FromConfigRules trusts that the config has already passed validation
// and only rejects values it cannot translate.
func FromConfigRules(in []config.Rule) ([]Rule, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]Rule, len(in))
	for i, src := range in {
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
		out[i] = Rule{
			Host:      src.Host,
			SecretRef: src.SecretRef,
			Injection: InjectSpec{
				Type:     t,
				Name:     src.Inject.Name,
				Template: src.Inject.Template,
			},
		}
	}
	return out, nil
}

func injectTypeFromConfig(t config.InjectType) (InjectType, error) {
	switch t {
	case config.InjectTypeHeader:
		return InjectHeader, nil
	case config.InjectTypePlaceholder:
		return InjectPlaceholder, nil
	default:
		return 0, fmt.Errorf("unknown inject.type %q", t)
	}
}
