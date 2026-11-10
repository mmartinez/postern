package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// The YAML decoder reproduces scalar values in type errors. Enrollment is
// checked structurally first so even malformed verifiers stay out of diagnostics.
func checkEnrollmentNodes(doc *yaml.Node) error {
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "agents" {
			continue
		}
		agents := root.Content[i+1]
		if agents.Kind != yaml.SequenceNode {
			return enrollmentNodeError(agents.Line)
		}
		for _, entry := range agents.Content {
			if entry.Kind != yaml.MappingNode {
				return enrollmentNodeError(entry.Line)
			}
			for j := 0; j < len(entry.Content); j += 2 {
				key, value := entry.Content[j], entry.Content[j+1]
				if key.Value != "name" && key.Value != "key_sha256" || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
					return enrollmentNodeError(key.Line)
				}
			}
		}
	}
	return nil
}

func enrollmentNodeError(line int) error {
	return fmt.Errorf("line %d: invalid agents structure or unknown enrollment field", line)
}
