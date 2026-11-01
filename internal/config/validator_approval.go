package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// checkApproval validates a rule's optional approval block. A null block is
// an error because it decodes to nil, which would silently drop the prompt
// the author asked for. The block is only accepted on platforms with an
// approval backend.
func (v *validator) checkApproval(base string, r Rule) {
	path := base + ".approval"
	if r.Approval == nil {
		node, err := v.decodedApproval(base)
		if err != nil {
			v.add(path, fmt.Sprintf("read approval block: %v", err), SeverityError)
			return
		}
		if node == nil {
			return
		}
		line, col := v.locate(path)
		if line == 0 {
			line, col = node.Line, node.Column
		}
		v.out = append(v.out, LintError{
			Line:     line,
			Column:   col,
			Severity: SeverityError,
			Path:     path,
			Message:  "approval needs a mapping; use approval: {} to prompt on every request",
		})
		return
	}
	if v.goos != "linux" {
		v.add(path, fmt.Sprintf("approval is not supported on %s", v.goos), SeverityError)
	}
	if r.Approval.TTL < 0 {
		v.add(path+".ttl", "ttl must be zero or positive", SeverityError)
	}
}

// decodedApproval returns the raw approval value the decoder saw for the rule
// at base, or nil when the rule has no approval key. It decodes the document
// again instead of walking the tree, so aliases and merge keys resolve exactly
// as they did for the config.
func (v *validator) decodedApproval(base string) (*yaml.Node, error) {
	if v.root == nil {
		return nil, nil
	}
	if v.approvals == nil {
		var doc struct {
			Rules []struct {
				Approval yaml.Node `yaml:"approval"`
			} `yaml:"rules"`
		}
		if err := v.root.Decode(&doc); err != nil {
			return nil, err
		}
		v.approvals = make(map[string]*yaml.Node, len(doc.Rules))
		for i := range doc.Rules {
			if doc.Rules[i].Approval.Kind != 0 {
				v.approvals[fmt.Sprintf("rules[%d]", i)] = &doc.Rules[i].Approval
			}
		}
	}
	return v.approvals[base], nil
}
