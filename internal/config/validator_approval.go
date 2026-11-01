package config

import (
	"fmt"
	"slices"
	"strings"
)

// checkApproval validates a rule's optional approval block. A null block is
// an error because it decodes to nil, which would silently drop the prompt
// the author asked for. The block is only accepted on platforms with an
// approval backend. Approval methods must be methods the rule brokers, when
// the rule lists them.
func (v *validator) checkApproval(base string, r Rule) {
	path := base + ".approval"
	if r.Approval == nil {
		if v.nodeAt(path) != nil {
			v.add(path, "approval needs a mapping; use approval: {} to prompt on every request", SeverityError)
		}
		return
	}
	if v.goos != "linux" && v.goos != "darwin" {
		v.add(path, fmt.Sprintf("approval is not supported on %s", v.goos), SeverityError)
	}
	if r.Approval.TTL < 0 {
		v.add(path+".ttl", "ttl must be zero or positive", SeverityError)
	}
	v.checkMethods(path+".methods", r.Approval.Methods, "requires approval for every method")
	if len(r.Methods) == 0 {
		return
	}
	for i, m := range r.Approval.Methods {
		if !slices.ContainsFunc(r.Methods, func(rm string) bool { return strings.EqualFold(rm, m) }) {
			v.add(fmt.Sprintf("%s.methods[%d]", path, i), fmt.Sprintf("%q is not in the rule's methods", m), SeverityError)
		}
	}
}
