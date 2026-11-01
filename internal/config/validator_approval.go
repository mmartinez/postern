package config

import "fmt"

// checkApproval validates a rule's optional approval block. A null block is
// an error because it decodes to nil, which would silently drop the prompt
// the author asked for. The block is only accepted on platforms with an
// approval backend.
func (v *validator) checkApproval(base string, r Rule) {
	path := base + ".approval"
	if r.Approval == nil {
		if node := v.nodeAt(path); node != nil && node.Tag == "!!null" {
			v.add(path, "approval needs a mapping; use approval: {} to prompt on every request", SeverityError)
		}
		return
	}
	if v.goos != "linux" {
		v.add(path, fmt.Sprintf("approval is not supported on %s", v.goos), SeverityError)
	}
}
