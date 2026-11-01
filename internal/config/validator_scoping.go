package config

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// alphabeticTokenPattern matches a non-empty run of ASCII letters — the
// shape of every RFC 9110 method token ("GET", "POST", "PATCH"). Anything
// else in a methods entry could never equal a real request method and would
// silently 502 that rule's traffic, so catch it at validate time.
var alphabeticTokenPattern = regexp.MustCompile(`^[A-Za-z]+$`)

// checkScoping validates a rule's optional request-scoping knobs:
//
//   - paths entries are URL-path prefixes and must start with "/" (they are
//     matched from the request root);
//   - methods entries must be non-empty alphabetic tokens (conventionally
//     uppercase, e.g. "POST");
//   - an explicitly empty list (`paths: []` / `methods: []`) is an error,
//     because the broker treats empty as unrestricted while an author who
//     wrote the key almost certainly meant "nothing matches" — the two
//     readings disagree fail-closed vs fail-open, so refuse the ambiguity
//     instead of guessing. An absent key stays fine.
func (v *validator) checkScoping(base string, r Rule) {
	v.checkScopingList(base+".paths", r.Paths,
		func(entry string) bool { return strings.HasPrefix(entry, "/") },
		`must start with "/" (entries match as URL-path prefixes from the request root)`)
	v.checkScopingList(base+".methods", r.Methods,
		func(entry string) bool { return alphabeticTokenPattern.MatchString(entry) },
		"must be a non-empty alphabetic HTTP method token (e.g. POST)")
}

// checkScopingList validates one scoping knob's entry list. Empty lists are
// only rejected when the key is actually present in the YAML document,
// which the decoded struct alone cannot reveal (both nil and [] decode from
// different sources), so presence is confirmed against the AST.
func (v *validator) checkScopingList(path string, entries []string, valid func(string) bool, requirement string) {
	if len(entries) == 0 {
		if node := v.nodeAt(path); node != nil && node.Kind == yaml.SequenceNode {
			key := path[strings.LastIndex(path, ".")+1:]
			v.add(path, fmt.Sprintf("%s is empty; declare at least one entry or omit the key entirely (an omitted %s leaves the rule unscoped)", key, key), SeverityError)
		}
		return
	}
	for i := range entries {
		if !valid(entries[i]) {
			v.add(fmt.Sprintf("%s[%d]", path, i), fmt.Sprintf("%q %s", entries[i], requirement), SeverityError)
		}
	}
}

// nodeAt walks the AST to the dotted path (same grammar locate consumes)
// and returns the terminal node, or nil when the document has no such node.
func (v *validator) nodeAt(path string) *yaml.Node {
	if v.root == nil {
		return nil
	}
	// yaml.v3 wraps the doc in a DocumentNode; descend once.
	node := v.root
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	for _, step := range parsePath(path) {
		node = step(node)
		if node == nil {
			return nil
		}
	}
	return node
}
