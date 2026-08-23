package credstore

import "strings"

// ParseQualifiedRef splits a secret reference's scheme portion into its
// scheme and optional credstore-name qualifier per the grammar
//
//	<scheme>+<name>://<rest>       (qualified, e.g. op+team://V/I/f)
//	<scheme>://<rest>              (unqualified, e.g. op://V/I/f)
//
// It returns the scheme, the credstore name ("" when the reference is
// unqualified), and ok=false for anything that is not a well-formed
// qualified or plain URI head (missing "://", empty scheme, or an empty
// qualifier as in "op+://..."). The split point is the LAST "+" before
// "://" so a hypothetical provider scheme containing "+" can still be
// qualified unambiguously; a name may therefore not contain "+".
//
// This is the single grammar definition for credstore-qualified secret
// references: every inspection site (registry lookup, router dispatch,
// CLI boot guards, validator facts, `rules list`) parses through it so
// the qualifier means exactly one thing everywhere.
func ParseQualifiedRef(secretRef string) (scheme, name string, ok bool) {
	i := strings.Index(secretRef, "://")
	if i <= 0 {
		return "", "", false
	}
	head := secretRef[:i]
	if plus := strings.LastIndex(head, "+"); plus > 0 {
		scheme, name = head[:plus], head[plus+1:]
		if name == "" {
			return "", "", false
		}
	} else {
		scheme = head
	}
	if scheme == "" {
		return "", "", false
	}
	return scheme, name, true
}

// StripQualifier removes the credstore-name qualifier from a secret
// reference so vendor code only ever sees the plain "<scheme>://<rest>"
// form ("op+team://V/I/f" → "op://V/I/f"). An unqualified or malformed
// reference is returned unchanged.
func StripQualifier(secretRef string) string {
	i := strings.Index(secretRef, "://")
	if i <= 0 {
		return secretRef
	}
	if plus := strings.LastIndex(secretRef[:i], "+"); plus > 0 {
		return secretRef[:plus] + secretRef[i:]
	}
	return secretRef
}
