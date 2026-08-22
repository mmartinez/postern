package config

import (
	"fmt"
	"slices"
)

// This file implements the credstore-qualified secret-ref routing checks
// for the `<scheme>+<name>://` grammar (see credstore.ParseQualifiedRef in
// the credstore package, wired in here via ProviderFacts.ClassifyRef).
// They run on the registry-aware validation stage (ValidateProviders)
// because they need the config's credstore routing picture, which plain
// schema validation cannot know:
//
//   - an unqualified ref whose scheme more than one credstore resolves is
//     ambiguous — it must carry a `+<name>` qualifier naming one of them;
//   - a qualified ref naming a credstore that is not configured can never
//     route;
//   - a qualified ref whose scheme differs from the named store's provider
//     scheme can never route (e.g. op+bw-store://... where bw-store
//     resolves "bw").
//
// Each finding is reported at the offending reference's line so
// `postern config validate` points straight at the YAML.

// checkQualifiedRef applies the three routing checks above to one secret
// reference. Unroutable schemes (no configured credstore at all) are left
// to checkRefScheme; empty and malformed refs are skipped as usual.
func (v *validator) checkQualifiedRef(path, ref string, facts ProviderFacts) {
	scheme, name, ok := facts.ClassifyRef(ref)
	if !ok {
		return
	}
	if name != "" {
		storeScheme, known := facts.StoreSchemes[name]
		if !known {
			v.add(path, fmt.Sprintf("secret_ref %q names credstore %q which is not configured", ref, name), SeverityError)
			return
		}
		if storeScheme != scheme {
			v.add(path, fmt.Sprintf(
				"secret_ref %q names credstore %q which resolves scheme %q, not %q",
				ref, name, storeScheme, scheme,
			), SeverityError)
		}
		return
	}

	names := slices.Clone(facts.SchemeNames[scheme])
	slices.Sort(names)
	switch len(names) {
	case 0:
		// No credstore at all: already flagged by checkRefScheme.
	case 1:
	default:
		list := fmt.Sprintf("%q", names[0])
		for _, n := range names[1:] {
			list += fmt.Sprintf(" and %q", n)
		}
		v.add(path, fmt.Sprintf(
			"unqualified secret_ref scheme %q is ambiguous: credstores %s both resolve it; qualify the reference as <scheme>+<name>:// (e.g., %s+%s://)",
			scheme, list, scheme, names[0],
		), SeverityError)
	}
}
