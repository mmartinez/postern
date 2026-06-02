package token

import (
	keyringlib "github.com/99designs/keyring"
)

// backendPreference ranks the OS keyring backends from most to least
// preferred when more than one is available on the host. Order matches the
// token-resolution intent: native OS stores first, file-encrypted fallback
// last.
//
// Anything returned by keyring.AvailableBackends that is not in this slice is
// still surfaced (appended at the end of the preference list) so we don't
// silently mask a newly introduced backend type.
var backendPreference = []keyringlib.BackendType{
	keyringlib.KeychainBackend,
	keyringlib.WinCredBackend,
	keyringlib.SecretServiceBackend,
	keyringlib.KWalletBackend,
	keyringlib.KeyCtlBackend,
	keyringlib.PassBackend,
	keyringlib.FileBackend,
}

// Probe returns the label of the preferred OS keyring backend on the current
// host, or "none" when no backend is available. The detection delegates to
// keyring.AvailableBackends, which probes runtime conditions (D-Bus session,
// keychain helper, Windows credential manager) rather than reading GOOS — so
// a Linux devcontainer with no D-Bus is correctly reported as "none" even
// though the binary was built for linux/amd64.
//
// Labels are stable strings used by `postern token status` output and by
// audit logs; they are not paths to behavior, so callers should not branch
// on them beyond reporting.
func Probe() string {
	available := keyringlib.AvailableBackends()
	if len(available) == 0 {
		return "none"
	}
	present := make(map[keyringlib.BackendType]struct{}, len(available))
	for _, b := range available {
		present[b] = struct{}{}
	}
	for _, b := range backendPreference {
		if _, ok := present[b]; ok {
			return string(b)
		}
	}
	// Unknown backend type — surface it rather than masking with "none" so
	// a future keyring release that adds a new backend doesn't make Postern
	// silently behave as if nothing was available.
	return string(available[0])
}
