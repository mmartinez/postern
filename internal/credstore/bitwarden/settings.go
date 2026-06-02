package bitwarden

import (
	"fmt"
	"net/url"
)

// Recognized provider-interpreted config keys. Both are optional.
const (
	keyServerURL = "server_url"
	keyBwsPath   = "bws_path"
)

// settings is the typed view of a bitwarden credstore's provider-interpreted
// config map. Parsing happens at one boundary (parseSettings) so the config-key
// strings live in exactly one place and the rest of the package stays typed.
type settings struct {
	serverURL string // self-hosted base URL; empty selects Bitwarden cloud
	bwsPath   string // explicit bws binary path; empty looks bws up on PATH
}

// parseSettings turns the provider-interpreted config map into typed settings.
// It rejects unknown keys and a malformed server_url so a typo is a loud error
// rather than a silent fallback to the wrong (cloud) server, which for a
// self-hosted deployment would resolve against the wrong host.
func parseSettings(m map[string]string) (settings, error) {
	var s settings
	for k, v := range m {
		switch k {
		case keyServerURL:
			s.serverURL = v
		case keyBwsPath:
			s.bwsPath = v
		default:
			return settings{}, fmt.Errorf("unknown setting %q (recognized: %s, %s)", k, keyBwsPath, keyServerURL)
		}
	}
	if s.serverURL != "" {
		if err := validateServerURL(s.serverURL); err != nil {
			return settings{}, err
		}
	}
	return s, nil
}

// validateServerURL rejects a server_url that is not an absolute http(s) URL.
func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid server_url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid server_url %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid server_url %q: missing host", raw)
	}
	return nil
}
