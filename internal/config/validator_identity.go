package config

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/mmartinez/postern/internal/identity"
)

func (v *validator) checkAgents(cfg *Config) {
	if cfg.Proxy.ClientAuth == "required" {
		host, _, err := net.SplitHostPort(cfg.Proxy.Listen)
		ip := net.ParseIP(host)
		if err == nil && (ip == nil || !ip.IsLoopback()) {
			v.add("proxy.listen", "authenticated plaintext currently requires loopback", SeverityError)
		}
	}
	mode := cfg.Proxy.ClientAuth
	if mode != "" && mode != "off" && mode != "required" {
		v.add("proxy.client_auth", "client_auth must be required or off", SeverityError)
	}
	if mode != "required" && len(cfg.Agents) > 0 {
		v.add("agents", "agents require proxy.client_auth: required", SeverityError)
	}
	if mode != "required" {
		host, _, err := net.SplitHostPort(cfg.Proxy.Listen)
		ip := net.ParseIP(host)
		if err == nil && (ip == nil || !ip.IsLoopback()) {
			v.add("proxy.client_auth", "unauthenticated network listener has no agent identity security guarantee", SeverityWarning)
		}
	}
	names := make(map[string]bool)
	digests := make(map[string]bool)
	for i, a := range cfg.Agents {
		path := fmt.Sprintf("agents[%d]", i)
		if !identity.ValidName(a.Name) {
			v.add(path+".name", "invalid agent name", SeverityError)
		}
		if names[a.Name] {
			v.add(path+".name", "duplicate agent name", SeverityError)
		}
		names[a.Name] = true
		digest, err := hex.DecodeString(a.KeySHA256)
		if err != nil || len(digest) != 32 {
			v.add(path+".key_sha256", "verifier must decode to exactly 32 bytes", SeverityError)
			continue
		}
		if digests[string(digest)] {
			v.add(path+".key_sha256", "duplicate agent verifier", SeverityError)
		}
		digests[string(digest)] = true
	}
}
