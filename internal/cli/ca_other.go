//go:build !linux

package cli

// caInstalledFormat reports where ca install anchored the CA.
const caInstalledFormat = "Installed trust anchor at %s\nYou can now point HTTPS_PROXY at postern.\n"
