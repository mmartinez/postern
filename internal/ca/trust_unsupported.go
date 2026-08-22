//go:build !linux && !darwin

package ca

// defaultTrustDir on platforms without a trust-store integration errors with
// ErrTrustUnsupported so the CLI can surface a clear "manual install"
// message. Linux and macOS are first-class targets today; other platforms'
// trust-store integration is deferred.
func defaultTrustDir() (string, error) {
	return "", ErrTrustUnsupported
}

// installTrustAt and uninstallTrustAt reject work up front with
// ErrTrustUnsupported instead of half-writing an anchor no platform
// registration will ever pick up.
func installTrustAt(dir string, certPEM []byte) (string, error) {
	return "", ErrTrustUnsupported
}

func uninstallTrustAt(dir string) ([]string, error) {
	return nil, ErrTrustUnsupported
}
