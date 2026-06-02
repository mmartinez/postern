//go:build !linux

package ca

// defaultTrustDir on non-Linux builds errors with ErrTrustUnsupported so the
// CLI can surface a clear "manual install" message. Only Linux is a
// first-class target today; macOS and Windows trust-store integration is
// deferred.
func defaultTrustDir() (string, error) {
	return "", ErrTrustUnsupported
}
