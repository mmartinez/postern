// Package ca generates and persists the local certificate authority that
// postern's MITM proxy uses to mint per-host leaf certificates. The CA is an
// ECDSA P-256 keypair, self-signed for ten years, stored on disk under
// ~/.postern with 0600 file mode and 0700 directory mode.
//
// Only the CA generation, persistence, and leaf minting live in this package.
// System-trust integration lives in trust_<goos>.go behind build tags so
// non-target platforms get a clear "unsupported" error instead of a partial
// install.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	// FileName for the PEM-encoded CA certificate inside the CA directory.
	caCertFile = "ca.pem"
	// FileName for the PEM-encoded CA private key inside the CA directory.
	caKeyFile = "ca.key"

	caValidYears = 10

	// Secrets must not be world-readable.
	caFileMode os.FileMode = 0o600
	caDirMode  os.FileMode = 0o700
)

// CA bundles a self-signed CA certificate with the private key that issued it.
// Callers obtain a CA from Generate (in-memory) or Load (on-disk) and use
// Mint to issue per-host leaf certificates.
type CA struct {
	// Cert is the parsed x509 representation of the self-signed CA.
	Cert *x509.Certificate
	// PrivateKey is the issuing key; concrete type is *ecdsa.PrivateKey.
	// It is exposed as the generic crypto.Signer surface so consumers don't
	// have to type-assert when they only need to sign.
	PrivateKey *ecdsa.PrivateKey
	// CertPEM is the PEM-encoded CA certificate, ready to write to disk
	// or hand to a trust store.
	CertPEM []byte
	// KeyPEM is the PEM-encoded EC private key, ready to write to disk.
	KeyPEM []byte
}

// CertPath returns the path of the persisted CA certificate under dir
// (the directory's own absoluteness is preserved — pass an absolute dir
// when you need an absolute result). Callers (bootstrap snippets,
// trust-store installers) use this to refer to the same file ca.Load
// and ca.Save use, without re-stating the "ca.pem" filename.
func CertPath(dir string) string { return filepath.Join(dir, caCertFile) }

// Generate produces a fresh ECDSA P-256 self-signed CA whose validity window
// runs from now to now + 10 years. The CA is returned in memory only; call
// Save to persist it.
func Generate(now time.Time) (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Postern Local CA",
			Organization: []string{"Postern"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(caValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	return &CA{
		Cert:       cert,
		PrivateKey: priv,
		CertPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	}, nil
}

// Save writes the CA certificate and private key to dir, creating dir (and
// any missing parents) with 0700 permissions. The files themselves are 0600.
// An existing CA in the same directory is overwritten; callers wanting
// stricter semantics should check for the files first.
func (c *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, caDirMode); err != nil {
		return fmt.Errorf("create ca dir: %w", err)
	}
	// MkdirAll respects umask for newly-created dirs, so re-chmod the
	// final segment to guarantee 0700 on systems where the umask masked
	// off owner-write or group-read bits.
	if err := os.Chmod(dir, caDirMode); err != nil {
		return fmt.Errorf("chmod ca dir: %w", err)
	}

	if err := writeFileMode(filepath.Join(dir, caCertFile), c.CertPEM, caFileMode); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	if err := writeFileMode(filepath.Join(dir, caKeyFile), c.KeyPEM, caFileMode); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	return nil
}

// Load reads a previously-saved CA from dir and reconstructs the in-memory
// CA struct. It returns an error if either file is missing or malformed.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile)) //nolint:gosec // user-supplied path is intentional
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)
	if err := checkKeyPerms(keyPath); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // user-supplied path is intentional
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("ca cert: invalid PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.New("ca key: invalid PEM block")
	}
	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}

	return &CA{
		Cert:       cert,
		PrivateKey: priv,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
	}, nil
}

// DefaultDir returns ~/.postern, the canonical CA directory. It errors when
// the user's home directory cannot be resolved.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".postern"), nil
}

// checkKeyPerms refuses a CA key file readable by group or other. Save writes
// the key 0600, so any looser mode signals tampering or a careless chmod; the
// key is the root of postern's MITM trust, so Load fails closed rather than
// use it. The check is skipped on Windows, where Go synthesizes Unix
// permission bits that do not reflect the real ACL.
func checkKeyPerms(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat ca key: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("ca key %s has insecure permissions %#o: must be 0600 (no group or other access); run `chmod 600 %s`", path, perm, path)
	}
	return nil
}

// writeFileMode writes data to path with the given mode atomically enough for
// our purposes — os.WriteFile honors the mode argument on create but not on
// overwrite, so chmod afterwards to guarantee the requested permissions.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
