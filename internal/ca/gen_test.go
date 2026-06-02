package ca_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

// genFixed pins the CA creation time to a stable value so validity assertions
// don't drift with wall-clock.
func genFixed(t *testing.T) *ca.CA {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := ca.Generate(now)
	require.NoError(t, err)
	require.NotNil(t, c)
	return c
}

func TestGenerate_ECDSAP256(t *testing.T) {
	t.Parallel()
	c := genFixed(t)

	require.NotNil(t, c.PrivateKey, "private key must be present")
	require.Equal(t, elliptic.P256(), c.PrivateKey.Curve, "curve must be P-256")
}

func TestGenerate_CertificateShape(t *testing.T) {
	t.Parallel()
	c := genFixed(t)

	require.True(t, c.Cert.IsCA, "BasicConstraints CA must be true")
	require.True(t, c.Cert.BasicConstraintsValid, "BasicConstraints must be marked valid")
	require.NotZero(t, c.Cert.SerialNumber.Sign(), "serial number must be non-zero")

	// Key usage must include cert sign so the cert can issue leaves.
	require.NotZero(t, c.Cert.KeyUsage&x509.KeyUsageCertSign, "KeyUsageCertSign must be set")

	// Self-signed: issuer == subject.
	require.Equal(t, c.Cert.Subject.String(), c.Cert.Issuer.String())
}

func TestGenerate_TenYearValidity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := ca.Generate(now)
	require.NoError(t, err)

	// Validity window is ~10 years; allow a small slack for jitter / leap days.
	gotYears := c.Cert.NotAfter.Sub(c.Cert.NotBefore).Hours() / 24 / 365
	require.InDelta(t, 10.0, gotYears, 0.05, "CA should be valid for ~10 years")

	require.False(t, c.Cert.NotBefore.After(now), "NotBefore must be at or before now")
	require.True(t, c.Cert.NotAfter.After(now), "NotAfter must be after now")
}

func TestGenerate_SelfSignatureVerifies(t *testing.T) {
	t.Parallel()
	c := genFixed(t)

	// The CA must verify against itself when used as the lone trust anchor.
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)

	_, err := c.Cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err)
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := genFixed(t)

	require.NoError(t, c.Save(dir))

	// File permissions: ca.pem and ca.key must be 0600, parent dir 0700.
	pemInfo, err := os.Stat(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), pemInfo.Mode().Perm())

	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())

	// PEM block types are correct.
	pemBytes, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	keyBytes, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(keyBytes)
	require.NotNil(t, keyBlock)
	require.Equal(t, "EC PRIVATE KEY", keyBlock.Type)

	// Round-trip: Load returns a CA with the same serial.
	loaded, err := ca.Load(dir)
	require.NoError(t, err)
	require.Equal(t, c.Cert.SerialNumber, loaded.Cert.SerialNumber)
}

func TestSave_FailsWhenParentIsFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	// Treat the regular file as a parent dir → MkdirAll must fail.
	err := genFixed(t).Save(filepath.Join(blocker, "postern"))
	require.Error(t, err)
}

func TestSave_CreatesParentDirWith0700(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "nested", "postern")
	c := genFixed(t)

	require.NoError(t, c.Save(dir))

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

func TestLoad_MissingDir(t *testing.T) {
	t.Parallel()
	_, err := ca.Load(filepath.Join(t.TempDir(), "no-such-dir"))
	require.Error(t, err)
}

func TestLoad_MissingKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := genFixed(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), c.CertPEM, 0o600))
	// No ca.key written.

	_, err := ca.Load(dir)
	require.Error(t, err)
}

func TestLoad_MalformedCertPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := genFixed(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("not a pem"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), c.KeyPEM, 0o600))

	_, err := ca.Load(dir)
	require.Error(t, err)
}

func TestLoad_WrongCertPEMType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := genFixed(t)
	wrong := []byte("-----BEGIN PUBLIC KEY-----\nQUE=\n-----END PUBLIC KEY-----\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), wrong, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), c.KeyPEM, 0o600))

	_, err := ca.Load(dir)
	require.Error(t, err)
}

func TestLoad_MalformedKeyPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := genFixed(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), c.CertPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), []byte("nope"), 0o600))

	_, err := ca.Load(dir)
	require.Error(t, err)
}

func TestLoad_WrongKeyPEMType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := genFixed(t)
	// Use a "CERTIFICATE" PEM block in the key slot — it parses as a PEM
	// block but Load must reject it because the type is wrong. We avoid
	// the literal "RSA PRIVATE KEY" marker so gitleaks doesn't flag this
	// test fixture as a secret.
	wrong := []byte("-----BEGIN CERTIFICATE-----\nQUE=\n-----END CERTIFICATE-----\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), c.CertPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), wrong, 0o600))

	_, err := ca.Load(dir)
	require.Error(t, err)
}
