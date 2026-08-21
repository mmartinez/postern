package ca_test

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

func newMinter(t *testing.T, capacity int) (*ca.CA, *ca.Minter) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root, err := ca.Generate(now)
	require.NoError(t, err)
	m, err := ca.NewMinter(root, capacity, func() time.Time { return now })
	require.NoError(t, err)
	return root, m
}

func TestMint_LeafSANContainsHost(t *testing.T) {
	t.Parallel()
	_, m := newMinter(t, 4)

	leaf, err := m.Mint("example.com")
	require.NoError(t, err)
	require.NotNil(t, leaf)
	require.NotEmpty(t, leaf.Certificate, "tls.Certificate must hold at least one DER block")

	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)
	require.Contains(t, parsed.DNSNames, "example.com")
}

func TestMint_IPHostUsesIPSAN(t *testing.T) {
	t.Parallel()
	_, m := newMinter(t, 4)

	leaf, err := m.Mint("127.0.0.1")
	require.NoError(t, err)

	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)

	var found bool
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			found = true
			break
		}
	}
	require.True(t, found, "IP literal hosts should populate IPAddresses SAN, not DNSNames")
}

func TestMint_LeafSignedByCAAndExpiresBeforeCA(t *testing.T) {
	t.Parallel()
	root, m := newMinter(t, 4)

	leaf, err := m.Mint("example.com")
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)

	// Leaf must be signed by the CA — verify with the CA as the lone root.
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	_, err = parsed.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     "example.com",
		CurrentTime: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)

	require.True(t, parsed.NotAfter.Before(root.Cert.NotAfter),
		"leaf expiry must precede CA expiry")
}

func TestMint_CacheHitReturnsSameCert(t *testing.T) {
	t.Parallel()
	_, m := newMinter(t, 4)

	first, err := m.Mint("example.com")
	require.NoError(t, err)
	second, err := m.Mint("example.com")
	require.NoError(t, err)

	// Pointer equality is the cleanest "cache hit" assertion — a freshly
	// minted cert would be a different *tls.Certificate even if cosmetically
	// similar.
	require.Same(t, first, second)
}

// A cached leaf that has reached its NotAfter must be re-minted on the next
// Mint, not served stale: the cache has no TTL of its own, so without this a
// long-running daemon would hand a client an expired leaf once a hot host's
// leaf aged out, breaking the MITM handshake.
func TestMint_ReMintsExpiredCachedLeaf(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	root, err := ca.Generate(base)
	require.NoError(t, err)
	m, err := ca.NewMinter(root, 4, func() time.Time { return clock })
	require.NoError(t, err)

	first, err := m.Mint("example.com")
	require.NoError(t, err)

	// Within validity the cache returns the same pointer.
	same, err := m.Mint("example.com")
	require.NoError(t, err)
	require.Same(t, first, same, "cache hit within validity must return the same cert")

	// Past the leaf's NotAfter the cache must re-mint.
	clock = first.Leaf.NotAfter.Add(time.Hour)
	fresh, err := m.Mint("example.com")
	require.NoError(t, err)
	require.NotSame(t, first, fresh, "an expired cached leaf must be re-minted")
	require.True(t, fresh.Leaf.NotAfter.After(clock), "re-minted leaf must be valid at the current time")
}

func TestMint_CacheEvictsLRUEntry(t *testing.T) {
	t.Parallel()
	_, m := newMinter(t, 2)

	a1, err := m.Mint("a.example.com")
	require.NoError(t, err)
	_, err = m.Mint("b.example.com")
	require.NoError(t, err)
	// Adding a third entry evicts the LRU (a).
	_, err = m.Mint("c.example.com")
	require.NoError(t, err)

	a2, err := m.Mint("a.example.com")
	require.NoError(t, err)
	require.NotSame(t, a1, a2, "evicted entry should be re-minted, not returned from cache")
}

// A host sent with an RFC 3986 §3.2.2 trailing dot ("example.com.") is the
// same logical host as its bare spelling: Mint must key both to one LRU
// entry and mint one leaf whose SAN carries the bare name — crypto/x509's
// hostname matching does not tolerate a dotted SAN, so a leaf minted under
// the dotted spelling would fail exactly the Go clients whose CONNECT it
// was minted for.
func TestMint_TrailingDotSharesLeafAndSANIsBare(t *testing.T) {
	t.Parallel()
	_, m := newMinter(t, 4)

	dotted, err := m.Mint("example.com.")
	require.NoError(t, err)
	bare, err := m.Mint("example.com")
	require.NoError(t, err)
	require.Same(t, dotted, bare, "dotted and bare spellings must share one cached leaf")

	parsed, err := x509.ParseCertificate(dotted.Certificate[0])
	require.NoError(t, err)
	require.Contains(t, parsed.DNSNames, "example.com")
	require.NotContains(t, parsed.DNSNames, "example.com.",
		"a trailing-dot SAN would fail Go client hostname verification")
}

func TestNewMinter_RejectsNonPositiveCapacity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root, err := ca.Generate(now)
	require.NoError(t, err)

	_, err = ca.NewMinter(root, 0, nil)
	require.Error(t, err)
}

func TestNewMinter_RejectsNilCA(t *testing.T) {
	t.Parallel()
	_, err := ca.NewMinter(nil, 4, nil)
	require.Error(t, err)
}

func TestNewMinter_DefaultClock(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root, err := ca.Generate(now)
	require.NoError(t, err)

	m, err := ca.NewMinter(root, 1, nil)
	require.NoError(t, err)

	leaf, err := m.Mint("example.com")
	require.NoError(t, err)
	require.NotNil(t, leaf)
}
