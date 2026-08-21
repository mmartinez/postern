package ca

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// leafValidity is how long a minted leaf cert is valid for. Deliberately
// short so an exfiltrated leaf has a bounded blast radius: leaves are
// disposable, the CA is the durable trust anchor, and a re-minted leaf is
// signed by the same CA so the client needs no re-trust. Mint re-mints a
// cached leaf once it reaches NotAfter, so a long-running daemon cycles its
// leaves without operator intervention. The minter clamps this against the
// CA's own NotAfter, so the leaf can never outlive its issuer.
const leafValidity = 48 * time.Hour

// leafRenewBefore re-mints a cached leaf this long before its NotAfter, so a
// near-expiry leaf isn't handed to a client only to expire mid-connection.
const leafRenewBefore = 5 * time.Minute

// Minter issues per-host TLS leaf certificates signed by a postern CA and
// caches the results in an LRU keyed by SNI host. It is safe for concurrent
// use.
//
// Minter is intentionally narrow: it doesn't know about goproxy, the runtime
// config, or trust stores. That keeps the proxy layer free to inject its own
// fakes in tests.
type Minter struct {
	ca  *CA
	now func() time.Time

	mu    sync.Mutex
	cap   int
	lru   *list.List
	cache map[string]*list.Element
}

// cacheEntry pairs a cached *tls.Certificate with its cache key so the LRU
// list can also report which key it's about to evict.
type cacheEntry struct {
	host string
	cert *tls.Certificate
}

// NewMinter returns a Minter ready to issue leaves under root. capacity is
// the LRU cache size and must be positive. now defaults to time.Now when
// nil; tests should inject a fixed clock to make validity assertions stable.
func NewMinter(root *CA, capacity int, now func() time.Time) (*Minter, error) {
	if root == nil {
		return nil, errors.New("ca is required")
	}
	if capacity <= 0 {
		return nil, errors.New("capacity must be positive")
	}
	if now == nil {
		now = time.Now
	}
	return &Minter{
		ca:    root,
		now:   now,
		cap:   capacity,
		lru:   list.New(),
		cache: make(map[string]*list.Element, capacity),
	}, nil
}

// canonicalHost strips exactly one trailing dot so the RFC 3986 §3.2.2
// fully-qualified spelling of a host ("example.com.") shares one cache entry
// — and therefore one leaf — with its bare spelling. More than one trailing
// dot is left alone: that is a malformed name, not an FQDN.
//
// This helper is deliberately duplicated in internal/broker and internal/proxy:
// the packages are decoupled by design, and a one-line string op is not worth
// a new coupling point.
func canonicalHost(host string) string {
	return strings.TrimSuffix(host, ".")
}

// Mint returns a TLS certificate valid for host, signed by the wrapped CA.
// Repeated calls with the same host return the cached certificate (same
// pointer) until LRU eviction; a host sent in its RFC 3986 §3.2.2
// fully-qualified form ("example.com.") hits the same entry as its bare
// spelling, and the minted SAN carries the bare name — crypto/x509's hostname
// matching does not tolerate a dotted SAN. Hosts that parse as IP literals
// populate the IPAddresses SAN; everything else populates DNSNames.
func (m *Minter) Mint(host string) (*tls.Certificate, error) {
	host = canonicalHost(host)

	m.mu.Lock()
	defer m.mu.Unlock()

	if elem, ok := m.cache[host]; ok {
		entry := elem.Value.(*cacheEntry)
		// The cache has no TTL of its own, so guard against serving a leaf
		// that has aged past (or nearly to) its NotAfter: drop it and fall
		// through to re-mint rather than hand a client an expired cert.
		if m.now().Before(entry.cert.Leaf.NotAfter.Add(-leafRenewBefore)) {
			m.lru.MoveToFront(elem)
			return entry.cert, nil
		}
		m.lru.Remove(elem)
		delete(m.cache, host)
	}

	cert, err := m.mintLocked(host)
	if err != nil {
		return nil, err
	}

	elem := m.lru.PushFront(&cacheEntry{host: host, cert: cert})
	m.cache[host] = elem

	if m.lru.Len() > m.cap {
		victim := m.lru.Back()
		if victim != nil {
			m.lru.Remove(victim)
			delete(m.cache, victim.Value.(*cacheEntry).host)
		}
	}
	return cert, nil
}

// mintLocked synthesizes a fresh leaf cert for host. The caller must hold m.mu.
func (m *Minter) mintLocked(host string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	now := m.now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(m.ca.Cert.NotAfter) {
		notAfter = m.ca.Cert.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, m.ca.Cert, &priv.PublicKey, m.ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der, m.ca.Cert.Raw},
		PrivateKey:  priv,
		Leaf:        mustParse(der),
	}, nil
}

// mustParse re-parses a DER blob the package just generated. A parse failure
// here means the local x509 package itself is broken, which is unrecoverable
// — the alternative is to thread the error up through Mint, but the only
// trigger would be an out-of-memory condition we can't usefully report.
func mustParse(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("ca: parse self-generated leaf: %v", err))
	}
	return c
}
