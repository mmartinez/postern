package ca_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

// TestMintedLeaf_VerifiesAgainstCAOverHTTPS proves the full end-to-end
// happy path: a CA → leaf mint → TLS server using that leaf → HTTP client
// that trusts only the CA → 200 response with no in-flight cert errors.
//
// This is the integration counterpart to mint_test.go's pure-x509 checks;
// it catches the kinds of cert-chain shape bugs (missing intermediate,
// wrong SAN type, wrong ExtKeyUsage) that pass an isolated x509.Verify but
// still fail under a real TLS handshake.
func TestMintedLeaf_VerifiesAgainstCAOverHTTPS(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root, err := ca.Generate(now)
	require.NoError(t, err)
	minter, err := ca.NewMinter(root, 4, func() time.Time { return now })
	require.NoError(t, err)

	leaf, err := minter.Mint("127.0.0.1")
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	// httptest.Server.URL is keyed off 127.0.0.1; our IP SAN was minted
	// for the same literal so SNI/hostname matching succeeds without any
	// InsecureSkipVerify or ServerName override.
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	parsedURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", parsedURL.Hostname(),
		"sanity check: httptest server bound to the IP we minted for")
}

// TestMintedLeaf_DottedSNI_PassesRealHandshake proves the MITM shape for a
// trailing-dot CONNECT: the leaf Mint returns for the dotted SNI a Go client
// actually sends ("example.com.", RFC 3986 §3.2.2) completes a real TLS
// handshake against that same dotted ServerName. A leaf whose SAN carried
// the dot would fail here — crypto/x509 trims the dot from the client's
// name but not from certificate SANs.
func TestMintedLeaf_DottedSNI_PassesRealHandshake(t *testing.T) {
	t.Parallel()

	now := time.Now()
	root, err := ca.Generate(now)
	require.NoError(t, err)
	minter, err := ca.NewMinter(root, 4, func() time.Time { return now })
	require.NoError(t, err)

	leaf, err := minter.Mint("example.com.")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	type handshakeResult struct{ err error }
	serverErr := make(chan handshakeResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- handshakeResult{err}
			return
		}
		srv := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{*leaf},
			MinVersion:   tls.VersionTLS12,
		})
		serverErr <- handshakeResult{err: srv.HandshakeContext(context.Background())}
	}()

	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	client := tls.Client(conn, &tls.Config{
		RootCAs:    pool,
		ServerName: "example.com.",
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, client.HandshakeContext(context.Background()),
		"leaf minted via dotted SNI must validate against the dotted ServerName")

	select {
	case res := <-serverErr:
		require.NoError(t, res.err, "server-side handshake must also succeed")
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not complete")
	}
}
