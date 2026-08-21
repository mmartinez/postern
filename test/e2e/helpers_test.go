//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// boundAddrRe extracts the actual bound address from the server's
// "proxy listening" log line. Test configs declare `listen: 127.0.0.1:0`
// so the OS assigns the port at bind time (no allocate-then-close race);
// the real address is only observable here.
var boundAddrRe = regexp.MustCompile(`proxy listening addr=(\S+)`)

const clientSecretEnv = "POSTERN_E2E_CLIENT_SECRET"

// readyTimeout bounds how long startPostern waits for the listener.
const readyTimeout = 15 * time.Second

// caCommonName is the Subject CN of the CA the tests plant under
// $HOME/.postern so the server finds it via ca.Load; clients assert the
// MITM leaf chains to it.
const caCommonName = "postern e2e root"

// syncBuffer is a race-safe sink for subprocess output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// env is the per-test isolated environment: a temp HOME holding the planted
// CA, and the self-signed serving cert every local TLS stub presents.
type env struct {
	home        string
	caPEM       []byte // postern CA; clients trust only this
	stubCert    tls.Certificate
	stubCertPEM []byte // served by upstream/IdP stubs; postern trusts via SSL_CERT_FILE
}

func newEnv(t *testing.T) *env {
	t.Helper()

	home := t.TempDir()
	caPEM := plantCA(t, home)
	cert, certPEM := selfSignedServingCert(t)

	// Go's crypto/x509 reads this env var for the process-wide root pool; the
	// system trust store is never touched.
	bundle := append(append([]byte{}, caPEM...), certPEM...)
	require.NoError(t, os.WriteFile(filepath.Join(home, "trust-bundle.pem"), bundle, 0o600))

	return &env{home: home, caPEM: caPEM, stubCert: cert, stubCertPEM: certPEM}
}

// plantCA generates an ECDSA P-256 self-signed CA and writes it where the
// server expects it ($HOME/.postern/ca.pem + ca.key, both 0600, dir 0700),
// mirroring ca.Generate/ca.Save. `postern ca install` is deliberately never
// invoked: the CA is trusted via SSL_CERT_FILE only.
func plantCA(t *testing.T, home string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caCommonName, Organization: []string{"postern"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := filepath.Join(home, ".postern")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600))
	return certPEM
}

// selfSignedServingCert mints the cert every local TLS stub serves. It covers
// 127.0.0.1 and localhost so postern's upstream/token dials verify regardless
// of which spelling the CONNECT target uses.
func selfSignedServingCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "postern e2e stub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, certPEM
}

// startTLSStub runs an httptest server on 127.0.0.1 presenting the shared
// stub cert over TLS.
func startTLSStub(t *testing.T, e *env, h http.Handler) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{e.stubCert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// idpStub is the OAuth2 token endpoint. Every POST mints a fresh token and
// is counted, so tests can assert exactly how many exchanges happened.
type idpStub struct {
	srv    *httptest.Server
	URL    string
	mu     sync.Mutex
	count  int64
	tokens []string
}

func startIdP(t *testing.T, e *env) *idpStub {
	t.Helper()

	s := &idpStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.count++
		tok := fmt.Sprintf("e2e-token-%d", s.count)
		s.tokens = append(s.tokens, tok)
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": tok,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	srv := startTLSStub(t, e, mux)
	s.srv = srv
	s.URL = srv.URL + "/token"
	return s
}

// Fetches reports how many token exchanges the stub served.
func (s *idpStub) Fetches() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Token returns the nth minted token (1-based).
func (s *idpStub) Token(n int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[n-1]
}

// upstreamStub records every forwarded request's Authorization header and
// Host so tests can assert injection and (non-)contact.
type upstreamStub struct {
	srv   *httptest.Server
	port  string
	mu    sync.Mutex
	auth  []string
	hosts []string
}

func startUpstream(t *testing.T, e *env) *upstreamStub {
	t.Helper()

	u := &upstreamStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.auth = append(u.auth, r.Header.Get("Authorization"))
		u.hosts = append(u.hosts, r.Host)
		u.mu.Unlock()
		_, _ = w.Write([]byte("upstream-ok\n"))
	})
	u.srv = startTLSStub(t, e, mux)
	u.port = u.srv.URL[strings.LastIndexByte(u.srv.URL, ':')+1:]
	return u
}

func (u *upstreamStub) Requests() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.auth)
}

func (u *upstreamStub) AuthHeader(i int) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.auth[i]
}

func (u *upstreamStub) Hosts() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.hosts...)
}

// renderConfig writes the YAML config for one scenario. The proxy listens
// on 127.0.0.1:0 so the OS assigns the port at bind time; the tests read
// the actual address from the server's log (see boundAddrRe). ruleHost is
// the brokered host; onNoMatch is "passthrough" or "block".
func renderConfig(tokenURL, ruleHost, onNoMatch string) []byte {
	return []byte(fmt.Sprintf(`credstores:
  - name: e2e-idp
    provider: oauth2
    token:
      source: env
      env_var: %s
    settings:
      token_url: %s
      client_id: e2e-client
      grant_type: client_credentials

proxy:
  cache_ttl: 30s
  listen: 127.0.0.1:0
  on_no_match: %s

rules:
  - host: %s
    secret_ref: oauth2://e2e-idp
    inject:
      type: header
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
`, clientSecretEnv, tokenURL, onNoMatch, ruleHost))
}

// posternProc is one running `postern server` subprocess.
type posternProc struct {
	cfgPath  string
	addr     string // 127.0.0.1:<port>
	proxyURL string
	logs     *syncBuffer
	done     chan struct{} // closed once cmd.Wait has reaped the process
	mu       sync.Mutex
	waitErr  error
	cmd      *exec.Cmd
}

// startPostern launches the compiled binary as a subprocess with a fully
// isolated environment (temp HOME, bundled SSL_CERT_FILE, no inherited proxy
// vars), waits for its listener, and registers shutdown cleanup.
func startPostern(t *testing.T, e *env, cfg []byte) *posternProc {
	t.Helper()

	cfgPath := filepath.Join(e.home, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, cfg, 0o600))

	logs := &syncBuffer{}
	cmd := exec.Command(posternBin, "server", "--config", cfgPath, "--log-level", "debug")
	cmd.Dir = e.home
	cmd.Env = []string{
		"HOME=" + e.home,
		"PATH=" + os.Getenv("PATH"),
		"SSL_CERT_FILE=" + filepath.Join(e.home, "trust-bundle.pem"),
		clientSecretEnv + "=e2e-client-secret",
	}
	cmd.Stdout = logs
	cmd.Stderr = logs

	p := &posternProc{
		cfgPath: cfgPath,
		logs:    logs,
		done:    make(chan struct{}),
		cmd:     cmd,
	}
	require.NoError(t, cmd.Start())
	go func() {
		p.mu.Lock()
		p.waitErr = cmd.Wait()
		p.mu.Unlock()
		close(p.done)
	}()
	t.Cleanup(p.stop)

	waitReady(t, p)
	return p
}

// waitReady polls the subprocess log for the bound listener address and
// confirms it accepts connections. Polls every 10ms against a generous
// deadline; no fixed startup delay.
func waitReady(t *testing.T, p *posternProc) {
	t.Helper()

	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			t.Fatalf("postern exited during startup: %v\nlogs:\n%s", p.waitResult(), p.logs.String())
		default:
		}
		if m := boundAddrRe.FindStringSubmatch(p.logs.String()); m != nil {
			p.addr = m[1]
			p.proxyURL = "http://" + p.addr
			conn, err := net.DialTimeout("tcp", p.addr, 250*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("postern not listening within %v\nlogs:\n%s", readyTimeout, p.logs.String())
}

func (p *posternProc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		<-p.done
	}
}

// waitResult blocks until the subprocess has been reaped and returns its
// exit error (nil on clean shutdown).
func (p *posternProc) waitResult() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waitErr
}

// rewriteConfig atomically replaces the server's config file the way an
// editor does (write temp + rename) so the hot-reload watcher sees it.
func (p *posternProc) rewriteConfig(t *testing.T, cfg []byte) {
	t.Helper()

	tmp := p.cfgPath + ".new"
	require.NoError(t, os.WriteFile(tmp, cfg, 0o600))
	require.NoError(t, os.Rename(tmp, p.cfgPath))
}

// proxiedClient returns an HTTP client that routes through the postern
// subprocess and trusts only postern's planted CA for MITM'd TLS.
func proxiedClient(t *testing.T, proxyURL string, caPEM []byte) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM), "postern CA PEM must parse")
	proxyU, err := url.Parse(proxyURL)
	require.NoError(t, err)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyU),
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig:     &tls.Config{RootCAs: pool},
		},
		Timeout: 15 * time.Second,
	}
}

// get performs a GET through the client and returns status + body.
func get(t *testing.T, c *http.Client, target string) (int, string) {
	t.Helper()

	resp, err := c.Get(target)
	if err != nil {
		return 0, fmt.Sprintf("transport error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}
