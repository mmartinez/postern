package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"
)

// waitForEnrollment confirms the live server accepts this exact incarnation.
// Probes terminate locally at the proxy and never invoke routing or a resolver.
func waitForEnrollment(ctx context.Context, endpoint *url.URL, name, key, caPath string) error {
	// The watcher can take 5s to poll, then 100ms to debounce. Leave room
	// for applying the snapshot and a bounded (1s) confirmation request.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	if caPath != "" {
		pem, err := os.ReadFile(caPath) //nolint:gosec // operator-selected public CA bundle, never credential material
		if err != nil {
			return errors.New("public CA bundle is not readable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("public CA bundle has no certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	target := *endpoint
	target.Path = "/.well-known/postern/client-auth"
	target.User = nil
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, target.String(), http.NoBody)
		if err != nil {
			return errors.New("invalid enrollment probe endpoint")
		}
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(name+":"+key)))
		response, err := client.Do(req)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("server did not confirm enrollment; verify the running server, reload diagnostics and proxy trust settings; the verifier remains committed")
		case <-ticker.C:
		}
	}
}
