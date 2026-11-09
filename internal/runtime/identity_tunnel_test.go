package runtime_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
	"github.com/mmartinez/postern/internal/runtime"
)

func TestRevocationClosesBothPassthroughSockets(t *testing.T) {
	t.Parallel()
	for _, encrypted := range []bool{false, true} {
		name := "plaintext"
		if encrypted {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) { checkRevokedPassthrough(t, encrypted) })
	}
}

func checkRevokedPassthrough(t *testing.T, encrypted bool) {
	t.Helper()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	e := broker.NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	root := fixtureCA(t)
	var names []string
	if encrypted {
		names = []string{"localhost"}
	}
	rt, err := runtime.New(runtime.Options{CA: root, ListenerTLSNames: names, Addr: "127.0.0.1:0", Authenticator: e, ShouldIntercept: func(string) bool { return false }})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	defer func() { cancel(); require.NoError(t, <-done) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	var c net.Conn
	if encrypted {
		pool := x509.NewCertPool()
		pool.AddCert(root.Cert)
		c, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", rt.Addr(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	} else {
		c, err = net.DialTimeout("tcp", rt.Addr(), time.Second)
	}
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	// Never print the request or its authentication value on a test failure.
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", l.Addr(), l.Addr(), base64.StdEncoding.EncodeToString([]byte("agent:"+key)))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var upstream net.Conn
	select {
	case upstream = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("upstream not accepted")
	}
	defer func() { _ = upstream.Close() }()
	_, err = c.Write([]byte("ping"))
	require.NoError(t, err)
	var payload [4]byte
	_, err = io.ReadFull(upstream, payload[:])
	require.NoError(t, err)
	require.Equal(t, "ping", string(payload[:]))
	_, err = upstream.Write([]byte("pong"))
	require.NoError(t, err)
	_, err = io.ReadFull(c, payload[:])
	require.NoError(t, err)
	require.Equal(t, "pong", string(payload[:]))
	started := make(chan struct{}, 2)
	results := make(chan error, 4)
	for _, conn := range []net.Conn{c, upstream} {
		go func() {
			for {
				if _, err := conn.Write([]byte("continuous tunnel traffic")); err != nil {
					results <- err
					return
				}
			}
		}()
		go func() {
			var buf [1024]byte
			first := true
			for {
				n, err := conn.Read(buf[:])
				if n > 0 && first {
					first = false
					started <- struct{}{}
				}
				if err != nil {
					results <- err
					return
				}
			}
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("bidirectional traffic did not start")
		}
	}
	require.NoError(t, e.Publish(nil, nil))
	for range 4 {
		select {
		case err := <-results:
			var timeout net.Error
			if errors.As(err, &timeout) {
				require.False(t, timeout.Timeout(), "relay waited for timeout after revocation")
			}
		case <-time.After(time.Second):
			t.Fatal("revocation leaked a busy relay")
		}
	}
}
