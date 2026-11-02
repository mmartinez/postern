package runtime_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/runtime"
)

type approverFunc func(ctx context.Context, reason string) (broker.Outcome, error)

func (f approverFunc) Approve(ctx context.Context, reason string) (broker.Outcome, error) {
	return f(ctx, reason)
}

type countingResolver struct{ calls atomic.Int64 }

func (r *countingResolver) Resolve(context.Context, string, string) (string, error) {
	r.calls.Add(1)
	return "sk-secret", nil
}

// TestApprovalFailsClosedWhenClientLeavesDuringPrompt drives an upload larger
// than the hangup watch's read-ahead through the real listener and MITM. The
// client leaves while the dialog is open and the user then approves: the
// request must fail closed without resolving or reaching the upstream.
func TestApprovalFailsClosedWhenClientLeavesDuringPrompt(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	t.Cleanup(upstream.Close)
	target := strings.TrimPrefix(upstream.URL, "https://")
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	prompts := make(chan chan broker.Outcome, 1)
	gate := broker.NewGate(t.Context(), broker.GateConfig{
		Approver: approverFunc(func(ctx context.Context, _ string) (broker.Outcome, error) {
			answer := make(chan broker.Outcome, 1)
			prompts <- answer
			select {
			case o := <-answer:
				return o, nil
			case <-ctx.Done():
				return broker.OutcomeUnavailable, ctx.Err()
			}
		}),
	})
	res := &countingResolver{}
	rule := broker.Rule{
		Host:      upstreamURL.Hostname(),
		SecretRef: "test://secret",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		Approval:  &config.Approval{},
	}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{rule}), res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // goproxy closes it

	// Tell the test when the real watch reports the hangup, and what the hook
	// finally returned.
	left := make(chan struct{})
	var leftOnce sync.Once
	returned := make(chan int, 1)
	observed := func(req *http.Request) *http.Response {
		if watch := broker.HangupWatchFrom(req.Context()); watch != nil {
			req = req.WithContext(broker.WithHangupWatch(req.Context(), func(onHangup func()) func() {
				return watch(func() {
					onHangup()
					leftOnce.Do(func() { close(left) })
				})
			}))
		}
		resp := hook(req)
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		returned <- code
		return resp
	}

	root := fixtureCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	rt, err := runtime.New(runtime.Options{
		CA:                 root,
		Addr:               "127.0.0.1:0",
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		PreUpstreamHandler: observed,
	})
	require.NoError(t, err)
	startRuntime(t, rt)

	conn, raw := dialIntercepted(t, rt.Addr(), root, target)
	const bodySize = 256 << 10
	sent := make(chan int, bodySize/(16<<10))
	go func() {
		defer close(sent)
		if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, bodySize); err != nil {
			return
		}
		chunk := make([]byte, 16<<10)
		for total := 0; total < bodySize; total += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
			sent <- total + len(chunk)
		}
	}()

	answer := waitFor(t, prompts, "the approval dialog")
	// Twice the read-ahead cap is past what the watch buffers, so any
	// unread remainder sits in front of the FIN.
	for n := 0; n < 128<<10; {
		var ok bool
		select {
		case n, ok = <-sent:
			require.True(t, ok, "upload stopped after fewer than 128 KiB")
		case <-time.After(2 * time.Second):
			t.Fatal("timed out sending the upload")
		}
	}
	require.NoError(t, raw.Close())
	waitFor(t, left, "the hangup watch to report the client leaving")
	answer <- broker.OutcomeApproved

	require.Equal(t, http.StatusBadGateway, waitFor(t, returned, "the hook to return"))
	require.Zero(t, res.calls.Load(), "an abandoned request must not resolve the credential")
	require.Zero(t, upstreamHits.Load(), "an abandoned request must not reach the upstream")
}
