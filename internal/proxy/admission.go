package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/mmartinez/postern/internal/identity"
)

type closeSlot struct {
	mu     sync.Mutex
	closer io.Closer
	closed bool
}

func (s *closeSlot) close() {
	s.mu.Lock()
	s.closed = true
	c := s.closer
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (s *closeSlot) attach(c io.Closer) {
	s.mu.Lock()
	s.closer = c
	closed := s.closed
	s.mu.Unlock()
	if closed {
		_ = c.Close()
	}
}

type admissionBody struct {
	io.ReadCloser
	release func()
}

func (b *admissionBody) Close() error {
	defer b.release()
	return b.ReadCloser.Close()
}

func (b *admissionBody) Write(p []byte) (int, error) {
	if w, ok := b.ReadCloser.(io.Writer); ok {
		return w.Write(p)
	}
	return 0, errors.New("upstream response is not writable")
}

type admissionConn struct {
	net.Conn
	release func()
}

func (c *admissionConn) Close() error { defer c.release(); return c.Conn.Close() }
func (c *admissionConn) CloseRead() error {
	if half, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return half.CloseRead()
	}
	return c.Close()
}

func (c *admissionConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}

func installAdmission(gp *goproxy.ProxyHttpServer, auth Authenticator) {
	if auth == nil {
		return
	}
	gp.OnRequest().DoFunc(func(req *http.Request, pc *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		pc.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			slot := &closeSlot{}
			ctx, release, ok := auth.Admit(req.Context(), identity.FromContext(req.Context()), slot.close)
			if !ok {
				return nil, errors.New("upstream authorization refused")
			}
			resp, err := gp.Tr.RoundTrip(req.WithContext(ctx))
			if err != nil {
				release()
				return nil, err
			}
			slot.attach(resp.Body)
			resp.Body = &admissionBody{ReadCloser: resp.Body, release: release}
			return resp, nil
		})
		return req, nil
	})
	// Explicit request-aware dialing prevents the dependency's ambient proxy
	// dialer from losing the authenticated context on opaque CONNECT relays.
	gp.ConnectDial = nil
	gp.ConnectDialWithReq = func(req *http.Request, network, addr string) (net.Conn, error) {
		slot := &closeSlot{}
		ctx, release, ok := auth.Admit(req.Context(), identity.FromContext(req.Context()), slot.close)
		if !ok {
			return nil, errors.New("tunnel authorization refused")
		}
		conn, err := gp.Tr.DialContext(ctx, network, addr)
		if err != nil {
			release()
			return nil, err
		}
		slot.attach(conn)
		if ctx.Err() != nil {
			_ = conn.Close()
			release()
			return nil, context.Canceled
		}
		markTunnelStarted(req)
		return &admissionConn{Conn: conn, release: release}, nil
	}
}
