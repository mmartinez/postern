package proxy

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/mmartinez/postern/internal/identity"
)

type (
	tunnelStateKey struct{}
	tunnelState    struct{ started atomic.Bool }
)

// Authenticator verifies enrollment and serializes admission with publication.
// A nil authenticator preserves legacy unauthenticated operation.
type Authenticator interface {
	Authenticate(name, key string) *identity.Principal
	Current(*identity.Principal) bool
	Authorize(*http.Request) bool
	Admit(context.Context, *identity.Principal, func()) (context.Context, func(), bool)
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if p.cfg.Authenticator == nil {
		req.Header.Del("Proxy-Authorization")
		p.server.ServeHTTP(w, req)
		return
	}
	principal := authenticateHeader(p.cfg.Authenticator, req.Header.Values("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")
	if principal == nil {
		delay, release, capacity := p.throttle.failure(req.RemoteAddr)
		defer release()
		if capacity && delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-req.Context().Done():
				return
			}
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Second))
		w.Header().Set("Proxy-Authenticate", `Basic realm="postern"`)
		w.Header().Set("Connection", "close")
		http.Error(w, "postern: proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	ctx := req.Context()
	conn, _ := ctx.Value(connKey{}).(net.Conn)
	if req.Method == http.MethodConnect {
		if conn == nil {
			http.Error(w, badGatewayBody, http.StatusBadGateway)
			return
		}
		encrypted, _ := ctx.Value(tlsKey{}).(bool)
		ctx = context.WithValue(context.Background(), connKey{}, conn)
		ctx = context.WithValue(ctx, tlsKey{}, encrypted)
		ctx = context.WithValue(ctx, tunnelStateKey{}, &tunnelState{})
	}
	closeConn := func() {
		if conn != nil {
			_ = conn.Close()
		}
	}
	ctx, release, ok := p.cfg.Authenticator.Admit(ctx, principal, closeConn)
	if !ok {
		w.Header().Set("Connection", "close")
		http.Error(w, badGatewayBody, http.StatusBadGateway)
		return
	}
	if req.Method == http.MethodConnect {
		if c, ok := conn.(interface{ Closed() <-chan struct{} }); ok {
			go func() { <-c.Closed(); release() }()
		} else {
			release()
			http.Error(w, badGatewayBody, http.StatusBadGateway)
			return
		}
	} else {
		defer release()
	}
	ctx = identity.WithPrincipal(ctx, principal)
	if req.Method == http.MethodOptions && req.URL.Host == "" && req.URL.Path == "/.well-known/postern/client-auth" && req.URL.RawQuery == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p.server.ServeHTTP(w, req.WithContext(ctx))
}

func authenticateHeader(auth Authenticator, values []string) *identity.Principal {
	if len(values) != 1 || len(values[0]) > 512 || !strings.HasPrefix(values[0], "Basic ") {
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(values[0], "Basic "))
	if err != nil {
		return nil
	}
	name, key, ok := strings.Cut(string(raw), ":")
	if !ok || !identity.ValidName(name) || len(key) != 47 || !strings.HasPrefix(key, "pst_") {
		return nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(key[4:])
	if err != nil || len(decoded) != 32 {
		return nil
	}
	return auth.Authenticate(name, key)
}

func installIdentityGuard(gp *goproxy.ProxyHttpServer, auth Authenticator) {
	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		req.Header.Del("Proxy-Authorization")
		if t, ok := ctx.UserData.(*tunnel); ok && t.principal != nil && identity.FromContext(req.Context()) == nil {
			req = req.WithContext(identity.WithPrincipal(t.ctx, t.principal))
		}
		if auth != nil && !auth.Authorize(req) {
			resp := bad502(req)
			resp.Close = true
			resp.Header.Set("Connection", "close")
			return req, resp
		}
		return req, nil
	})
}

func tunnelMustClose(req *http.Request) bool {
	if req.Context().Err() != nil {
		return true
	}
	if state, _ := req.Context().Value(tunnelStateKey{}).(*tunnelState); state != nil && state.started.Load() {
		return true
	}
	if p := identity.FromContext(req.Context()); p != nil {
		select {
		case <-p.Done():
			return true
		default:
		}
	}
	return false
}

func markTunnelStarted(req *http.Request) {
	if state, _ := req.Context().Value(tunnelStateKey{}).(*tunnelState); state != nil {
		state.started.Store(true)
	}
}
