package proxy

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/mmartinez/postern/internal/identity"
)

type (
	connKey struct{}
	tlsKey  struct{}
)

// ConnContext is an http.Server ConnContext hook. It records the accepted
// conn on the context so the CONNECT handler can reach the conn's hangup
// watch.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if encrypted, ok := c.(*tls.Conn); ok {
		ctx = context.WithValue(ctx, tlsKey{}, true)
		c = encrypted.NetConn()
	}
	return context.WithValue(ctx, connKey{}, c)
}

// hangupWatcher is the accepted conn's view the broker needs: arm a watch for
// the client hanging up, and stop it.
type hangupWatcher interface {
	WatchHangup(onHangup func()) (stop func())
}

// tunnel is what the CONNECT handler stores in ProxyCtx.UserData for an
// intercepted host; goproxy copies it onto every inner request.
type tunnel struct {
	principal *identity.Principal
	ctx       context.Context
	authority string        // lowercased CONNECT host:port
	hangup    hangupWatcher // nil when the conn cannot be watched
}
