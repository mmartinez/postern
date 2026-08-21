package runtime

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Reap thresholds for hijacked connections. goproxy hijacks every CONNECT,
// and after Hijack net/http clears all deadlines on the conn — the MITM
// handshake runs on context.Background and tunnel relays loop deadline-free
// — so a stalled client or upstream would otherwise pin a goroutine and an
// fd forever. Deadlines here are ACTIVITY-based, not fixed read deadlines:
// any successful Read or Write resets the timer, so a live SSE stream is
// never cut mid-flight.
const (
	// stalledConnTimeout reaps conns that have moved fewer than
	// minProgressBytes total bytes since accept (stalled TLS handshakes,
	// silent or one-byte-then-stall slowloris clients). 30s matches the
	// server's ReadHeaderTimeout order of magnitude: far more generous than
	// any legitimate client needs to send its first bytes, short enough
	// that stalled conns cannot accumulate.
	stalledConnTimeout = 30 * time.Second

	// tunnelIdleTimeout reaps established conns after sustained inactivity
	// in BOTH directions. 10m tolerates legitimately quiet long-lived
	// tunnels (idle websockets, paused streams) while still bounding leak
	// lifetime; anything emitting keepalives more often than that — which
	// every real protocol does — is never touched.
	tunnelIdleTimeout = 10 * time.Minute

	// reapInterval is how often the reaper scans. Eviction latency is at
	// worst reapInterval + threshold; 30s keeps that bound negligible
	// relative to the thresholds while making the scan cost invisible.
	reapInterval = 30 * time.Second

	// minProgressBytes is the total bytes (reads+writes combined) a conn
	// must move to graduate from the stalled tier to the established idle
	// tier. Any real TLS handshake or HTTP request moves far more than 128
	// bytes within seconds, so a conn still under this total after
	// stalledConnTimeout is stalled by definition; raw-tunnel peers and
	// handshakes cross it immediately.
	//
	// The threshold is a heuristic, not a security boundary: any fixed byte
	// count admits padding, so a hostile client can cross 128 bytes and
	// then stall, landing in the 10m tier. This is accepted deliberately.
	// A padded but VALID TLS ClientHello produces a genuinely established
	// tunnel — the real upstream responds — and the activity-based 10m
	// idle tier is the correct bound for it, matching standard L4-proxy
	// idle semantics. Padded garbage is rejected by the upstream and the
	// relay error closes the conn naturally. The threat model
	// (docs/security.md) treats agents as local or LAN-scoped, and the
	// per-conn cost stays bounded by the tier-2 ceiling either way.
	minProgressBytes = 128
)

// halfClosable mirrors goproxy's unexported interface of the same name.
// goproxy type-asserts hijacked conns to it to give raw tunnels half-close
// semantics; a wrapper that dropped CloseWrite/CloseRead would silently
// demote every tunnel to goproxy's degraded no-half-close relay path, so
// trackedConn must implement it fully.
type halfClosable interface {
	net.Conn
	CloseWrite() error
	CloseRead() error
}

var _ halfClosable = (*trackedConn)(nil)

// trackedConn wraps an accepted conn for lifecycle tracking. Activity
// timestamps are updated by Read/Write; the reaper and the shutdown drain
// close stale entries through Close, which unblocks whatever goroutine
// (goproxy's copyAndClose/copyOrWarn relays, the MITM read loop) is parked
// inside the conn.
type trackedConn struct {
	net.Conn

	reg *connRegistry

	accepted     time.Time    // fixed at track time; tier-1 clock start
	lastActivity atomic.Int64 // unix nanos of last successful Read/Write
	progress     atomic.Int64 // total bytes read+written since accept
	closeOnce    sync.Once
	half         halfClosable // non-nil when the underlying conn half-closes
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.progress.Add(int64(n))
		c.markActive()
	}
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.progress.Add(int64(n))
		c.markActive()
	}
	return n, err
}

func (c *trackedConn) markActive() { c.lastActivity.Store(time.Now().UnixNano()) }

func (c *trackedConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.reg.remove(c)
		err = c.Conn.Close()
	})
	return err
}

// CloseWrite forwards half-close so goproxy's halfClosable assertion holds
// and raw tunnels keep their clean-EOF semantics. The fallback returns nil
// rather than an error only because listener-accepted TCP conns always
// support half-close; a non-TCP underlying conn never occurs on this path.
func (c *trackedConn) CloseWrite() error {
	if c.half != nil {
		return c.half.CloseWrite()
	}
	return nil
}

func (c *trackedConn) CloseRead() error {
	if c.half != nil {
		return c.half.CloseRead()
	}
	return nil
}

// idleFor reports how long the conn has been quiet and whether it counts as
// insufficient-progress (under minProgressBytes total bytes — tier-1) or
// established (tier-2).
func (c *trackedConn) idleFor(now time.Time) (d time.Duration, insufficientProgress bool) {
	if c.progress.Load() < minProgressBytes {
		return now.Sub(c.accepted), true
	}
	return now.Sub(time.Unix(0, c.lastActivity.Load())), false
}

// connRegistry tracks live accepted conns. It doubles as the shutdown drain
// barrier: Run waits on count() reaching zero before force-closing stragglers.
type connRegistry struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: make(map[*trackedConn]struct{})}
}

func (r *connRegistry) track(c net.Conn) *trackedConn {
	t := &trackedConn{
		Conn:     c,
		reg:      r,
		accepted: time.Now(),
	}
	t.lastActivity.Store(t.accepted.UnixNano())
	if hc, ok := c.(halfClosable); ok {
		t.half = hc
	}
	r.mu.Lock()
	r.conns[t] = struct{}{}
	r.mu.Unlock()
	return t
}

func (r *connRegistry) remove(c *trackedConn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *connRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// each runs fn over a snapshot of live conns.
func (r *connRegistry) each(fn func(*trackedConn)) {
	r.mu.Lock()
	snapshot := make([]*trackedConn, 0, len(r.conns))
	for c := range r.conns {
		snapshot = append(snapshot, c)
	}
	r.mu.Unlock()
	for _, c := range snapshot {
		fn(c)
	}
}

// closeAll force-closes every tracked conn and returns how many were closed.
func (r *connRegistry) closeAll() int {
	r.mu.Lock()
	victims := make([]*trackedConn, 0, len(r.conns))
	for c := range r.conns {
		victims = append(victims, c)
	}
	r.mu.Unlock()
	for _, c := range victims {
		_ = c.Close()
	}
	return len(victims)
}

// trackingListener wraps the accept path so every inbound conn enters the
// registry as a trackedConn.
type trackingListener struct {
	net.Listener
	reg *connRegistry
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.reg.track(c), nil
}
