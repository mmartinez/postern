package runtime

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// maxHangupBuf bounds the bytes a watch reads ahead of the MITM read
	// loop. Past it the pump stops reading and TCP backpressure resumes, so
	// a hangup queued behind those bytes goes unseen until the loop drains
	// them.
	maxHangupBuf = 64 << 10

	// hangupReadChunk is the size of each pump read.
	hangupReadChunk = 4 << 10
)

// pastDeadline unblocks a pending Read immediately.
var pastDeadline = time.Unix(1, 0)

// hangupConn lets the broker notice a client hanging up while it holds a
// request and nothing reads the conn. While a watch is armed a pump
// goroutine is the only reader of the underlying conn; Read serves the
// pump's buffer first, so no byte of the stream is lost or reordered.
type hangupConn struct {
	net.Conn

	mu       sync.Mutex
	cond     sync.Cond
	buf      []byte
	err      error // read error the pump saw; returned once buf drains
	watching bool
	stopping bool
}

func newHangupConn(c net.Conn) *hangupConn {
	h := &hangupConn{Conn: c}
	h.cond.L = &h.mu
	return h
}

func (c *hangupConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	for c.watching && len(c.buf) == 0 && c.err == nil {
		c.cond.Wait()
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.cond.Broadcast()
		c.mu.Unlock()
		return n, nil
	}
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	// shortcut: assumes no foreground Read is in flight when a watch arms,
	// true for goproxy's serial HTTP/1 MITM loop; revisit if HTTP/2 MITM
	// (AllowHTTP2) is ever enabled.
	return c.Conn.Read(p)
}

// WatchHangup calls onHangup once if the client closes the conn, or the conn
// is closed locally, before stop is called. stop must be called exactly once;
// it returns after the pump has exited, with the read deadline cleared.
func (c *hangupConn) WatchHangup(onHangup func()) (stop func()) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		onHangup()
		return func() {}
	}
	c.watching = true
	c.mu.Unlock()
	done := make(chan struct{})
	go c.pump(onHangup, done)
	return func() {
		c.mu.Lock()
		c.stopping = true
		c.cond.Broadcast()
		c.mu.Unlock()
		_ = c.SetReadDeadline(pastDeadline)
		<-done
		// net/http clears every deadline at Hijack and nothing on the MITM
		// path sets one, so zero is the state to restore.
		_ = c.SetReadDeadline(time.Time{})
		c.mu.Lock()
		c.watching, c.stopping = false, false
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

func (c *hangupConn) pump(onHangup func(), done chan<- struct{}) {
	defer close(done)
	var chunk [hangupReadChunk]byte
	for {
		c.mu.Lock()
		for len(c.buf) >= maxHangupBuf && !c.stopping {
			c.cond.Wait()
		}
		stopping := c.stopping
		c.mu.Unlock()
		if stopping {
			return
		}
		n, err := c.Conn.Read(chunk[:])
		c.mu.Lock()
		c.buf = append(c.buf, chunk[:n]...)
		if err != nil && (!c.stopping || !errors.Is(err, os.ErrDeadlineExceeded)) {
			c.err = err
		}
		gone := c.err != nil
		c.cond.Broadcast()
		c.mu.Unlock()
		if gone {
			onHangup()
		}
		if err != nil {
			return
		}
	}
}
