package runtime

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const hangupWait = 2 * time.Second

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (server, client *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	s := <-accepted
	require.NotNil(t, s)
	t.Cleanup(func() { _ = s.Close(); _ = c.Close() })
	return s.(*net.TCPConn), c.(*net.TCPConn)
}

// readCounter counts the bytes read from the wrapped conn, so a test knows
// the pump has pulled them off the socket.
type readCounter struct {
	net.Conn
	total  atomic.Int64
	notify chan struct{}
}

func newReadCounter(c net.Conn) *readCounter {
	return &readCounter{Conn: c, notify: make(chan struct{}, 1)}
}

func (r *readCounter) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.total.Add(int64(n))
		select {
		case r.notify <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (r *readCounter) waitFor(t *testing.T, total int) {
	t.Helper()
	for r.total.Load() < int64(total) {
		select {
		case <-r.notify:
		case <-time.After(hangupWait):
			t.Fatalf("pump read %d of %d bytes", r.total.Load(), total)
		}
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(hangupWait):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// readFull is io.ReadFull that fails the test instead of hanging; the
// cleanup that closes the conn unblocks the abandoned read.
func readFull(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	type result struct {
		buf []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		ch <- result{buf, err}
	}()
	select {
	case res := <-ch:
		require.NoError(t, res.err)
		return res.buf
	case <-time.After(hangupWait):
		t.Fatalf("read of %d bytes did not finish", n)
		return nil
	}
}

func TestHangupConnReplaysReadAheadAfterStop(t *testing.T) {
	t.Parallel()
	server, client := tcpPair(t)
	rc := newReadCounter(server)
	h := newHangupConn(rc)

	var hangups atomic.Int32
	stop := h.WatchHangup(func() { hangups.Add(1) })
	_, err := client.Write([]byte("first"))
	require.NoError(t, err)
	rc.waitFor(t, len("first"))
	stop()

	_, err = client.Write([]byte("second"))
	require.NoError(t, err)
	got := readFull(t, h, len("firstsecond"))
	require.Equal(t, "firstsecond", string(got), "stop must replay read-ahead bytes and leave the conn readable")
	require.Zero(t, hangups.Load(), "a connected client must not be signalled")
}

func TestHangupConnServesArmedRead(t *testing.T) {
	t.Parallel()
	server, client := tcpPair(t)
	h := newHangupConn(server)
	stop := h.WatchHangup(func() { t.Error("connected client signalled") })
	defer stop()

	_, err := client.Write([]byte("body"))
	require.NoError(t, err)
	require.Equal(t, "body", string(readFull(t, h, 4)))
}

func TestHangupConnSignalsOnceWhileArmed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		leave func(h *hangupConn, client *net.TCPConn)
	}{
		{"client FIN", func(_ *hangupConn, c *net.TCPConn) { _ = c.Close() }},
		{"client RST", func(_ *hangupConn, c *net.TCPConn) {
			_ = c.SetLinger(0)
			_ = c.Close()
		}},
		{"local close", func(h *hangupConn, _ *net.TCPConn) { _ = h.Close() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, client := tcpPair(t)
			h := newHangupConn(server)
			var hangups atomic.Int32
			gone := make(chan struct{})
			stop := h.WatchHangup(func() {
				if hangups.Add(1) == 1 {
					close(gone)
				}
			})
			tc.leave(h, client)
			waitClosed(t, gone, "onHangup")
			stop()
			require.Equal(t, int32(1), hangups.Load())
		})
	}
}

func TestHangupConnSilentWhileDisarmed(t *testing.T) {
	t.Parallel()
	server, client := tcpPair(t)
	h := newHangupConn(server)
	var hangups atomic.Int32
	h.WatchHangup(func() { hangups.Add(1) })()

	require.NoError(t, client.Close())
	n, err := h.Read(make([]byte, 1))
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, hangups.Load())
}

func TestHangupConnStickyErrorAfterDrain(t *testing.T) {
	t.Parallel()
	server, client := tcpPair(t)
	h := newHangupConn(server)
	gone := make(chan struct{})
	stop := h.WatchHangup(func() { close(gone) })
	_, err := client.Write([]byte("tail"))
	require.NoError(t, err)
	require.NoError(t, client.Close())
	waitClosed(t, gone, "onHangup")
	stop()

	got, err := io.ReadAll(h)
	require.NoError(t, err)
	require.Equal(t, "tail", string(got))
	_, err = h.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	again := make(chan struct{})
	h.WatchHangup(func() { close(again) })()
	waitClosed(t, again, "onHangup when arming a conn that is already gone")
}

func TestHangupConnCapsReadAhead(t *testing.T) {
	t.Parallel()
	server, client := tcpPair(t)
	rc := newReadCounter(server)
	h := newHangupConn(rc)
	want := bytes.Repeat([]byte("0123456789abcdef"), 4*maxHangupBuf/16)

	stop := h.WatchHangup(func() { t.Error("connected client signalled") })
	written := make(chan error, 1)
	go func() {
		_, err := client.Write(want)
		written <- err
	}()
	rc.waitFor(t, maxHangupBuf)
	stop()
	require.Less(t, rc.total.Load(), int64(maxHangupBuf+hangupReadChunk), "the pump must stop reading at the read-ahead cap")

	got := readFull(t, h, len(want))
	require.NoError(t, <-written)
	require.Equal(t, want, got)
}

func TestHangupConnSignalsLocalCloseWithFullBuffer(t *testing.T) {
	t.Parallel()
	server, client := tcpPair(t)
	rc := newReadCounter(server)
	h := newHangupConn(rc)
	gone := make(chan struct{})
	stop := h.WatchHangup(func() { close(gone) })
	defer stop()
	go func() { _, _ = client.Write(bytes.Repeat([]byte("x"), 2*maxHangupBuf)) }()
	rc.waitFor(t, maxHangupBuf)

	require.NoError(t, h.Close())
	waitClosed(t, gone, "onHangup after a local close while the read-ahead buffer is full")
}
