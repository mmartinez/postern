package broker

import "context"

// HangupWatch arms a watch on the client connection behind a request. It
// calls onHangup at most once if the client disconnects while the watch is
// armed. stop disarms the watch and returns once the watcher has exited, so
// the connection is safe to read again.
type HangupWatch func(onHangup func()) (stop func())

type hangupWatchKey struct{}

// WithHangupWatch returns a copy of ctx that carries w. The proxy attaches a
// watch to every intercepted request; the broker arms it only while it holds
// a request, so traffic that never waits pays nothing for it.
func WithHangupWatch(ctx context.Context, w HangupWatch) context.Context {
	return context.WithValue(ctx, hangupWatchKey{}, w)
}

// HangupWatchFrom returns the watch attached by WithHangupWatch, or nil when
// the request carries none.
func HangupWatchFrom(ctx context.Context) HangupWatch {
	w, _ := ctx.Value(hangupWatchKey{}).(HangupWatch)
	return w
}
