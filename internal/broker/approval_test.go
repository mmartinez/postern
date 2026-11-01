package broker_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/proxy"
)

// waitLimit bounds every channel wait so a broken gate fails the test instead
// of hanging it. It is never slept on.
const waitLimit = 5 * time.Second

// fakeClock drives the gate's Now and After. Timers fire only on Advance.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []fakeTimer
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, fakeTimer{at: c.now.Add(d), ch: ch})
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.timers[:0]
	for _, tm := range c.timers {
		if tm.at.After(c.now) {
			kept = append(kept, tm)
			continue
		}
		tm.ch <- c.now
	}
	c.timers = kept
}

// prompt is one dialog the fake approver holds open until the test answers.
type prompt struct {
	ctx    context.Context
	reason string
	answer chan broker.Outcome
}

// fakeApprover hands every dialog to the test and tracks how many are open.
type fakeApprover struct {
	prompts chan *prompt
	calls   atomic.Int64
	open    atomic.Int64
	maxOpen atomic.Int64
}

func newFakeApprover() *fakeApprover {
	return &fakeApprover{prompts: make(chan *prompt, 128)}
}

func (f *fakeApprover) Approve(ctx context.Context, reason string) (broker.Outcome, error) {
	f.calls.Add(1)
	n := f.open.Add(1)
	defer f.open.Add(-1)
	for m := f.maxOpen.Load(); n > m && !f.maxOpen.CompareAndSwap(m, n); m = f.maxOpen.Load() {
	}
	p := &prompt{ctx: ctx, reason: reason, answer: make(chan broker.Outcome, 1)}
	f.prompts <- p
	select {
	case o := <-p.answer:
		return o, nil
	case <-ctx.Done():
		return broker.OutcomeUnavailable, ctx.Err()
	}
}

func (f *fakeApprover) next(t *testing.T) *prompt {
	t.Helper()
	select {
	case p := <-f.prompts:
		return p
	case <-time.After(waitLimit):
		t.Fatal("no dialog opened")
		return nil
	}
}

// fakeWatch stands in for the proxy's client hangup watch.
type fakeWatch struct {
	armed    chan<- struct{}
	mu       sync.Mutex
	onHangup func()
	stops    atomic.Int64
	// hangupOnStop reports a hangup from inside stop, the way the real
	// watch delivers a disconnect it read just before being stopped.
	hangupOnStop bool
}

func (w *fakeWatch) watch(onHangup func()) func() {
	w.mu.Lock()
	w.onHangup = onHangup
	w.mu.Unlock()
	w.armed <- struct{}{}
	return func() {
		w.stops.Add(1)
		if w.hangupOnStop {
			onHangup()
		}
	}
}

func (w *fakeWatch) hangup() {
	w.mu.Lock()
	f := w.onHangup
	w.mu.Unlock()
	f()
}

type gateFixture struct {
	clock    *fakeClock
	approver *fakeApprover
	res      *fakeResolver
	engine   *broker.Engine
	hook     func(*http.Request) *http.Response
	armed    chan struct{}
}

func newGateFixture(t *testing.T, res broker.Resolver, rules ...broker.Rule) *gateFixture {
	t.Helper()
	f := &gateFixture{
		clock:    newFakeClock(),
		approver: newFakeApprover(),
		engine:   broker.NewEngine(rules),
		armed:    make(chan struct{}, 128),
	}
	if res == nil {
		f.res = &fakeResolver{value: "sk-secret"}
		res = f.res
	}
	gate := broker.NewGate(t.Context(), broker.GateConfig{
		Approver: f.approver,
		Now:      f.clock.Now,
		After:    f.clock.After,
	})
	f.hook = broker.Hook(f.engine, res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // closure
	return f
}

// inflight is a request the hook is still holding.
type inflight struct {
	req   *http.Request
	watch *fakeWatch
	out   chan *http.Response
}

// send runs req through the hook in the background with a fresh hangup watch.
func (f *gateFixture) send(req *http.Request) *inflight {
	return f.sendWatched(req, &fakeWatch{armed: f.armed})
}

// sendWatched is send with a caller-built watch.
func (f *gateFixture) sendWatched(req *http.Request, w *fakeWatch) *inflight {
	in := &inflight{
		req:   req.WithContext(broker.WithHangupWatch(req.Context(), w.watch)),
		watch: w,
		out:   make(chan *http.Response, 1),
	}
	go func() { in.out <- f.hook(in.req) }() //nolint:bodyclose // the receiver closes it
	return in
}

// waitArmed blocks until n requests have entered the gate's wait.
func (f *gateFixture) waitArmed(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-f.armed:
		case <-time.After(waitLimit):
			t.Fatal("request never started waiting for approval")
		}
	}
}

func (in *inflight) result(t *testing.T) *http.Response {
	t.Helper()
	select {
	case resp := <-in.out:
		return resp
	case <-time.After(waitLimit):
		t.Fatal("hook never returned")
		return nil
	}
}

func (in *inflight) requireForwarded(t *testing.T) {
	t.Helper()
	requireForwarded(t, in.result(t)) //nolint:bodyclose // requireForwarded closes it
}

func (in *inflight) requireFailClosed(t *testing.T) {
	t.Helper()
	requireFailClosed(t, in.result(t)) //nolint:bodyclose // requireFailClosed closes it
}

func (in *inflight) done() bool {
	select {
	case resp := <-in.out:
		in.out <- resp
		return true
	default:
		return false
	}
}

func requireForwarded(t *testing.T, resp *http.Response) {
	t.Helper()
	defer closeIfNonNil(t, resp)
	require.Nil(t, resp, "an approved request must be forwarded")
}

func requireFailClosed(t *testing.T, resp *http.Response) {
	t.Helper()
	require.NotNil(t, resp, "request must not be forwarded")
	defer closeIfNonNil(t, resp)
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func approvalRule() broker.Rule {
	return broker.Rule{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		Approval:  &config.Approval{},
	}
}

func approvalRoutedRule() broker.Rule {
	r := routedRule()
	r.Host = "api.example.com"
	r.Approval = &config.Approval{}
	return r
}

func newRequest(t *testing.T, header ...string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/v1/x?k=q", http.NoBody)
	require.NoError(t, err)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	return req
}

func TestGate_PromptsBeforeEveryRuleShape(t *testing.T) {
	t.Parallel()

	oauth := broker.Rule{
		Host:      "api.example.com",
		Injection: broker.InjectSpec{Type: broker.InjectOAuth1, OAuth1: oauth1Refs()},
		Approval:  &config.Approval{},
	}
	multi := broker.Rule{
		Host:       "api.example.com",
		SecretRef:  "op://V/I/f",
		Injections: []broker.InjectSpec{{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"}},
		Approval:   &config.Approval{},
	}
	shapes := []struct {
		name       string
		rule       broker.Rule
		header     []string
		wantReason string
	}{
		{name: "default", rule: approvalRule(), wantReason: "send op://V/I/f to GET api.example.com/v1/x for any client"},
		{name: "injects", rule: multi, wantReason: "send op://V/I/f to GET api.example.com/v1/x for any client"},
		{name: "oauth1", rule: oauth, wantReason: "send op://v/tk to GET api.example.com/v1/x for any client"},
		{
			name:       "routes",
			rule:       approvalRoutedRule(),
			header:     []string{"X-Token", "tg_max_8Kq2Lp9wZ"},
			wantReason: "send op://Agents/telegram-max/token to GET api.example.com/v1/x for agent max",
		},
	}
	for _, sh := range shapes {
		for _, answer := range []broker.Outcome{broker.OutcomeApproved, broker.OutcomeDenied, broker.OutcomeDismissed} {
			t.Run(sh.name+"/"+string(answer), func(t *testing.T) {
				t.Parallel()
				f := newGateFixture(t, nil, sh.rule)
				in := f.send(newRequest(t, sh.header...))

				p := f.approver.next(t)
				require.Equal(t, sh.wantReason, p.reason)
				require.Zero(t, f.res.calls.Load(), "nothing may resolve while the dialog is open")
				p.answer <- answer

				if answer != broker.OutcomeApproved {
					in.requireFailClosed(t)
					require.Zero(t, f.res.calls.Load(), "a refused request must never resolve")
					return
				}
				in.requireForwarded(t)
				require.Positive(t, f.res.calls.Load())
				require.Equal(t, int64(1), in.watch.stops.Load(), "the hangup watch must be disarmed before forwarding")
			})
		}
	}
}

func TestGate_OneDialogAtATime(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRule())
	// Distinct paths let each prompt name the request it belongs to.
	byPath := map[string]*inflight{}
	for _, path := range []string{"/a", "/b", "/c"} {
		req := newRequest(t)
		req.URL.Path = path
		byPath[path] = f.send(req)
	}
	f.waitArmed(t, 3)

	for range 3 {
		p := f.approver.next(t)
		path := p.reason[len("send op://V/I/f to GET api.example.com") : len(p.reason)-len(" for any client")]
		in, ok := byPath[path]
		require.True(t, ok, "unexpected prompt %q", p.reason)
		delete(byPath, path)

		p.answer <- broker.OutcomeApproved
		in.requireForwarded(t)
		for other, pending := range byPath {
			require.False(t, pending.done(), "approving %s must not release %s", path, other)
		}
	}
	require.Equal(t, int64(3), f.approver.calls.Load(), "every request gets its own prompt")
	require.Equal(t, int64(1), f.approver.maxOpen.Load(), "dialogs must never overlap")
	require.Equal(t, int64(3), f.res.calls.Load())
}

func TestGate_RoutesHaveSeparateKeys(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRoutedRule())
	maxReq := func() *http.Request { return newRequest(t, "X-Token", "tg_max_8Kq2Lp9wZ") }
	johnReq := func() *http.Request { return newRequest(t, "X-Token", "tg_john_3Rt7Yx1mQ") }

	in := f.send(maxReq())
	f.approver.next(t).answer <- broker.OutcomeDenied
	in.requireFailClosed(t)

	in = f.send(johnReq())
	p := f.approver.next(t)
	require.Contains(t, p.reason, "for agent john")
	p.answer <- broker.OutcomeApproved
	in.requireForwarded(t)

	in = f.send(maxReq())
	in.requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "max stays in cooldown after john is approved")
	require.Equal(t, int64(1), f.res.calls.Load())
}

func TestGate_QueuedRequestThatLeavesNeverPrompts(t *testing.T) {
	t.Parallel()

	for _, leave := range []string{"hangup", "context"} {
		t.Run(leave, func(t *testing.T) {
			t.Parallel()
			f := newGateFixture(t, nil, approvalRule())
			first := f.send(newRequest(t))
			holder := f.approver.next(t)
			f.waitArmed(t, 1)

			ctx, cancel := context.WithCancel(t.Context())
			second := f.send(newRequest(t).WithContext(ctx))
			f.waitArmed(t, 1)
			if leave == "hangup" {
				second.watch.hangup()
			} else {
				cancel()
			}
			second.requireFailClosed(t)
			cancel()

			holder.answer <- broker.OutcomeApproved
			first.requireForwarded(t)
			require.Equal(t, int64(1), f.approver.calls.Load(), "the request that left must never prompt")
			require.Equal(t, int64(1), f.res.calls.Load())
		})
	}
}

func TestGate_ApprovedAfterClientLeftFailsClosed(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRule())
	in := f.send(newRequest(t))
	f.waitArmed(t, 1)
	p := f.approver.next(t)

	in.watch.hangup()
	require.NoError(t, p.ctx.Err(), "the dialog must outlive the client")
	require.False(t, in.done(), "the request must wait for the answer")

	p.answer <- broker.OutcomeApproved
	in.requireFailClosed(t)
	require.Zero(t, f.res.calls.Load(), "a request whose client left must never resolve")
}

func TestGate_RefusalCooldown(t *testing.T) {
	t.Parallel()

	for _, answer := range []broker.Outcome{broker.OutcomeDenied, broker.OutcomeDismissed} {
		t.Run(string(answer), func(t *testing.T) {
			t.Parallel()
			f := newGateFixture(t, nil, approvalRule())
			first := f.send(newRequest(t))
			p := f.approver.next(t)
			queued := f.send(newRequest(t))
			f.waitArmed(t, 2)

			p.answer <- answer
			first.requireFailClosed(t)
			queued.requireFailClosed(t)
			require.Equal(t, int64(1), f.approver.calls.Load(), "a queued request must not prompt after a refusal")

			f.clock.Advance(30*time.Second - time.Nanosecond)
			f.send(newRequest(t)).requireFailClosed(t)
			require.Equal(t, int64(1), f.approver.calls.Load(), "a retry inside the cooldown must not prompt")

			f.clock.Advance(time.Nanosecond)
			retry := f.send(newRequest(t))
			f.approver.next(t).answer <- broker.OutcomeApproved
			retry.requireForwarded(t)
			require.Equal(t, int64(1), f.res.calls.Load())
		})
	}
}

func TestGate_PromptTimesOut(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRule())
	in := f.send(newRequest(t))
	p := f.approver.next(t)

	f.clock.Advance(60*time.Second - time.Nanosecond)
	require.NoError(t, p.ctx.Err(), "the dialog must stay open until the timeout")
	require.False(t, in.done())

	f.clock.Advance(time.Nanosecond)
	in.requireFailClosed(t)
	require.Error(t, p.ctx.Err(), "a timed-out dialog must be closed")
	require.Zero(t, f.res.calls.Load())

	f.send(newRequest(t)).requireFailClosed(t)
	require.Equal(t, int64(1), f.approver.calls.Load(), "a timeout starts the cooldown")
}

// TestGate_TimeoutStartsWhenDialogOpens holds a request in the queue for most
// of a timeout behind another route's dialog. Its own dialog still gets the
// full 60 seconds.
func TestGate_TimeoutStartsWhenDialogOpens(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRoutedRule())
	first := f.send(newRequest(t, "X-Token", "tg_max_8Kq2Lp9wZ"))
	p := f.approver.next(t)
	queued := f.send(newRequest(t, "X-Token", "tg_john_3Rt7Yx1mQ"))
	f.waitArmed(t, 2)

	f.clock.Advance(59 * time.Second)
	p.answer <- broker.OutcomeApproved
	first.requireForwarded(t)

	q := f.approver.next(t)
	f.clock.Advance(59 * time.Second)
	require.NoError(t, q.ctx.Err(), "the queued request's dialog gets its own 60 seconds")
	q.answer <- broker.OutcomeApproved
	queued.requireForwarded(t)
}

// TestGate_RefusalBudget covers dialogs that end without an approval, which
// pam_faillock counts as failed logins: after two within 15 minutes, on any
// keys, the gate stops prompting until the older one leaves the window, and
// an approval clears the count.
func TestGate_RefusalBudget(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRoutedRule())
	maxReq := func() *http.Request { return newRequest(t, "X-Token", "tg_max_8Kq2Lp9wZ") }
	johnReq := func() *http.Request { return newRequest(t, "X-Token", "tg_john_3Rt7Yx1mQ") }
	refuse := func(req *http.Request, answer broker.Outcome) {
		t.Helper()
		in := f.send(req)
		f.approver.next(t).answer <- answer
		in.requireFailClosed(t)
	}

	refuse(maxReq(), broker.OutcomeDismissed)
	f.clock.Advance(5 * time.Minute)
	refuse(johnReq(), broker.OutcomeDenied)
	f.clock.Advance(5 * time.Minute)
	f.send(maxReq()).requireFailClosed(t)
	f.send(johnReq()).requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "two refusals in 15 minutes stop every dialog")

	f.clock.Advance(5*time.Minute - time.Nanosecond)
	f.send(maxReq()).requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load())

	f.clock.Advance(time.Nanosecond)
	in := f.send(maxReq())
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)

	// The approval clears the count, so one more refusal still leaves room.
	f.clock.Advance(time.Minute)
	refuse(maxReq(), broker.OutcomeDismissed)
	f.clock.Advance(time.Minute)
	in = f.send(maxReq())
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)
	require.Equal(t, int64(5), f.approver.calls.Load())
	require.Equal(t, int64(2), f.res.calls.Load())
}

// TestGate_RefusalBudgetSpansRulesQueueAndReload refuses on two rules. A
// request that queued behind the second dialog, before the budget was spent,
// still gets no dialog, and a hot reload does not clear the count.
func TestGate_RefusalBudgetSpansRulesQueueAndReload(t *testing.T) {
	t.Parallel()

	cfgRule := func(host string) config.Rule {
		return config.Rule{
			Host:      host,
			SecretRef: "op://V/I/f",
			Inject:    config.Inject{Type: config.InjectTypeHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
			Approval:  &config.Approval{},
		}
	}
	cfgRules := []config.Rule{cfgRule("api.example.com"), cfgRule("other.example.com")}
	rules, err := broker.FromConfigRules(cfgRules)
	require.NoError(t, err)
	f := newGateFixture(t, nil, rules...)
	otherReq := newRequest(t)
	otherReq.URL.Host = "other.example.com"

	in := f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeDismissed
	in.requireFailClosed(t)
	f.clock.Advance(time.Minute)

	in = f.send(otherReq)
	p := f.approver.next(t)
	queued := f.send(newRequest(t))
	f.waitArmed(t, 3)
	p.answer <- broker.OutcomeDenied
	in.requireFailClosed(t)
	queued.requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "a request queued before the budget was spent must not prompt")

	reloaded, err := broker.FromConfigRules(cfgRules)
	require.NoError(t, err)
	f.engine.Swap(reloaded)
	f.send(newRequest(t)).requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "a reload must not clear the count")
	require.Zero(t, f.res.calls.Load())
}

func TestGate_ReloadClearsCooldown(t *testing.T) {
	t.Parallel()

	cfgRules := []config.Rule{{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Inject:    config.Inject{Type: config.InjectTypeHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		Approval:  &config.Approval{},
	}}
	rules, err := broker.FromConfigRules(cfgRules)
	require.NoError(t, err)
	f := newGateFixture(t, nil, rules...)

	in := f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeDenied
	in.requireFailClosed(t)
	f.send(newRequest(t)).requireFailClosed(t)
	require.Equal(t, int64(1), f.approver.calls.Load())

	reloaded, err := broker.FromConfigRules(cfgRules)
	require.NoError(t, err)
	f.engine.Swap(reloaded)

	in = f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)
}

// countingInner is the vault behind the real cached resolver.
type countingInner struct{ calls atomic.Int64 }

func (c *countingInner) Resolve(context.Context, string, string) (string, error) {
	c.calls.Add(1)
	return "sk-secret", nil
}

func TestGate_WarmCacheStillPrompts(t *testing.T) {
	t.Parallel()

	inner := &countingInner{}
	clk := newFakeClock()
	cached, err := credstore.NewCachedResolver(inner, credstore.CacheConfig{
		TTL:          time.Hour,
		RefreshAhead: 45 * time.Minute,
		MaxStale:     24 * time.Hour,
		ShouldCache:  func(string) bool { return true },
		Now:          clk.Now,
	})
	require.NoError(t, err)
	f := newGateFixture(t, cached, approvalRule())

	in := f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)
	require.Equal(t, int64(1), inner.calls.Load())

	warm := f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeDenied
	warm.requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "a cached credential must not skip the prompt")
	require.Empty(t, warm.req.Header.Get("x-api-key"))
}

func TestGate_WaitingCap(t *testing.T) {
	t.Parallel()

	// Requests sharing one grant prompt still count one each.
	for name, rule := range map[string]broker.Rule{"per request": approvalRule(), "grant": grantRule()} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newGateFixture(t, nil, rule)
			waiting := make([]*inflight, 0, 64)
			for range 64 {
				waiting = append(waiting, f.send(newRequest(t)))
			}
			f.waitArmed(t, 64)
			p := f.approver.next(t)

			over := f.send(newRequest(t))
			over.requireFailClosed(t)
			require.Zero(t, over.watch.stops.Load(), "a request over the cap must not wait")

			p.answer <- broker.OutcomeDenied
			for _, in := range waiting {
				in.requireFailClosed(t)
			}
			require.Equal(t, int64(1), f.approver.calls.Load())
			require.Zero(t, f.res.calls.Load())
		})
	}
}

func TestGate_OversizedBodyFailsBeforePrompt(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRule())
	body := strings.NewReader(strings.Repeat("a", config.DefaultMaxBodyBytes+1))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.example.com/v1/upload", body)
	require.NoError(t, err)

	resp := f.send(req).result(t)
	require.NotNil(t, resp)
	defer closeIfNonNil(t, resp)
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	require.Zero(t, f.approver.calls.Load(), "an oversized body must not prompt")
	require.Zero(t, f.res.calls.Load())
}

// TestGate_HangupSeenWhileStoppingFailsClosed covers a disconnect the watch
// has read but not yet reported when the approval arrives. Stopping the
// watch delivers it, and the request must still fail closed.
func TestGate_HangupSeenWhileStoppingFailsClosed(t *testing.T) {
	t.Parallel()

	for name, rule := range map[string]broker.Rule{"per request": approvalRule(), "grant": grantRule()} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newGateFixture(t, nil, rule)
			in := f.sendWatched(newRequest(t), &fakeWatch{armed: f.armed, hangupOnStop: true})
			f.waitArmed(t, 1)
			f.approver.next(t).answer <- broker.OutcomeApproved

			in.requireFailClosed(t)
			require.Zero(t, f.res.calls.Load())
		})
	}
}

func TestGate_ShutdownClosesDialogAndFailsQueued(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, approvalRule())
	base, shutdown := context.WithCancel(t.Context())
	gate := broker.NewGate(base, broker.GateConfig{Approver: f.approver, Now: f.clock.Now, After: f.clock.After})
	f.hook = broker.Hook(f.engine, f.res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // closure

	open := f.send(newRequest(t))
	queued := f.send(newRequest(t))
	f.waitArmed(t, 2)
	p := f.approver.next(t)
	shutdown()
	select {
	case <-p.ctx.Done():
	case <-time.After(waitLimit):
		t.Fatal("shutdown left the dialog open")
	}

	open.requireFailClosed(t)
	queued.requireFailClosed(t)
	require.Equal(t, int64(1), f.approver.calls.Load(), "a queued request must not prompt after shutdown")
	require.Zero(t, f.res.calls.Load())
}

// TestGate_BrokenApproverFailsClosed covers backends that break the Approver
// contract: a panic, and an approval that comes with an error.
func TestGate_BrokenApproverFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		approve approverFunc
	}{
		{"panic", func(context.Context, string) (broker.Outcome, error) { panic("backend bug") }},
		{"approved with error", func(context.Context, string) (broker.Outcome, error) {
			return broker.OutcomeApproved, errors.New("backend failed")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := &fakeResolver{value: "sk-secret"}
			gate := broker.NewGate(t.Context(), broker.GateConfig{Approver: tc.approve})
			hook := broker.Hook(broker.NewEngine([]broker.Rule{approvalRule()}), res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // requireFailClosed closes it

			requireFailClosed(t, hook(newRequest(t))) //nolint:bodyclose // requireFailClosed closes it
			require.Zero(t, res.calls.Load())
		})
	}
}

func TestGate_MissingApproverFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		gate []*broker.Gate
	}{
		{name: "no gate"},
		{name: "nil gate", gate: []*broker.Gate{nil}},
		{name: "nil approver", gate: []*broker.Gate{broker.NewGate(t.Context(), broker.GateConfig{})}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := &fakeResolver{value: "sk-secret"}
			engine := broker.NewEngine([]broker.Rule{approvalRule()})
			hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, true, nil, tc.gate...) //nolint:bodyclose // closure
			resp := hook(newRequest(t))                                                             //nolint:bodyclose // requireFailClosed closes it
			requireFailClosed(t, resp)
			require.Zero(t, res.calls.Load())
		})
	}
}

// approverFunc answers every prompt at once.
type approverFunc func(context.Context, string) (broker.Outcome, error)

func (f approverFunc) Approve(ctx context.Context, reason string) (broker.Outcome, error) {
	return f(ctx, reason)
}

func TestE2E_ApprovalGatesUpstream(t *testing.T) {
	t.Parallel()

	for _, answer := range []broker.Outcome{broker.OutcomeApproved, broker.OutcomeDenied} {
		t.Run(string(answer), func(t *testing.T) {
			t.Parallel()

			var upstreamHits atomic.Int64
			var gotKey atomic.Value
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				upstreamHits.Add(1)
				gotKey.Store(r.Header.Get("x-api-key"))
			}))
			t.Cleanup(upstream.Close)

			root := fixtureCA(t)
			rule := approvalRule()
			rule.Host = "127.0.0.1"
			res := &fakeResolver{value: "sk-secret"}
			gate := broker.NewGate(t.Context(), broker.GateConfig{
				Approver: approverFunc(func(context.Context, string) (broker.Outcome, error) { return answer, nil }),
			})
			hook := broker.Hook(broker.NewEngine([]broker.Rule{rule}), res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // goproxy closes it

			p, err := proxy.New(proxy.Config{
				CA:                 root,
				Minter:             fixtureMinter(t, root),
				Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
				UpstreamTLS:        upstreamTLS(t, upstream),
				PreUpstreamHandler: hook,
			})
			require.NoError(t, err)

			resp, err := clientThroughProxy(t, startProxy(t, p), root).Get(upstream.URL)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			if answer == broker.OutcomeApproved {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, "sk-secret", gotKey.Load())
				return
			}
			require.Equal(t, http.StatusBadGateway, resp.StatusCode)
			require.Zero(t, upstreamHits.Load(), "a denied request must never reach the upstream")
			require.Zero(t, res.calls.Load())
		})
	}
}
