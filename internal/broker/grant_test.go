package broker_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

func grantRule() broker.Rule {
	r := approvalRule()
	r.Approval = &config.Approval{TTL: 10 * time.Minute}
	return r
}

func grantRoutedRule() broker.Rule {
	r := approvalRoutedRule()
	r.Approval = &config.Approval{TTL: 10 * time.Minute}
	return r
}

func maxRequest(t *testing.T) *http.Request {
	t.Helper()
	return newRequest(t, "X-Token", "tg_max_8Kq2Lp9wZ")
}

func johnRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	req := newRequest(t, "X-Token", "tg_john_3Rt7Yx1mQ")
	req.URL.Path = path
	return req
}

func TestGate_GrantCoversTheWindow(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, grantRule())
	in := f.send(newRequest(t))
	p := f.approver.next(t)
	// The window counts from the answer, not from when the dialog opened.
	f.clock.Advance(30 * time.Second)
	p.answer <- broker.OutcomeApproved
	in.requireForwarded(t)

	f.send(newRequest(t)).requireForwarded(t)
	f.clock.Advance(10*time.Minute - time.Nanosecond)
	f.send(newRequest(t)).requireForwarded(t)
	require.Equal(t, int64(1), f.approver.calls.Load(), "requests inside the window must not prompt")

	f.clock.Advance(time.Nanosecond)
	in = f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeDenied
	in.requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "a request after the window must prompt")
	require.Equal(t, int64(3), f.res.calls.Load())
}

func TestGate_GrantSharesOnePrompt(t *testing.T) {
	t.Parallel()

	for _, answer := range []broker.Outcome{broker.OutcomeApproved, broker.OutcomeDenied} {
		t.Run(string(answer), func(t *testing.T) {
			t.Parallel()
			f := newGateFixture(t, nil, grantRoutedRule())
			const n = 5
			waiting := []*inflight{f.send(maxRequest(t))}
			p := f.approver.next(t)
			f.waitArmed(t, 1)
			// john queues for the dialog before the rest of max's requests arrive.
			john := f.send(johnRequest(t, "/v1/x"))
			f.waitArmed(t, 1)
			for range n - 1 {
				waiting = append(waiting, f.send(maxRequest(t)))
			}
			f.waitArmed(t, n-1)

			require.Equal(t, "let agent max use op://Agents/telegram-max/token for all requests to api.example.com on any path for 10m (first request: GET api.example.com/v1/x)", p.reason)
			p.answer <- answer
			for _, in := range waiting {
				if answer == broker.OutcomeApproved {
					in.requireForwarded(t)
				} else {
					in.requireFailClosed(t)
				}
			}
			jp := f.approver.next(t)
			require.Contains(t, jp.reason, "let agent john")
			require.Equal(t, int64(2), f.approver.calls.Load(), "concurrent requests for one grant share one prompt")
			jp.answer <- broker.OutcomeDenied
			john.requireFailClosed(t)
			if answer == broker.OutcomeApproved {
				require.Equal(t, int64(n), f.res.calls.Load())
				return
			}
			require.Zero(t, f.res.calls.Load())

			f.send(maxRequest(t)).requireFailClosed(t)
			require.Equal(t, int64(2), f.approver.calls.Load(), "a refused grant starts the cooldown")
			require.Zero(t, f.res.calls.Load())
		})
	}
}

func TestGate_ApproverErrorNeverGrants(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	gate := broker.NewGate(t.Context(), broker.GateConfig{
		Approver: approverFunc(func(context.Context, string) (broker.Outcome, error) {
			calls.Add(1)
			return broker.OutcomeApproved, errors.New("backend failed")
		}),
	})
	res := &fakeResolver{value: "sk-secret"}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{grantRule()}), res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // closure
	for range 2 {
		requireFailClosed(t, hook(newRequest(t))) //nolint:bodyclose // requireFailClosed closes it
	}
	require.Equal(t, int64(2), calls.Load(), "a failed dialog must not leave a grant behind")
	require.Zero(t, res.calls.Load())
}

func TestGate_GrantWaitersThatLeave(t *testing.T) {
	t.Parallel()

	t.Run("all leave while queued", func(t *testing.T) {
		t.Parallel()
		f := newGateFixture(t, nil, grantRoutedRule())
		holder := f.send(maxRequest(t))
		hp := f.approver.next(t)
		f.waitArmed(t, 1)

		left := []*inflight{f.send(johnRequest(t, "/left")), f.send(johnRequest(t, "/left"))}
		f.waitArmed(t, 2)
		for _, in := range left {
			in.watch.hangup()
			in.requireFailClosed(t)
		}
		hp.answer <- broker.OutcomeApproved
		holder.requireForwarded(t)

		fresh := f.send(johnRequest(t, "/fresh"))
		p := f.approver.next(t)
		require.Contains(t, p.reason, "(first request: GET api.example.com/fresh)", "a grant every client left while queued must never prompt")
		p.answer <- broker.OutcomeApproved
		fresh.requireForwarded(t)
		require.Equal(t, int64(2), f.approver.calls.Load())
		require.Equal(t, int64(2), f.res.calls.Load())
	})

	t.Run("one leaves while queued", func(t *testing.T) {
		t.Parallel()
		f := newGateFixture(t, nil, grantRoutedRule())
		holder := f.send(maxRequest(t))
		hp := f.approver.next(t)
		f.waitArmed(t, 1)

		gone := f.send(johnRequest(t, "/v1/x"))
		stays := f.send(johnRequest(t, "/v1/x"))
		f.waitArmed(t, 2)
		gone.watch.hangup()
		gone.requireFailClosed(t)
		hp.answer <- broker.OutcomeApproved
		holder.requireForwarded(t)

		p := f.approver.next(t)
		require.Contains(t, p.reason, "let agent john")
		p.answer <- broker.OutcomeApproved
		stays.requireForwarded(t)
		require.Equal(t, int64(2), f.approver.calls.Load())
		require.Equal(t, int64(2), f.res.calls.Load(), "the request that left must never resolve")
	})
}

func TestGate_GrantAnswerSettlesRequestsQueuedBehindIt(t *testing.T) {
	t.Parallel()

	for _, answer := range []broker.Outcome{broker.OutcomeApproved, broker.OutcomeDenied} {
		t.Run(string(answer), func(t *testing.T) {
			t.Parallel()
			f := newGateFixture(t, nil, grantRule())
			first := f.send(newRequest(t))
			p := f.approver.next(t)
			f.waitArmed(t, 1)
			first.watch.hangup()
			first.requireFailClosed(t)
			require.NoError(t, p.ctx.Err(), "an open dialog must outlive its waiters")

			next := f.send(newRequest(t))
			f.waitArmed(t, 1)
			p.answer <- answer
			if answer == broker.OutcomeApproved {
				next.requireForwarded(t)
				require.Equal(t, int64(1), f.res.calls.Load())
			} else {
				next.requireFailClosed(t)
				require.Zero(t, f.res.calls.Load())
			}
			require.Equal(t, int64(1), f.approver.calls.Load(), "a request queued behind the dialog must take its answer")
		})
	}
}

func TestGate_GrantIsPerRoute(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, grantRoutedRule())
	in := f.send(maxRequest(t))
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)

	john := f.send(johnRequest(t, "/v1/x"))
	p := f.approver.next(t)
	require.Contains(t, p.reason, "let agent john")
	f.send(maxRequest(t)).requireForwarded(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "a granted request must pass while another key's dialog is open")

	p.answer <- broker.OutcomeDenied
	john.requireFailClosed(t)
	require.Equal(t, int64(2), f.res.calls.Load(), "only the granted route may resolve")
}

func TestGate_ReloadClearsGrant(t *testing.T) {
	t.Parallel()

	cfgRules := []config.Rule{{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Inject:    config.Inject{Type: config.InjectTypeHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		Approval:  &config.Approval{TTL: 10 * time.Minute},
	}}
	rules, err := broker.FromConfigRules(cfgRules)
	require.NoError(t, err)
	f := newGateFixture(t, nil, rules...)

	in := f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)
	f.send(newRequest(t)).requireForwarded(t)
	require.Equal(t, int64(1), f.approver.calls.Load())

	reloaded, err := broker.FromConfigRules(cfgRules)
	require.NoError(t, err)
	f.engine.Swap(reloaded)

	in = f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeDenied
	in.requireFailClosed(t)
	require.Equal(t, int64(2), f.approver.calls.Load(), "a reload must clear the grant")
	require.Equal(t, int64(2), f.res.calls.Load())
}

// TestGate_GrantRequestAlreadyGoneNeverPrompts sends grant requests whose
// client left before they reached the gate, with the dialog free. None of
// them may open a dialog.
func TestGate_GrantRequestAlreadyGoneNeverPrompts(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, grantRule())
	for range 50 {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		f.send(newRequest(t).WithContext(ctx)).requireFailClosed(t)
	}
	live := newRequest(t)
	live.URL.Path = "/v1/live"
	in := f.send(live)
	p := f.approver.next(t)
	require.Contains(t, p.reason, "/v1/live", "the first dialog came from a request that was already gone")
	p.answer <- broker.OutcomeDenied
	in.requireFailClosed(t)
	require.Equal(t, int64(1), f.approver.calls.Load())
	require.Zero(t, f.res.calls.Load())
}

// TestGate_ShutdownVoidsGrants covers a request on a tunnel that outlives the
// gate's context during shutdown: a grant recorded earlier no longer applies.
func TestGate_ShutdownVoidsGrants(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, grantRule())
	base, shutdown := context.WithCancel(t.Context())
	gate := broker.NewGate(base, broker.GateConfig{Approver: f.approver, Now: f.clock.Now, After: f.clock.After})
	f.hook = broker.Hook(f.engine, f.res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // closure

	in := f.send(newRequest(t))
	f.approver.next(t).answer <- broker.OutcomeApproved
	in.requireForwarded(t)

	shutdown()
	f.send(newRequest(t)).requireFailClosed(t)
	require.Equal(t, int64(1), f.approver.calls.Load())
	require.Equal(t, int64(1), f.res.calls.Load(), "a grant must not inject after the gate is cancelled")
}

// logLines hands each log line to the test as it is written.
type logLines chan string

func (l logLines) Write(p []byte) (int, error) {
	l <- string(p)
	return len(p), nil
}

// TestGate_GrantNobodyWaitsForStillLogs covers a grant dialog whose only
// request left while it was open. The answer it records must still leave
// an audit line.
func TestGate_GrantNobodyWaitsForStillLogs(t *testing.T) {
	t.Parallel()

	f := newGateFixture(t, nil, grantRule())
	lines := make(logLines, 16)
	gate := broker.NewGate(t.Context(), broker.GateConfig{
		Approver: f.approver, Now: f.clock.Now, After: f.clock.After,
		Logger: slog.New(slog.NewTextHandler(lines, nil)),
	})
	f.hook = broker.Hook(f.engine, f.res, config.OnNoMatchPassthrough, 0, true, nil, gate) //nolint:bodyclose // closure

	in := f.send(newRequest(t))
	p := f.approver.next(t)
	f.waitArmed(t, 1)
	in.watch.hangup()
	in.requireFailClosed(t)
	require.Contains(t, <-lines, "outcome=canceled")

	p.answer <- broker.OutcomeApproved
	select {
	case line := <-lines:
		require.Contains(t, line, "outcome=approved")
		require.Contains(t, line, "rule=api.example.com")
	case <-time.After(5 * time.Second):
		t.Fatal("the grant nobody waited for was recorded without a log line")
	}
	f.send(newRequest(t)).requireForwarded(t)
	require.Equal(t, int64(1), f.approver.calls.Load())
}
