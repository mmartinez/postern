package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/mmartinez/postern/internal/config"
)

// errRefusalBudget explains a request refused because the refusal budget is
// spent.
var errRefusalBudget = errors.New("dialogs paused: 2 ended without an approval within 15m")

const (
	// promptTimeout bounds how long a dialog stays open. It starts when the
	// dialog opens, not when the request starts waiting.
	promptTimeout = 60 * time.Second
	// denyCooldown is how long a refused key fails closed without prompting.
	denyCooldown = 30 * time.Second
	// maxWaiting caps requests waiting on approval. Each holds a buffered
	// body, so requests over the cap fail closed as unavailable.
	maxWaiting = 64
	// refusalBudget is how many dialogs may end without an approval within
	// refusalWindow before the gate stops prompting. pam_faillock counts each
	// such dialog as a failed login and, by default, locks the account after
	// three in 15 minutes.
	refusalBudget = 2
	refusalWindow = 15 * time.Minute
	// maxRequestLine caps the request line shown in a dialog.
	maxRequestLine = 120
)

// Outcome is the result of one approval decision.
type Outcome string

// Outcomes an Approver returns, plus the ones the gate decides itself.
const (
	// OutcomeApproved means the user authenticated and allowed the request.
	OutcomeApproved Outcome = "approved"
	// OutcomeDenied means the OS refused authorization.
	OutcomeDenied Outcome = "denied"
	// OutcomeDismissed means the user closed the dialog without answering.
	OutcomeDismissed Outcome = "dismissed"
	// OutcomeTimeout means the dialog got no answer within promptTimeout.
	OutcomeTimeout Outcome = "timeout"
	// OutcomeCooldown means the gate refused without a dialog: the key is
	// cooling down after a refusal, or the refusal budget is spent.
	OutcomeCooldown Outcome = "cooldown"
	// OutcomeUnavailable means no answer could be obtained: no dialog
	// backend, a backend error, a full queue, or shutdown.
	OutcomeUnavailable Outcome = "unavailable"
	// outcomeCanceled means the client left before its request was approved.
	outcomeCanceled Outcome = "canceled"
)

// Approver shows reason in an OS authentication dialog and blocks until the
// user answers or ctx is done. Cancelling ctx must close the dialog before
// Approve returns. A non-nil error comes with OutcomeUnavailable.
type Approver interface {
	Approve(ctx context.Context, reason string) (Outcome, error)
}

// GateConfig configures a Gate.
type GateConfig struct {
	// Approver shows the dialogs. Nil makes every approval rule fail closed.
	Approver Approver
	// Now defaults to time.Now when nil.
	Now func() time.Time
	// After defaults to time.After when nil.
	After func(time.Duration) <-chan time.Time
	// Logger receives one line per decision; nil discards them.
	Logger *slog.Logger
}

// Gate asks the user to approve each credential injection for rules that
// declare an approval block. It shows one dialog at a time, in arrival order,
// and is safe for concurrent use.
type Gate struct {
	base     context.Context
	approver Approver
	now      func() time.Time
	after    func(time.Duration) <-chan time.Time
	logger   *slog.Logger
	dialog   *semaphore.Weighted

	mu       sync.Mutex
	cooldown map[gateKey]time.Time
	// refusals holds when recent dialogs ended without an approval, oldest
	// first. It spans every key, as the login failures it mirrors do.
	refusals []time.Time
	waiting  int
}

// gateKey identifies what one decision covers: a rule of one loaded ruleset
// (FromConfigRules allocates a fresh approval block per rule per load) and
// the route the request selected, "" for rules without routes.
type gateKey struct {
	approval *config.Approval
	route    string
}

// NewGate returns a gate whose dialogs live as long as ctx. Cancelling ctx
// closes any open dialog and fails later approvals closed.
func NewGate(ctx context.Context, cfg GateConfig) *Gate {
	g := &Gate{
		base:     ctx,
		approver: cfg.Approver,
		now:      cfg.Now,
		after:    cfg.After,
		logger:   cfg.Logger,
		dialog:   semaphore.NewWeighted(1),
		cooldown: make(map[gateKey]time.Time),
	}
	if g.now == nil {
		g.now = time.Now
	}
	if g.after == nil {
		g.after = time.After
	}
	if g.logger == nil {
		g.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return g
}

// allow reports whether req may have secretRef injected. Rules without an
// approval block always pass. Every other path that does not end in an
// approval by a client that is still connected returns false, and the caller
// fails closed. A gate without an approver refuses every approval rule.
func (g *Gate) allow(req *http.Request, rule Rule, route, secretRef string) bool {
	if rule.Approval == nil {
		return true
	}
	log := func(o Outcome, err error) {
		level := slog.LevelWarn
		if o == OutcomeApproved {
			level = slog.LevelInfo
		}
		attrs := []slog.Attr{
			slog.String("outcome", string(o)),
			slog.String("host", canonicalHost(stripPort(req.URL.Host))),
			slog.String("rule", rule.Host),
			slog.String("route", route),
			slog.String("method", req.Method),
		}
		if err != nil {
			attrs = append(attrs, slog.Any("err", err))
		}
		g.logger.LogAttrs(context.Background(), level, "broker approval", attrs...)
	}
	if g.approver == nil {
		log(OutcomeUnavailable, nil)
		return false
	}

	key := gateKey{approval: rule.Approval, route: route}
	g.mu.Lock()
	if g.coolingLocked(key) {
		g.mu.Unlock()
		log(OutcomeCooldown, nil)
		return false
	}
	if g.waiting >= maxWaiting {
		g.mu.Unlock()
		log(OutcomeUnavailable, nil)
		return false
	}
	g.waiting++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.waiting--
		g.mu.Unlock()
	}()

	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	stopWatch := func() {}
	if w := HangupWatchFrom(ctx); w != nil {
		stopWatch = sync.OnceFunc(w(cancel))
	}
	defer stopWatch()

	if err := g.dialog.Acquire(ctx, 1); err != nil {
		log(outcomeCanceled, err)
		return false
	}
	defer g.dialog.Release(1)
	g.mu.Lock()
	cooling, spent := g.coolingLocked(key), g.refusalsSpentLocked()
	g.mu.Unlock()
	if cooling {
		log(OutcomeCooldown, nil)
		return false
	}
	if spent {
		log(OutcomeCooldown, errRefusalBudget)
		return false
	}
	if err := g.base.Err(); err != nil {
		log(OutcomeUnavailable, err)
		return false
	}

	outcome, err := g.ask(approvalReason(req, secretRef, route))
	if outcome == OutcomeDenied || outcome == OutcomeDismissed || outcome == OutcomeTimeout {
		g.mu.Lock()
		now := g.now()
		// Keys from a replaced ruleset are never read again, so expired
		// entries are swept here rather than only on lookup.
		for k, until := range g.cooldown {
			if !now.Before(until) {
				delete(g.cooldown, k)
			}
		}
		g.cooldown[key] = now.Add(denyCooldown)
		g.refusals = append(g.refusals, now)
		g.mu.Unlock()
	}
	if outcome == OutcomeApproved && err == nil {
		// A successful authentication clears pam_faillock's count too.
		g.mu.Lock()
		g.refusals = nil
		g.mu.Unlock()
	}
	if err != nil || outcome != OutcomeApproved {
		if err != nil {
			outcome = OutcomeUnavailable
		}
		log(outcome, err)
		return false
	}
	// Stopping the watch first delivers a hangup it has already read, so
	// the check below sees every disconnect that happened before the answer.
	stopWatch()
	if err := ctx.Err(); err != nil {
		log(outcomeCanceled, err)
		return false
	}
	log(OutcomeApproved, nil)
	return true
}

// ask shows one dialog. The dialog's context derives from the gate, not the
// request, so it stays open when the client leaves.
func (g *Gate) ask(reason string) (Outcome, error) {
	dctx, dcancel := context.WithCancel(g.base)
	defer dcancel()
	timeout := g.after(promptTimeout)
	type result struct {
		outcome Outcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{OutcomeUnavailable, fmt.Errorf("approver panicked: %v", r)}
			}
		}()
		o, err := g.approver.Approve(dctx, reason)
		done <- result{o, err}
	}()
	select {
	case r := <-done:
		return r.outcome, r.err
	case <-timeout:
		dcancel()
		<-done
		return OutcomeTimeout, nil
	}
}

// coolingLocked reports whether key is inside a refusal cooldown and drops
// the entry once it has expired. g.mu must be held.
func (g *Gate) coolingLocked(key gateKey) bool {
	until, ok := g.cooldown[key]
	if !ok {
		return false
	}
	if g.now().Before(until) {
		return true
	}
	delete(g.cooldown, key)
	return false
}

// refusalsSpentLocked reports whether refusalBudget dialogs ended without an
// approval inside refusalWindow, dropping older ones. g.mu must be held.
func (g *Gate) refusalsSpentLocked() bool {
	cutoff := g.now().Add(-refusalWindow)
	for len(g.refusals) > 0 && !g.refusals[0].After(cutoff) {
		g.refusals = g.refusals[1:]
	}
	return len(g.refusals) >= refusalBudget
}

// approvalReason renders what the dialog asks the user to allow. The request
// line comes from the client, so it is reduced to printable ASCII and capped.
func approvalReason(req *http.Request, secretRef, route string) string {
	line := []byte(req.Method + " " + canonicalHost(stripPort(req.URL.Host)) + req.URL.EscapedPath())
	for i, b := range line {
		if b < 0x20 || b > 0x7e {
			line[i] = '?'
		}
	}
	shown := string(line)
	if len(line) > maxRequestLine {
		shown = string(line[:maxRequestLine-1]) + "…"
	}
	who := "any client"
	if route != "" {
		who = "agent " + route
	}
	return "send " + secretRef + " to " + shown + " for " + who
}
