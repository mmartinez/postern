package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
	// Now defaults to the wall clock when nil.
	Now func() time.Time
	// After defaults to time.After when nil.
	After func(time.Duration) <-chan time.Time
	// Logger receives one line per decision; nil discards them.
	Logger *slog.Logger
}

// Gate asks the user to approve credential injections for rules that
// declare an approval block, either per request or as a grant that covers a
// key for the block's ttl. It shows one dialog at a time, in arrival order,
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
	grants   map[gateKey]time.Time
	flights  map[gateKey]*flight
	waiting  int
}

// flight is the one dialog that decides a grant, shared by every request
// for the key that waits on it. turn closes when the flight leaves the
// dialog queue; outcome and err are set before done closes. waiters is
// guarded by Gate.mu; cancel stops a flight that is still queued.
type flight struct {
	turn    chan struct{}
	done    chan struct{}
	outcome Outcome
	err     error
	waiters int
	cancel  context.CancelFunc
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
		grants:   make(map[gateKey]time.Time),
		flights:  make(map[gateKey]*flight),
	}
	if g.now == nil {
		// Windows must keep running while the machine sleeps, and the
		// monotonic reading stops then on Linux.
		g.now = func() time.Time { return time.Now().Round(0) }
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
// approval block, and requests under a live grant, pass at once. Every other
// path that does not end in an approval by a client that is still connected
// returns false, and the caller fails closed. A gate without an approver
// refuses every approval rule.
func (g *Gate) allow(req *http.Request, rule Rule, route, secretRef string) bool {
	if rule.Approval == nil {
		return true
	}
	log := func(o Outcome, err error) {
		g.logOutcome("broker approval", o, err,
			slog.String("host", canonicalHost(stripPort(req.URL.Host))),
			slog.String("rule", rule.Host),
			slog.String("route", route),
			slog.String("method", req.Method))
	}
	if g.approver == nil {
		log(OutcomeUnavailable, nil)
		return false
	}

	key := gateKey{approval: rule.Approval, route: route}
	g.mu.Lock()
	if err := g.base.Err(); err != nil {
		g.mu.Unlock()
		log(OutcomeUnavailable, err)
		return false
	}
	if g.liveLocked(g.grants, key) {
		g.mu.Unlock()
		return true
	}
	if g.liveLocked(g.cooldown, key) {
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
	ctx, cancel := context.WithCancel(req.Context())
	stopWatch := func() {}
	if w := HangupWatchFrom(ctx); w != nil {
		stopWatch = sync.OnceFunc(w(cancel))
	}
	// A flight can open its dialog as soon as it is joined, so the watch is
	// armed first and a request whose client already left never joins one.
	// Joining under the lock that checked the grant means a request either
	// sees the grant or waits on the flight that records it.
	ttl := rule.Approval.TTL
	var fl *flight
	if ttl > 0 && ctx.Err() == nil {
		fl = g.joinLocked(key, rule.Host, ttl, grantReason(req, rule, route, secretRef))
	}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.waiting--
		g.mu.Unlock()
	}()
	defer cancel()
	defer stopWatch()

	var outcome Outcome
	var err error
	switch {
	case fl != nil:
		outcome, err = g.await(ctx, key, fl)
	case ttl > 0:
		outcome, err = outcomeCanceled, ctx.Err()
	default:
		outcome, err = g.decide(ctx, key, rule.Host, 0, approvalReason(req, secretRef, route), nil)
	}
	if err != nil || outcome != OutcomeApproved {
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

// joinLocked adds a waiter to the flight that decides key's grant, starting
// one when no request is waiting on it yet. g.mu must be held.
func (g *Gate) joinLocked(key gateKey, rule string, ttl time.Duration, reason string) *flight {
	fl := g.flights[key]
	if fl == nil {
		fctx, cancel := context.WithCancel(g.base)
		fl = &flight{turn: make(chan struct{}), done: make(chan struct{}), cancel: cancel}
		g.flights[key] = fl
		go func() {
			fl.outcome, fl.err = g.decide(fctx, key, rule, ttl, reason, fl.turn)
			g.mu.Lock()
			if g.flights[key] == fl {
				delete(g.flights, key)
			}
			g.mu.Unlock()
			cancel()
			close(fl.done)
		}()
	}
	fl.waiters++
	return fl
}

// await waits for fl's answer until ctx is done. When its last waiter
// leaves, a flight that is still queued never opens its dialog.
func (g *Gate) await(ctx context.Context, key gateKey, fl *flight) (Outcome, error) {
	select {
	case <-fl.done:
		return fl.outcome, fl.err
	case <-ctx.Done():
	}
	g.mu.Lock()
	fl.waiters--
	last := fl.waiters == 0
	if last {
		fl.cancel()
		// An open dialog keeps running; a later request starts a new
		// flight, which queues behind it and takes its answer.
		if g.flights[key] == fl {
			delete(g.flights, key)
		}
	}
	g.mu.Unlock()
	if last {
		// The last waiter returns only once its flight has left the queue,
		// either cancelled or holding the dialog.
		select {
		case <-fl.turn:
		case <-fl.done:
		}
	}
	return outcomeCanceled, ctx.Err()
}

// decide waits its turn for the dialog until ctx is done, closes turn when
// it is not nil, then asks about key unless a cooldown or a grant recorded
// meanwhile already answers it. An answer is logged, since no request may be
// left waiting for it, and recorded for later requests: a grant of ttl when
// ttl is positive, a cooldown after a refusal.
func (g *Gate) decide(ctx context.Context, key gateKey, rule string, ttl time.Duration, reason string, turn chan<- struct{}) (Outcome, error) {
	if err := g.dialog.Acquire(ctx, 1); err != nil {
		if g.base.Err() != nil {
			return OutcomeUnavailable, err
		}
		return outcomeCanceled, err
	}
	defer g.dialog.Release(1)
	if turn != nil {
		close(turn)
	}
	if err := g.base.Err(); err != nil {
		return OutcomeUnavailable, err
	}
	g.mu.Lock()
	cooling, granted, spent := g.liveLocked(g.cooldown, key), g.liveLocked(g.grants, key), g.refusalsSpentLocked()
	g.mu.Unlock()
	switch {
	case cooling:
		return OutcomeCooldown, nil
	case granted:
		return OutcomeApproved, nil
	case spent:
		return OutcomeCooldown, errRefusalBudget
	}

	outcome, err := g.ask(reason)
	g.logOutcome("broker approval dialog", outcome, err, slog.String("rule", rule), slog.String("route", key.route))
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var m map[gateKey]time.Time
	var d time.Duration
	switch outcome {
	case OutcomeApproved:
		// A successful authentication clears pam_faillock's count too.
		g.refusals = nil
		if ttl <= 0 {
			return outcome, err
		}
		m, d = g.grants, ttl
	case OutcomeDenied, OutcomeDismissed, OutcomeTimeout:
		g.refusals = append(g.refusals, now)
		m, d = g.cooldown, denyCooldown
	default:
		return outcome, err
	}
	// Keys from a replaced ruleset are never read again, so expired entries
	// are swept here rather than only on lookup.
	for k, until := range m {
		if !now.Before(until) {
			delete(m, k)
		}
	}
	m[key] = now.Add(d)
	return outcome, err
}

// logOutcome writes one approval line: at info for an approval, else at warn.
func (g *Gate) logOutcome(msg string, o Outcome, err error, attrs ...slog.Attr) {
	level := slog.LevelWarn
	if o == OutcomeApproved {
		level = slog.LevelInfo
	}
	attrs = append([]slog.Attr{slog.String("outcome", string(o))}, attrs...)
	if err != nil {
		attrs = append(attrs, slog.Any("err", err))
	}
	g.logger.LogAttrs(context.Background(), level, msg, attrs...)
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
		if r.err != nil {
			return OutcomeUnavailable, r.err
		}
		return r.outcome, nil
	case <-timeout:
		dcancel()
		<-done
		return OutcomeTimeout, nil
	}
}

// liveLocked reports whether m holds an unexpired entry for key and drops
// the entry once it has expired. g.mu must be held.
func (g *Gate) liveLocked(m map[gateKey]time.Time, key gateKey) bool {
	until, ok := m[key]
	if !ok {
		return false
	}
	if g.now().Before(until) {
		return true
	}
	delete(m, key)
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

// approvalReason renders what the dialog asks the user to allow for one
// request.
func approvalReason(req *http.Request, secretRef, route string) string {
	return "send " + secretRef + " to " + requestLine(req) + " for " + who(route)
}

// grantReason renders what the dialog asks the user to grant: everything
// the rule lets the client do for the approval's ttl, and the request that
// asked first.
func grantReason(req *http.Request, rule Rule, route, secretRef string) string {
	methods := "all"
	if len(rule.Methods) > 0 {
		methods = strings.Join(rule.Methods, "/")
	}
	paths := "any path"
	if len(rule.Paths) > 0 {
		paths = "paths starting with " + strings.Join(rule.Paths, ", ")
	}
	// Duration.String spells out zero units ("1h0m0s"); the dialog drops them.
	ttl := rule.Approval.TTL.String()
	if strings.HasSuffix(ttl, "m0s") {
		ttl = ttl[:len(ttl)-2]
	}
	if strings.HasSuffix(ttl, "h0m") {
		ttl = ttl[:len(ttl)-2]
	}
	return "let " + who(route) + " use " + secretRef + " for " + methods + " requests to " + rule.Host +
		" on " + paths + " for " + ttl + " (first request: " + requestLine(req) + ")"
}

// requestLine renders req for a dialog. It comes from the client, so it is
// reduced to printable ASCII and capped.
func requestLine(req *http.Request) string {
	line := []byte(req.Method + " " + canonicalHost(stripPort(req.URL.Host)) + req.URL.EscapedPath())
	for i, b := range line {
		if b < 0x20 || b > 0x7e {
			line[i] = '?'
		}
	}
	if len(line) > maxRequestLine {
		return string(line[:maxRequestLine-1]) + "…"
	}
	return string(line)
}

func who(route string) string {
	if route == "" {
		return "any client"
	}
	return "agent " + route
}
