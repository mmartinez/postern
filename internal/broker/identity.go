package broker

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

type activeWork struct {
	principal *identity.Principal
	cancel    context.CancelFunc
	close     func()
}

// Authenticate verifies credentials against one immutable snapshot. Registration
// must still call Admit to close the authentication/publication race.
func (e *Engine) Authenticate(name, key string) *identity.Principal {
	a := e.snapshot.Load().agents[name]
	if !a.verifier.Authenticate(name, key) {
		return nil
	}
	return a.principal
}

// Current reports whether p is still the active incarnation.
func (e *Engine) Current(p *identity.Principal) bool {
	if p == nil {
		return false
	}
	return e.snapshot.Load().agents[p.Name()].principal == p
}

// Admit registers cancellable work under the publication lock. close must force
// teardown without waiting for a protocol-level graceful close. release is safe
// to call repeatedly. No network or dialog work runs under the lifecycle lock.
func (e *Engine) Admit(ctx context.Context, p *identity.Principal, closeWork func()) (context.Context, func(), bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.Current(p) || !e.authorizedSnapshot(ctx) || ctx.Err() != nil {
		return ctx, func() {}, false
	}
	ctx, cancel := context.WithCancel(ctx)
	w := &activeWork{principal: p, cancel: cancel, close: closeWork}
	e.work[w] = struct{}{}
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			e.mu.Lock()
			delete(e.work, w)
			e.mu.Unlock()
			cancel()
		})
	}, true
}

// Publish validates the entire enrollment then publishes identities and rules
// together. Revocation cancels work and completes teardown before returning.
func (e *Engine) Publish(rules []Rule, agents []config.Agent) error {
	next := &engineSnapshot{rules: append([]Rule(nil), rules...), agents: make(map[string]enrolledAgent)}
	seen := make(map[string]bool)
	for _, a := range agents {
		v, err := identity.NewVerifier(a.Name, a.KeySHA256)
		if err != nil {
			return err
		}
		if _, exists := next.agents[a.Name]; exists || seen[strings.ToLower(a.KeySHA256)] {
			return errors.New("duplicate identity enrollment")
		}
		next.agents[a.Name] = enrolledAgent{verifier: v}
		seen[strings.ToLower(a.KeySHA256)] = true
	}
	e.mu.Lock()
	previous := e.snapshot.Load()
	next.epoch = &authorizationEpoch{}
	if reflect.DeepEqual(previous.rules, next.rules) {
		next.epoch = previous.epoch
		next.rules = previous.rules
	}
	for name, a := range next.agents {
		old := previous.agents[name]
		if old.principal != nil && old.verifier == a.verifier {
			a.principal = old.principal
		} else {
			a.principal = identity.NewPrincipal(name)
		}
		next.agents[name] = a
	}
	for name, old := range previous.agents {
		if next.agents[name].principal != old.principal {
			old.principal.Revoke()
		}
	}
	e.snapshot.Store(next)
	var revoked []*activeWork
	for w := range e.work {
		if !e.Current(w.principal) {
			delete(e.work, w)
			revoked = append(revoked, w)
		}
	}
	e.mu.Unlock()
	for _, w := range revoked {
		w.cancel()
		if w.close != nil {
			w.close()
		}
	}
	return nil
}

type authorizationKey struct{}

func (e *Engine) authorizedSnapshot(ctx context.Context) bool {
	selected, _ := ctx.Value(authorizationKey{}).(*authorizationEpoch)
	return selected == nil || selected == e.snapshot.Load().epoch
}

// Authorize checks the identity and the rule snapshot that admitted the request.
func (e *Engine) Authorize(req *http.Request) bool {
	return e.Current(identity.FromContext(req.Context())) && e.authorizedSnapshot(req.Context()) && req.Context().Err() == nil
}

type guardedResolver struct {
	engine *Engine
	next   Resolver
}

func (r guardedResolver) Resolve(ctx context.Context, vaultID, ref string) (string, error) {
	if r.next == nil {
		return "", errors.New("broker resolver requires restart")
	}
	p := identity.FromContext(ctx)
	if p == nil {
		if !r.engine.authorizedSnapshot(ctx) {
			return "", errors.New("authorization changed")
		}
		return r.next.Resolve(ctx, vaultID, ref)
	}
	ctx, release, ok := r.engine.Admit(ctx, p, nil)
	if !ok {
		return "", errors.New("authorization changed")
	}
	defer release()
	return r.next.Resolve(ctx, vaultID, ref)
}
