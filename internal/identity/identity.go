// Package identity provides proxy verifiers and opaque, revocable principals.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
)

// Generate creates an in-memory proxy key and its persistable verifier.
func Generate() (key, verifier string, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", errors.New("generate proxy key failed")
	}
	key = "pst_" + base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(key))
	return key, hex.EncodeToString(digest[:]), nil
}

// Verifier holds a validated name and private fixed-size key digest.
type Verifier struct {
	name   string
	digest [32]byte
}

// NewVerifier validates enrollment values without reproducing them in errors.
func NewVerifier(name, encoded string) (Verifier, error) {
	if !ValidName(name) {
		return Verifier{}, errors.New("invalid agent name")
	}
	digest, err := hex.DecodeString(encoded)
	if err != nil || len(digest) != sha256.Size {
		return Verifier{}, errors.New("invalid agent verifier")
	}
	v := Verifier{name: name}
	copy(v.digest[:], digest)
	return v, nil
}

// ValidName reports whether name is a case-sensitive ASCII agent identifier.
func ValidName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, c := range []byte(name) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// Authenticate compares fixed-size digests, including for an unknown name.
func (v Verifier) Authenticate(name, key string) bool {
	digest := sha256.Sum256([]byte(key))
	match := subtle.ConstantTimeCompare(v.digest[:], digest[:])
	return match == 1 && v.name != "" && name == v.name
}

// String prevents verifier material appearing in formatted diagnostics.
func (v Verifier) String() string { return "proxy verifier" }

// GoString prevents verifier material appearing in Go-syntax diagnostics.
func (v Verifier) GoString() string { return v.String() }

// Principal is one incarnation of a validated identity. Its pointer is opaque
// and can key approval grants without sharing them across rotations.
type Principal struct {
	name string
	done chan struct{}
	once sync.Once
}

// NewPrincipal creates an identity incarnation independent of prior handles.
func NewPrincipal(name string) *Principal {
	return &Principal{name: name, done: make(chan struct{})}
}

// Name returns only the validated agent's display name.
func (p *Principal) Name() string { return p.name }

// Done closes permanently when this incarnation is revoked.
func (p *Principal) Done() <-chan struct{} { return p.done }

// Revoke permanently invalidates this incarnation, even if enrollment is restored.
func (p *Principal) Revoke() { p.once.Do(func() { close(p.done) }) }

type contextKey struct{}

// WithPrincipal carries a validated principal without credential material.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// FromContext returns the authenticated principal, or nil on legacy traffic.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(contextKey{}).(*Principal)
	return p
}
