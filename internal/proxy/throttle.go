package proxy

import (
	"net/netip"
	"sync"
	"time"
)

type failureBucket struct {
	tokens    float64
	last      time.Time
	delayed   int
	exponent  uint
	exhausted bool
}

type failureThrottle struct {
	onTransition func(string, bool)
	mu           sync.Mutex
	now          func() time.Time
	sources      map[string]*failureBucket
	fallback     failureBucket
	delayed      int
}

func newFailureThrottle(now func() time.Time) *failureThrottle {
	return &failureThrottle{now: now, sources: make(map[string]*failureBucket), fallback: failureBucket{tokens: 5, last: now()}}
}

func failureSource(peer string) string {
	a, err := netip.ParseAddrPort(peer)
	if err != nil {
		return "fallback"
	}
	ip := a.Addr().Unmap()
	if ip.IsLoopback() {
		return "loopback"
	}
	return ip.String()
}

func (f *failureThrottle) failure(peer string) (time.Duration, func(), bool) {
	f.mu.Lock()
	source := failureSource(peer)
	changed, exhausted := false, false
	defer func() {
		f.mu.Unlock()
		if changed && f.onTransition != nil {
			f.onTransition(source, exhausted)
		}
	}()
	now := f.now()
	b := f.sources[source]
	if b == nil {
		for key, bucket := range f.sources {
			if bucket.delayed == 0 && now.Sub(bucket.last) >= 10*time.Minute {
				delete(f.sources, key)
			}
		}
		if len(f.sources) >= 4096 || source == "fallback" {
			b = &f.fallback
		} else {
			b = &failureBucket{tokens: 5, last: now}
			f.sources[source] = b
		}
	}
	b.tokens = min(5, b.tokens+max(0, now.Sub(b.last).Seconds()))
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		if b.exhausted {
			b.exhausted = false
			changed = true
		}
		b.exponent = 0
		return 0, func() {}, true
	}
	if !b.exhausted {
		b.exhausted = true
		changed, exhausted = true, true
	}
	if b.delayed >= 4 || f.delayed >= 256 {
		return 0, func() {}, false
	}
	delay := min(2*time.Second, 100*time.Millisecond*time.Duration(1<<min(b.exponent, 5)))
	b.exponent = min(b.exponent+1, 5)
	b.delayed++
	f.delayed++
	var once sync.Once
	return delay, func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			b.delayed--
			f.delayed--
		})
	}, true
}
