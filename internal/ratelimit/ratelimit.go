// Package ratelimit provides a fixed-window per-key request limiter.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const maxKeys = 50_000

type window struct {
	start time.Time
	count int
}

// Limiter allows up to limit events per key in each window.
type Limiter struct {
	limit  int
	period time.Duration
	now    func() time.Time

	mu   sync.Mutex
	keys map[string]*window
}

// New returns a limiter allowing limit events per period per key.
func New(limit int, period time.Duration) *Limiter {
	return &Limiter{limit: limit, period: period, now: time.Now, keys: map[string]*window{}}
}

// Allow records an event for key and reports whether it is within the limit.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.keys) >= maxKeys {
		for k, w := range l.keys {
			if now.Sub(w.start) >= l.period {
				delete(l.keys, k)
			}
		}
	}
	w, ok := l.keys[key]
	if !ok || now.Sub(w.start) >= l.period {
		if !ok && len(l.keys) >= maxKeys {
			return false
		}
		l.keys[key] = &window{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= l.limit
}

// ClientIP returns the remote IP of r without trusting forwarding headers.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
