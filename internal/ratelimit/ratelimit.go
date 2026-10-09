// Package ratelimit provides a fixed-window per-key event limiter.
package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
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

// Exceeded reports whether key has used up its current window, without
// recording an event.
func (l *Limiter) Exceeded(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.keys[key]
	return ok && now.Sub(w.start) < l.period && w.count >= l.limit
}

// ClientIP returns the remote IP of r. X-Forwarded-For is consulted only when
// the connection comes from a trusted proxy, and then read right to left up
// to the first hop that is not itself trusted; entries further left are
// client-supplied and could be forged.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !isTrusted(ip, trusted) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return host
		}
		if !isTrusted(hop, trusted) {
			return hop.Unmap().String()
		}
	}
	return host
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
