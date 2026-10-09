package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func FuzzClientIP(f *testing.F) {
	f.Add("10.1.2.3:4000", "198.51.100.9, 10.9.9.9")
	f.Add("203.0.113.5:4000", "")
	f.Add("[::1]:80", "::ffff:192.0.2.1,,  ,x")
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	f.Fuzz(func(t *testing.T, remote, xff string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		got := ClientIP(r, trusted)
		if ip, err := netip.ParseAddr(got); err == nil && isTrusted(ip, trusted) {
			if base := ClientIP(r, nil); base != got {
				t.Fatalf("returned trusted hop %s instead of the connection address %s", got, base)
			}
		}
	})
}
