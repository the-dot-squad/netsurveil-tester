package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(2, time.Minute)
	l.now = func() time.Time { return now }
	for i, want := range []bool{true, true, false} {
		if got := l.Allow("a"); got != want {
			t.Fatalf("call %d: allowed %v, want %v", i+1, got, want)
		}
	}
	if !l.Allow("b") {
		t.Fatal("keys must be independent")
	}
	now = now.Add(time.Minute)
	if !l.Allow("a") {
		t.Fatal("window must reset")
	}
}

func TestExceeded(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(2, time.Minute)
	l.now = func() time.Time { return now }
	for range 5 {
		if l.Exceeded("a") {
			t.Fatal("Exceeded must not record events")
		}
	}
	l.Allow("a")
	if l.Exceeded("a") {
		t.Fatal("exceeded after 1 of 2")
	}
	l.Allow("a")
	if !l.Exceeded("a") || l.Exceeded("b") {
		t.Fatal("limit reached must report exceeded for that key only")
	}
	now = now.Add(time.Minute)
	if l.Exceeded("a") {
		t.Fatal("window must reset")
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, remote, xff string
		trusted           []netip.Prefix
		want              string
	}{
		{"direct ignores xff", "203.0.113.5:4000", "198.51.100.9", trusted, "203.0.113.5"},
		{"no trust configured", "10.1.2.3:4000", "198.51.100.9", nil, "10.1.2.3"},
		{"trusted proxy", "10.1.2.3:4000", "198.51.100.9", trusted, "198.51.100.9"},
		{"proxy chain", "10.1.2.3:4000", "198.51.100.9, 10.9.9.9", trusted, "198.51.100.9"},
		{"forged leftmost", "10.1.2.3:4000", "192.0.2.66, 198.51.100.9", trusted, "198.51.100.9"},
		{"mapped hop", "10.1.2.3:4000", "::ffff:198.51.100.9", trusted, "198.51.100.9"},
		{"missing xff", "10.1.2.3:4000", "", trusted, "10.1.2.3"},
		{"garbage hop", "10.1.2.3:4000", "nonsense", trusted, "10.1.2.3"},
		{"all trusted", "10.1.2.3:4000", "10.4.4.4", trusted, "10.1.2.3"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r, c.trusted); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
