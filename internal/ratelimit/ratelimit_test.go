package ratelimit

import (
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
