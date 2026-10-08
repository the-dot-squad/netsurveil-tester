package jobs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/check"
)

func slowRun(d time.Duration, running *atomic.Int32, peak *atomic.Int32) RunFunc {
	return func(ctx context.Context, s check.Spec) check.Result {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer running.Add(-1)
		select {
		case <-time.After(d):
			return check.Result{Type: s.Type, Target: s.Target, Verdict: check.OK}
		case <-ctx.Done():
			return check.Result{Type: s.Type, Target: s.Target, Verdict: check.Error, Mechanism: "cancelled"}
		}
	}
}

func specs(n int) []check.Spec {
	out := make([]check.Spec, n)
	for i := range out {
		out[i] = check.Spec{Type: "web", Target: "x"}
	}
	return out
}

func TestSubmitWaitConcurrencyAndOrder(t *testing.T) {
	var running, peak atomic.Int32
	s := New(slowRun(20*time.Millisecond, &running, &peak), Limits{MaxChecks: 10, CheckConcurrency: 2, MaxActiveJobs: 2, TTL: time.Minute})
	defer s.Close()

	in := specs(6)
	for i := range in {
		in[i].Target = string(rune('a' + i))
	}
	j, err := s.Submit(in)
	if err != nil || j.State != Running {
		t.Fatalf("submit: %+v %v", j, err)
	}
	j, _ = s.Wait(context.Background(), j.ID)
	if j.State != Done || j.FinishedAt == nil {
		t.Fatalf("state %s", j.State)
	}
	for i, r := range j.Results {
		if r == nil || r.Target != in[i].Target {
			t.Fatalf("result %d out of order: %+v", i, r)
		}
	}
	if peak.Load() > 2 {
		t.Fatalf("concurrency %d exceeded limit", peak.Load())
	}
}

func TestLimits(t *testing.T) {
	var running, peak atomic.Int32
	s := New(slowRun(200*time.Millisecond, &running, &peak), Limits{MaxChecks: 2, CheckConcurrency: 1, MaxActiveJobs: 1, TTL: time.Minute})
	defer s.Close()
	if _, err := s.Submit(nil); !errors.Is(err, ErrNoChecks) {
		t.Errorf("empty: %v", err)
	}
	if _, err := s.Submit(specs(3)); !errors.Is(err, ErrTooManyChecks) {
		t.Errorf("too many: %v", err)
	}
	if _, err := s.Submit(specs(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(specs(1)); !errors.Is(err, ErrBusy) {
		t.Errorf("busy: %v", err)
	}
}

func TestCancelAndPrune(t *testing.T) {
	var running, peak atomic.Int32
	s := New(slowRun(5*time.Second, &running, &peak), Limits{MaxChecks: 5, CheckConcurrency: 1, MaxActiveJobs: 1, TTL: time.Millisecond})
	defer s.Close()
	j, _ := s.Submit(specs(3))
	if !s.Cancel(j.ID) {
		t.Fatal("cancel unknown")
	}
	j, _ = s.Wait(context.Background(), j.ID)
	if j.State != Cancelled {
		t.Fatalf("state %s", j.State)
	}
	for _, r := range j.Results {
		if r == nil || r.Mechanism != "cancelled" {
			t.Fatalf("result %+v", r)
		}
	}
	s.prune(time.Now().Add(time.Second))
	if _, ok := s.Get(j.ID); ok {
		t.Fatal("finished job not pruned after TTL")
	}
	if _, err := s.Submit(specs(1)); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}
