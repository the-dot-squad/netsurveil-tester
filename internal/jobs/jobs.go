// Package jobs runs batches of checks asynchronously and keeps their results
// in memory for a bounded time.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/check"
)

// State is the lifecycle stage of a job.
type State string

const (
	Running   State = "running"
	Done      State = "done"
	Cancelled State = "cancelled"
)

// Job is a snapshot of a submitted batch. Results keep submission order;
// a nil entry is a check that has not finished yet.
type Job struct {
	ID         string          `json:"id"`
	State      State           `json:"state"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Results    []*check.Result `json:"results"`
}

// Limits bound resource use.
type Limits struct {
	MaxChecks        int           // per job
	CheckConcurrency int           // across all jobs
	MaxActiveJobs    int           // running at once
	TTL              time.Duration // retention after completion
}

// DefaultLimits are the production limits.
var DefaultLimits = Limits{MaxChecks: 20, CheckConcurrency: 4, MaxActiveJobs: 8, TTL: 15 * time.Minute}

var (
	ErrBusy          = errors.New("too many active jobs")
	ErrTooManyChecks = errors.New("too many checks in one job")
	ErrNoChecks      = errors.New("job has no checks")
)

// RunFunc executes one check.
type RunFunc func(ctx context.Context, s check.Spec) check.Result

type entry struct {
	job    Job
	cancel context.CancelFunc
	done   chan struct{}
}

// Store owns all jobs. It is safe for concurrent use.
type Store struct {
	run    RunFunc
	limits Limits
	sem    chan struct{}
	ctx    context.Context
	stop   context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	jobs   map[string]*entry
	active int
}

// New starts a store; Close stops it and cancels running jobs.
func New(run RunFunc, l Limits) *Store {
	ctx, stop := context.WithCancel(context.Background())
	s := &Store{run: run, limits: l, sem: make(chan struct{}, l.CheckConcurrency), ctx: ctx, stop: stop, jobs: map[string]*entry{}}
	s.wg.Go(s.janitor)
	return s
}

// Submit starts a job running specs, which the caller has already validated.
func (s *Store) Submit(specs []check.Spec) (Job, error) {
	switch {
	case len(specs) == 0:
		return Job{}, ErrNoChecks
	case len(specs) > s.limits.MaxChecks:
		return Job{}, ErrTooManyChecks
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= s.limits.MaxActiveJobs {
		return Job{}, ErrBusy
	}
	ctx, cancel := context.WithCancel(s.ctx)
	e := &entry{
		job:    Job{ID: newID(), State: Running, CreatedAt: time.Now().UTC(), Results: make([]*check.Result, len(specs))},
		cancel: cancel,
		done:   make(chan struct{}),
	}
	s.jobs[e.job.ID] = e
	s.active++
	s.wg.Go(func() { s.execute(ctx, e, specs) })
	return snapshot(e), nil
}

func (s *Store) execute(ctx context.Context, e *entry, specs []check.Spec) {
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Go(func() {
			var r check.Result
			select {
			case s.sem <- struct{}{}:
				r = s.run(ctx, spec)
				<-s.sem
			case <-ctx.Done():
				r = check.Result{Type: spec.Type, Target: spec.Target, Verdict: check.Error, Mechanism: "cancelled", Error: "check cancelled", StartedAt: time.Now().UTC()}
			}
			s.mu.Lock()
			e.job.Results[i] = &r
			s.mu.Unlock()
		})
	}
	wg.Wait()

	s.mu.Lock()
	now := time.Now().UTC()
	e.job.FinishedAt = &now
	e.job.State = Done
	if ctx.Err() != nil {
		e.job.State = Cancelled
	}
	s.active--
	s.mu.Unlock()
	e.cancel()
	close(e.done)
}

// Get returns a snapshot of job id.
func (s *Store) Get(id string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.jobs[id]
	if !ok {
		return Job{}, false
	}
	return snapshot(e), true
}

// Wait blocks until job id finishes or ctx ends, then returns its snapshot.
func (s *Store) Wait(ctx context.Context, id string) (Job, bool) {
	s.mu.Lock()
	e, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		return Job{}, false
	}
	select {
	case <-e.done:
	case <-ctx.Done():
	}
	return s.Get(id)
}

// Cancel stops a running job; finished checks keep their results.
func (s *Store) Cancel(id string) bool {
	s.mu.Lock()
	e, ok := s.jobs[id]
	s.mu.Unlock()
	if ok {
		e.cancel()
	}
	return ok
}

// Close cancels all jobs and waits for them to stop.
func (s *Store) Close() {
	s.stop()
	s.wg.Wait()
}

func (s *Store) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.prune(now)
		}
	}
}

func (s *Store) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.jobs {
		if e.job.FinishedAt != nil && now.Sub(*e.job.FinishedAt) > s.limits.TTL {
			delete(s.jobs, id)
		}
	}
}

// snapshot copies the job; caller holds s.mu. Result values are immutable once stored.
func snapshot(e *entry) Job {
	j := e.job
	j.Results = append([]*check.Result(nil), e.job.Results...)
	return j
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
