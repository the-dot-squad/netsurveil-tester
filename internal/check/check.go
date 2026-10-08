// Package check runs individual censorship measurements. Callers see one
// interface — Validate and Run over a Spec — and one Result shape; per-type
// options, limits and classification live behind it.
package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
)

// Spec describes one measurement request.
type Spec struct {
	Type     string          `json:"type"`
	Target   string          `json:"target"`
	Options  json.RawMessage `json:"options,omitempty"`
	TimeoutS int             `json:"timeout_s,omitempty"`
}

// Result is the outcome of one measurement.
type Result struct {
	Type       string          `json:"type"`
	Target     string          `json:"target"`
	Verdict    Verdict         `json:"verdict"`
	Mechanism  string          `json:"mechanism,omitempty"`
	Stages     []Stage         `json:"stages,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	DurationMs int64           `json:"duration_ms"`
}

// Env carries the dependencies checks need.
type Env struct {
	Guard   *netguard.Guard
	NodeID  string
	Version string
}

// outcome is what a check implementation produces; Run wraps it into a Result.
type outcome struct {
	verdict   Verdict
	mechanism string
	stages    []Stage
	evidence  any
	err       string
}

type execFunc func(ctx context.Context) outcome

type definition struct {
	defaultTimeout time.Duration
	maxTimeout     time.Duration
	// prepare validates target and options and returns the measurement to run
	// within budget, rejecting options that cannot finish in it.
	prepare func(env *Env, target string, opts json.RawMessage, budget time.Duration) (execFunc, error)
}

// resolveSlack is the share of a budget reserved for resolving the target.
const resolveSlack = 5 * time.Second

// fitBudget rejects options whose worst-case run time exceeds budget.
func fitBudget(worst, budget time.Duration) error {
	if worst > budget {
		return fmt.Errorf("these options can take up to %ds, more than the %ds timeout; reduce them or raise timeout_s",
			int((worst+time.Second-1)/time.Second), int(budget/time.Second))
	}
	return nil
}

var registry = map[string]definition{
	"web":        {30 * time.Second, 60 * time.Second, prepareWeb},
	"dns":        {15 * time.Second, 30 * time.Second, prepareDNS},
	"tcp":        {20 * time.Second, 45 * time.Second, prepareTCP},
	"sni":        {20 * time.Second, 45 * time.Second, prepareSNI},
	"quic":       {20 * time.Second, 45 * time.Second, prepareQUIC},
	"ping":       {20 * time.Second, 45 * time.Second, preparePing},
	"traceroute": {60 * time.Second, 120 * time.Second, prepareTraceroute},
	"throttle":   {45 * time.Second, 60 * time.Second, prepareThrottle},
	"info":       {15 * time.Second, 30 * time.Second, prepareInfo},
}

// Types lists the supported check types.
func Types() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MaxTimeout is the longest any single check may run.
const MaxTimeout = 120 * time.Second

// Runner executes checks against its Env.
type Runner struct {
	env Env
	log *slog.Logger
}

// NewRunner returns a runner; env.Guard must be set.
func NewRunner(env Env, log *slog.Logger) *Runner {
	return &Runner{env: env, log: log}
}

// Validate reports whether s is acceptable without running it.
func (r *Runner) Validate(s Spec) error {
	_, _, err := r.prepare(s)
	return err
}

func (r *Runner) prepare(s Spec) (execFunc, time.Duration, error) {
	def, ok := registry[s.Type]
	if !ok {
		return nil, 0, fmt.Errorf("unknown check type %q (supported: %v)", s.Type, Types())
	}
	if len(s.Target) > 2048 {
		return nil, 0, errors.New("target too long")
	}
	timeout := def.defaultTimeout
	if s.TimeoutS != 0 {
		requested := time.Duration(s.TimeoutS) * time.Second
		if s.TimeoutS < 0 || requested > def.maxTimeout {
			return nil, 0, fmt.Errorf("timeout_s must be between 1 and %d for %s", int(def.maxTimeout/time.Second), s.Type)
		}
		timeout = requested
	}
	exec, err := def.prepare(&r.env, s.Target, s.Options, timeout)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", s.Type, err)
	}
	return exec, timeout, nil
}

// Run executes s. It never panics and always returns a Result. A check stopped
// by cancellation of ctx reports error/cancelled, and one that ran out of its
// own timeout reports error/check_timeout, whatever it observed by then: an
// interrupted measurement must not read as a network verdict.
func (r *Runner) Run(ctx context.Context, s Spec) (res Result) {
	start := time.Now()
	res = Result{Type: s.Type, Target: s.Target, StartedAt: start.UTC()}
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("check panicked", "type", s.Type, "panic", p)
			res.Verdict, res.Mechanism, res.Error = Error, "", "internal error"
		}
		res.DurationMs = time.Since(start).Milliseconds()
	}()

	exec, timeout, err := r.prepare(s)
	if err != nil {
		res.Verdict, res.Error = Error, err.Error()
		return res
	}
	deadline := time.Now().Add(timeout)
	cctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	out := exec(cctx)
	res.Verdict, res.Mechanism, res.Stages, res.Error = out.verdict, out.mechanism, out.stages, out.err
	switch {
	case ctx.Err() != nil:
		res.Verdict, res.Mechanism, res.Error = Error, "cancelled", "check cancelled"
	// A socket deadline derived from cctx can fire before cctx's own timer
	// marks it done, so cctx.Err() alone may still be nil here.
	case cctx.Err() != nil || !time.Now().Before(deadline):
		res.Verdict, res.Mechanism = Error, "check_timeout"
		res.Error = fmt.Sprintf("check did not finish within %ds", int(timeout/time.Second))
	}
	if out.evidence != nil {
		if b, err := json.Marshal(out.evidence); err == nil {
			res.Evidence = b
		}
	}
	return res
}

// decodeOptions strictly decodes raw into dst; empty raw leaves dst untouched.
func decodeOptions(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("options: %w", err)
	}
	return nil
}
