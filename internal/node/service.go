// Package node exposes the check runner to authenticated controllers, either
// over inbound HTTP or by pulling requests from an S3 feed. Both paths share one
// request handler and one codec.
package node

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

// MaxInboundWait bounds how long an inbound submit with wait=true blocks.
const MaxInboundWait = 60 * time.Second

const cancelSettle = 5 * time.Second

// Service authenticates requests and runs them against the job store.
type Service struct {
	codec   *api.Codec
	runner  *check.Runner
	store   *jobs.Store
	version string
	log     *slog.Logger

	// lastPoll is the unix-nano time of the last successful feed poll; zero
	// until Pull has succeeded once.
	lastPoll atomic.Int64
	pulling  atomic.Bool
}

// New wires a service.
func New(codec *api.Codec, runner *check.Runner, store *jobs.Store, version string, log *slog.Logger) *Service {
	return &Service{codec: codec, runner: runner, store: store, version: version, log: log}
}

// handle executes an authenticated request. A submit with Wait blocks up to wait.
func (s *Service) handle(ctx context.Context, req api.Request, wait time.Duration) api.Response {
	resp := s.response(req)
	switch req.Op {
	case api.OpSubmit:
		for i, spec := range req.Checks {
			if err := s.runner.Validate(spec); err != nil {
				resp.Error = fmt.Sprintf("check %d: %v", i, err)
				return resp
			}
		}
		job, err := s.store.Submit(req.Checks)
		if err != nil {
			resp.Error = err.Error()
			return resp
		}
		s.log.Info("job submitted", "job", job.ID, "checks", len(req.Checks), "types", checkTypes(req.Checks))
		if req.Wait {
			wctx, cancel := context.WithTimeout(ctx, wait)
			job, _ = s.store.Wait(wctx, job.ID)
			cancel()
		}
		resp.Job = &job
	case api.OpGet, api.OpCancel:
		if req.Op == api.OpCancel {
			if !s.store.Cancel(req.JobID) {
				resp.Error = "unknown job"
				return resp
			}
			// Checks stop on cancellation promptly; report the settled state when they do.
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cancelSettle)
			s.store.Wait(wctx, req.JobID)
			cancel()
		}
		job, ok := s.store.Get(req.JobID)
		if !ok {
			resp.Error = "unknown job"
			return resp
		}
		resp.Job = &job
	default:
		resp.Error = fmt.Sprintf("unknown op %q", req.Op)
	}
	return resp
}

func (s *Service) response(req api.Request) api.Response {
	return api.Response{RID: req.RID, Node: s.codec.NodeID(), Version: s.version}
}

func checkTypes(specs []check.Spec) []string {
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.Type
	}
	return out
}
