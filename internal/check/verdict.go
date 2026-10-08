package check

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
)

// Verdict is the top-level classification of a measurement.
type Verdict string

const (
	OK          Verdict = "ok"
	Blocked     Verdict = "blocked"
	Throttled   Verdict = "throttled"
	Anomaly     Verdict = "anomaly"
	Unreachable Verdict = "unreachable"
	Error       Verdict = "error"
)

// Stage records one step of a layered measurement (dns, tcp, tls, http, ...).
type Stage struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Ms    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}

func stage(name string, start time.Time, err error) Stage {
	s := Stage{Name: name, OK: err == nil, Ms: time.Since(start).Milliseconds()}
	if err != nil {
		s.Error = err.Error()
	}
	return s
}

// resolveTarget returns the allowed addresses of host, or the outcome to
// report when there are none.
func resolveTarget(ctx context.Context, env *Env, host string) ([]netip.Addr, *outcome) {
	start := time.Now()
	addrs, err := env.Guard.Resolve(ctx, host)
	if err == nil {
		return addrs, nil
	}
	out := &outcome{verdict: Unreachable, mechanism: "dns_failure", stages: []Stage{stage("dns", start, err)}, err: err.Error()}
	if classifyErr(err) == kindForbidden {
		out.verdict, out.mechanism = Error, "forbidden_target"
	}
	return nil, out
}

// failure kinds produced by classifyErr.
const (
	kindRST       = "rst"
	kindRefused   = "refused"
	kindTimeout   = "timeout"
	kindNoRoute   = "no_route"
	kindEOF       = "eof"
	kindAlert     = "alert"
	kindForbidden = "forbidden"
	kindOther     = "error"
)

// classifyErr maps a network error to a failure kind.
func classifyErr(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, netguard.ErrForbidden):
		return kindForbidden
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), strings.Contains(err.Error(), "connection reset"):
		return kindRST
	case errors.Is(err, syscall.ECONNREFUSED):
		return kindRefused
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT), isTimeout(err):
		return kindTimeout
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return kindNoRoute
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return kindEOF
	case strings.Contains(err.Error(), "remote error: tls:"):
		return kindAlert
	}
	return kindOther
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// judgeStageErr turns a failure at a stage into a verdict and mechanism such as
// "tcp_rst" or "tls_timeout". Resets, silent drops and premature closes on an
// established path are what middleboxes produce; refusals and missing routes
// are reported as unreachable because a closed port looks the same.
func judgeStageErr(stageName string, err error) (Verdict, string) {
	kind := classifyErr(err)
	mech := stageName + "_" + kind
	switch kind {
	case kindForbidden:
		return Error, "forbidden_target"
	case kindRST, kindTimeout:
		return Blocked, mech
	case kindEOF:
		if stageName == "tcp" {
			return Unreachable, mech
		}
		return Blocked, mech
	case kindRefused, kindNoRoute:
		return Unreachable, mech
	case kindAlert:
		return Anomaly, mech
	}
	return Error, mech
}
