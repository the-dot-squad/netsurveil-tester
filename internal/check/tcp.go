package check

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Port dials run tcpParallel at a time, each after a random pause.
const (
	tcpParallel = 3
	tcpMinPause = 50 * time.Millisecond
	tcpMaxPause = 250 * time.Millisecond
)

type tcpOptions struct {
	Ports     []int `json:"ports"`
	TimeoutMs int   `json:"timeout_ms"`
}

type portResult struct {
	Port  int    `json:"port"`
	State string `json:"state"` // open, refused, reset, timeout, no_route, error
	Ms    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}

type tcpEvidence struct {
	IP    string       `json:"ip"`
	Ports []portResult `json:"ports"`
}

func prepareTCP(env *Env, target string, raw json.RawMessage, budget time.Duration) (execFunc, error) {
	o := tcpOptions{TimeoutMs: 5000}
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(target); err != nil && !validHostname(target) {
		return nil, errors.New("target must be a hostname or IP")
	}
	if len(o.Ports) == 0 {
		o.Ports = []int{80, 443}
	}
	if len(o.Ports) > 32 {
		return nil, errors.New("at most 32 ports")
	}
	seen := map[int]bool{}
	for _, p := range o.Ports {
		if p < 1 || p > 65535 || seen[p] {
			return nil, errors.New("ports must be unique and within 1-65535")
		}
		seen[p] = true
	}
	if o.TimeoutMs < 100 || o.TimeoutMs > 15000 {
		return nil, errors.New("timeout_ms must be within 100-15000")
	}
	timeout := time.Duration(o.TimeoutMs) * time.Millisecond
	rounds := (len(o.Ports) + tcpParallel - 1) / tcpParallel
	if err := fitBudget(resolveSlack+time.Duration(rounds)*(timeout+tcpMaxPause), budget); err != nil {
		return nil, err
	}

	return func(ctx context.Context) outcome {
		addrs, fail := resolveTarget(ctx, env, target)
		if fail != nil {
			return *fail
		}
		ip := preferV4(addrs)
		ev := &tcpEvidence{IP: ip.String(), Ports: make([]portResult, len(o.Ports))}

		// Few dials at a time with jittered starts, so a batch of ports does not
		// read as a port scan to an IDS on the node's network.
		var wg sync.WaitGroup
		sem := make(chan struct{}, tcpParallel)
		for i, p := range o.Ports {
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				select {
				case <-time.After(tcpMinPause + rand.N(tcpMaxPause-tcpMinPause)):
				case <-ctx.Done():
				}
				ev.Ports[i] = probePort(ctx, env, ip, p, timeout)
			})
		}
		wg.Wait()
		v, mech := judgePorts(ev.Ports)
		return outcome{verdict: v, mechanism: mech, evidence: ev}
	}, nil
}

func probePort(ctx context.Context, env *Env, ip netip.Addr, port int, timeout time.Duration) portResult {
	start := time.Now()
	conn, err := env.Guard.Dialer(timeout).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	r := portResult{Port: port, Ms: time.Since(start).Milliseconds()}
	if err == nil {
		_ = conn.Close()
		r.State = "open"
		return r
	}
	r.Error = err.Error()
	switch classifyErr(err) {
	case kindRefused:
		r.State = "refused"
	case kindRST:
		r.State = "reset"
	case kindTimeout:
		r.State = "timeout"
	case kindNoRoute:
		r.State = "no_route"
	default:
		r.State = "error"
	}
	return r
}

// judgePorts reports the worst port: silent drops and resets are firewall
// signatures; refusals look identical to a closed port, so they are unreachable.
func judgePorts(ports []portResult) (Verdict, string) {
	has := map[string]bool{}
	for _, p := range ports {
		has[p.State] = true
	}
	switch {
	case has["timeout"]:
		return Blocked, "tcp_timeout"
	case has["reset"]:
		return Blocked, "tcp_rst"
	case has["refused"]:
		return Unreachable, "tcp_refused"
	case has["no_route"]:
		return Unreachable, "tcp_no_route"
	case has["error"]:
		return Error, "tcp_error"
	}
	return OK, ""
}
