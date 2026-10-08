package check

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
)

type sniOptions struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	ControlSNI string `json:"control_sni"`
	TimeoutMs  int    `json:"timeout_ms"`
}

type sniAttempt struct {
	SNI        string `json:"sni"`
	State      string `json:"state"` // ok, alert, rst, timeout, eof, refused, no_route, error
	Ms         int64  `json:"ms"`
	TLSVersion string `json:"tls_version,omitempty"`
	Error      string `json:"error,omitempty"`
}

type sniEvidence struct {
	Endpoint string     `json:"endpoint"`
	Control  sniAttempt `json:"control"`
	Target   sniAttempt `json:"target"`
}

func prepareSNI(env *Env, target string, raw json.RawMessage, _ time.Duration) (execFunc, error) {
	o := sniOptions{Port: 443, ControlSNI: "www.cloudflare.com", TimeoutMs: 8000}
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(target); err == nil || !validHostname(target) {
		return nil, errors.New("target must be the hostname to test as SNI")
	}
	if !validHostname(o.ControlSNI) {
		return nil, errors.New("control_sni must be a hostname")
	}
	if o.Port < 1 || o.Port > 65535 || o.TimeoutMs < 500 || o.TimeoutMs > 15000 {
		return nil, errors.New("port must be 1-65535 and timeout_ms 500-15000")
	}
	var fixedIP netip.Addr
	if o.IP != "" {
		a, err := netip.ParseAddr(o.IP)
		if err != nil {
			return nil, errors.New("ip must be an IP address")
		}
		fixedIP = a
	}
	timeout := time.Duration(o.TimeoutMs) * time.Millisecond

	return func(ctx context.Context) outcome {
		ip := fixedIP
		if !ip.IsValid() {
			start := time.Now()
			addrs, err := env.Guard.Resolve(ctx, o.ControlSNI)
			if err != nil {
				return outcome{verdict: Error, mechanism: "sni_endpoint_unresolved", stages: []Stage{stage("dns", start, err)}, err: err.Error()}
			}
			ip = preferV4(addrs)
		}
		if err := env.Guard.Check(ip); err != nil {
			return outcome{verdict: Error, mechanism: "forbidden_target", err: err.Error()}
		}
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(o.Port))
		// Control first: censors that punish a forbidden SNI by blocking the
		// whole IP:port for a while would otherwise poison the control.
		ev := &sniEvidence{Endpoint: addr}
		ev.Control = handshakeSNI(ctx, env, addr, o.ControlSNI, timeout)
		ev.Target = handshakeSNI(ctx, env, addr, target, timeout)
		v, mech := judgeSNI(ev.Control.State, ev.Target.State)
		return outcome{verdict: v, mechanism: mech, evidence: ev}
	}, nil
}

func handshakeSNI(ctx context.Context, env *Env, addr, sni string, timeout time.Duration) (a sniAttempt) {
	a.SNI = sni
	start := time.Now()
	defer func() { a.Ms = time.Since(start).Milliseconds() }()
	conn, err := env.Guard.Dialer(timeout).DialContext(ctx, "tcp", addr)
	if err != nil {
		a.State, a.Error = attemptState(err), err.Error()
		return a
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	uc := utls.UClient(conn, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	defer uc.Close()
	if err := uc.HandshakeContext(ctx); err != nil {
		a.State, a.Error = attemptState(err), err.Error()
		return a
	}
	a.State = "ok"
	a.TLSVersion = utls.VersionName(uc.ConnectionState().Version)
	return a
}

func attemptState(err error) string {
	switch k := classifyErr(err); k {
	case kindRST:
		return "rst"
	case kindTimeout, kindEOF, kindAlert, kindRefused, kindNoRoute:
		return k
	}
	return "error"
}

// judgeSNI: a server alert still proves the ClientHello crossed the network,
// so only resets, drops and premature closes with a healthy control count.
func judgeSNI(control, target string) (Verdict, string) {
	if control != "ok" && control != "alert" {
		return Unreachable, "sni_control_failed"
	}
	switch target {
	case "ok", "alert":
		return OK, ""
	case "rst":
		return Blocked, "tls_sni_rst"
	case "timeout":
		return Blocked, "tls_sni_timeout"
	case "eof":
		return Blocked, "tls_sni_eof"
	}
	return Anomaly, "tls_sni_" + target
}
