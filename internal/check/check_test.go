package check

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
)

func testRunner() *Runner {
	return NewRunner(Env{Guard: netguard.New(false), NodeID: "t", Version: "test"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestValidateCaps(t *testing.T) {
	r := testRunner()
	bad := []Spec{
		{Type: "nope", Target: "x.com"},
		{Type: "web", Target: "ftp://x.com"},
		{Type: "web", Target: "https://user:pw@x.com"},
		{Type: "web", Target: "x.com", TimeoutS: 500},
		{Type: "web", Target: "x.com", Options: json.RawMessage(`{"unknown":1}`)},
		{Type: "dns", Target: "not a host"},
		{Type: "dns", Target: "x.com", Options: json.RawMessage(`{"qtype":"MX"}`)},
		{Type: "dns", Target: "x.com", Options: json.RawMessage(`{"resolvers":["dns.google"]}`)},
		{Type: "tcp", Target: "x.com", Options: json.RawMessage(`{"ports":[0]}`)},
		{Type: "tcp", Target: "x.com", Options: json.RawMessage(`{"ports":[80,80]}`)},
		{Type: "ping", Target: "x.com", Options: json.RawMessage(`{"count":100}`)},
		{Type: "traceroute", Target: "x.com", Options: json.RawMessage(`{"max_hops":64}`)},
		{Type: "traceroute", Target: "x.com", Options: json.RawMessage(`{"mode":"gre"}`)},
		{Type: "throttle", Target: "https://x.com", Options: json.RawMessage(`{"max_bytes":1073741824}`)},
		{Type: "sni", Target: "1.1.1.1"},
		{Type: "quic", Target: "http://x.com"},
		{Type: "info", Target: "x.com"},
		// Options that cannot finish within the timeout.
		{Type: "ping", Target: "x.com", Options: json.RawMessage(`{"count":20,"interval_ms":2000}`)},
		{Type: "traceroute", Target: "x.com", Options: json.RawMessage(`{"wait_ms":3000}`)},
		{Type: "tcp", Target: "x.com", Options: json.RawMessage(`{"ports":[1,2,3,4,5,6,7,8,9,10],"timeout_ms":15000}`)},
		{Type: "throttle", Target: "https://x.com", Options: json.RawMessage(`{"duration_s":20}`), TimeoutS: 30},
	}
	for _, s := range bad {
		if err := r.Validate(s); err == nil {
			t.Errorf("Validate(%+v) accepted", s)
		}
	}
	good := []Spec{
		{Type: "web", Target: "x.com"},
		{Type: "web", Target: "http://example.org:8080/path?q=1"},
		{Type: "dns", Target: "x.com", Options: json.RawMessage(`{"qtype":"AAAA","resolvers":["8.8.8.8","[2001:4860:4860::8888]:53"]}`)},
		{Type: "tcp", Target: "1.1.1.1", Options: json.RawMessage(`{"ports":[22,80,443]}`)},
		{Type: "sni", Target: "x.com", Options: json.RawMessage(`{"ip":"104.16.0.1"}`)},
		{Type: "quic", Target: "https://cloudflare.com"},
		{Type: "ping", Target: "8.8.8.8", Options: json.RawMessage(`{"tcp_port":0}`)},
		{Type: "traceroute", Target: "8.8.8.8", Options: json.RawMessage(`{"mode":"tcp","port":443}`)},
		{Type: "throttle", Target: "https://x.com/file"},
		{Type: "throttle", Target: "https://x.com/file", Options: json.RawMessage(`{"duration_s":20}`)},
		{Type: "info"},
		{Type: "traceroute", Target: "x.com", Options: json.RawMessage(`{"wait_ms":3000}`), TimeoutS: 120},
		{Type: "ping", Target: "x.com", Options: json.RawMessage(`{"count":20,"interval_ms":2000,"tcp_port":0}`), TimeoutS: 45},
	}
	for _, s := range good {
		if err := r.Validate(s); err != nil {
			t.Errorf("Validate(%+v) = %v", s, err)
		}
	}
}

// withSlowCheck registers a check type that reports a network verdict only
// once its context ends, as a real check interrupted mid-measurement would.
func withSlowCheck(t *testing.T, timeout time.Duration) string {
	t.Helper()
	const name = "test-slow"
	registry[name] = definition{timeout, timeout, func(*Env, string, json.RawMessage, time.Duration) (execFunc, error) {
		return func(ctx context.Context) outcome {
			<-ctx.Done()
			return outcome{verdict: Blocked, mechanism: "tcp_timeout", evidence: map[string]int{"partial": 1}}
		}, nil
	}}
	t.Cleanup(func() { delete(registry, name) })
	return name
}

func TestRunOutOfBudget(t *testing.T) {
	typ := withSlowCheck(t, 50*time.Millisecond)
	res := testRunner().Run(context.Background(), Spec{Type: typ})
	if res.Verdict != Error || res.Mechanism != "check_timeout" || res.Error == "" {
		t.Fatalf("got %+v", res)
	}
	if string(res.Evidence) != `{"partial":1}` {
		t.Errorf("partial evidence dropped: %s", res.Evidence)
	}
}

func TestRunOutOfBudgetAtIODeadline(t *testing.T) {
	const name = "test-io-deadline"
	registry[name] = definition{50 * time.Millisecond, 50 * time.Millisecond, func(*Env, string, json.RawMessage, time.Duration) (execFunc, error) {
		return func(ctx context.Context) outcome {
			deadline, _ := ctx.Deadline()
			time.Sleep(time.Until(deadline))
			return outcome{verdict: Blocked, mechanism: "tcp_timeout"}
		}, nil
	}}
	t.Cleanup(func() { delete(registry, name) })

	for range 50 {
		res := testRunner().Run(context.Background(), Spec{Type: name})
		if res.Verdict != Error || res.Mechanism != "check_timeout" {
			t.Fatalf("got %s/%s, want error/check_timeout", res.Verdict, res.Mechanism)
		}
	}
}

func TestRunCancelled(t *testing.T) {
	typ := withSlowCheck(t, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res := testRunner().Run(ctx, Spec{Type: typ})
	if res.Verdict != Error || res.Mechanism != "cancelled" {
		t.Fatalf("got %+v", res)
	}
}

func TestFirstValidCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	live := netip.MustParseAddrPort(srv.Listener.Addr().String())

	dead, alive, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1")
	var tried []netip.Addr
	dial := func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		tried = append(tried, ap.Addr())
		if ap.Addr() != alive {
			return nil, syscall.ECONNREFUSED
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", live.String())
	}
	if !firstValidCert(context.Background(), dial, "example.com", live.Port(), []netip.Addr{other, dead, alive}, roots) {
		t.Fatalf("valid certificate behind a dead first address not found; tried %v", tried)
	}
	if len(tried) != 2 || tried[0] != dead || tried[1] != alive {
		t.Errorf("want IPv4 addresses first, in order; tried %v", tried)
	}
	tried = nil
	if firstValidCert(context.Background(), dial, "wrong.example", live.Port(), []netip.Addr{alive}, roots) {
		t.Error("certificate for another name accepted")
	}
	tried = nil
	if firstValidCert(context.Background(), dial, "example.com", live.Port(), []netip.Addr{dead, dead, other, dead}, roots) || len(tried) > maxCertProbes {
		t.Errorf("unreachable addresses: tried %v", tried)
	}
}

func TestChromeDialTLSSpeaksHTTP1(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	var d net.Dialer
	client := &http.Client{Transport: &http.Transport{DialTLSContext: chromeDialTLS(d.DialContext)}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "HTTP/1.1" {
		t.Fatalf("status %d, server saw %q", resp.StatusCode, body)
	}
}

func TestRunForbiddenTarget(t *testing.T) {
	res := testRunner().Run(context.Background(), Spec{Type: "tcp", Target: "127.0.0.1", Options: json.RawMessage(`{"ports":[80]}`)})
	if res.Verdict != Error || res.Mechanism != "forbidden_target" {
		t.Fatalf("got %+v", res)
	}
}

func ans(src, rcode string, addrs ...string) dnsAnswer {
	return dnsAnswer{Source: src, RCode: rcode, Addrs: addrs}
}

func TestJudgeDNS(t *testing.T) {
	ctl := []dnsAnswer{ans("doh", "NOERROR", "104.244.42.1")}
	timeout := dnsAnswer{Source: "system", Error: "i/o timeout", timeout: true}
	injected := ans("injection", "NOERROR", "8.7.6.5")
	cases := []struct {
		name    string
		local   []dnsAnswer
		control []dnsAnswer
		inj     *dnsAnswer
		v       Verdict
		mech    string
	}{
		{"match", []dnsAnswer{ans("system", "NOERROR", "104.244.42.1")}, ctl, nil, OK, ""},
		{"iran sinkhole", []dnsAnswer{ans("system", "NOERROR", "10.10.34.34")}, nil, nil, Blocked, "dns_sinkhole"},
		{"null route", []dnsAnswer{ans("system", "NOERROR", "0.0.0.0")}, ctl, nil, Blocked, "dns_sinkhole"},
		{"nxdomain hijack", []dnsAnswer{ans("system", "NXDOMAIN")}, ctl, nil, Blocked, "dns_nxdomain"},
		{"timeout", []dnsAnswer{timeout}, ctl, nil, Blocked, "dns_timeout"},
		{"private answer", []dnsAnswer{ans("system", "NOERROR", "192.168.1.10")}, ctl, nil, Blocked, "dns_private_answer"},
		{"mismatch", []dnsAnswer{ans("system", "NOERROR", "31.13.1.1")}, ctl, nil, Anomaly, "dns_mismatch"},
		{"injection", []dnsAnswer{ans("system", "NOERROR", "104.244.42.1")}, ctl, &injected, Blocked, "dns_injection"},
		{"no injection on timeout", []dnsAnswer{ans("system", "NOERROR", "104.244.42.1")}, ctl, &timeout, OK, ""},
		{"nonexistent", []dnsAnswer{ans("system", "NXDOMAIN")}, []dnsAnswer{ans("doh", "NXDOMAIN")}, nil, Unreachable, "domain_not_found"},
		{"no control nx", []dnsAnswer{ans("system", "NXDOMAIN")}, nil, nil, Unreachable, "dns_nxdomain"},
		{"control down", []dnsAnswer{ans("system", "NOERROR", "1.2.3.5")}, []dnsAnswer{{Source: "doh", Error: "x"}}, nil, OK, ""},
	}
	for _, c := range cases {
		v, mech := judgeDNS(c.local, c.control, c.inj)
		if v != c.v || mech != c.mech {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, mech, c.v, c.mech)
		}
	}
}

func TestJudgeStageErr(t *testing.T) {
	cases := []struct {
		stage string
		err   error
		v     Verdict
		mech  string
	}{
		{"tcp", syscall.ECONNRESET, Blocked, "tcp_rst"},
		{"tcp", syscall.ECONNREFUSED, Unreachable, "tcp_refused"},
		{"tcp", context.DeadlineExceeded, Blocked, "tcp_timeout"},
		{"tcp", syscall.ENETUNREACH, Unreachable, "tcp_no_route"},
		{"tls", io.EOF, Blocked, "tls_eof"},
		{"tls", errors.New("remote error: tls: handshake failure"), Anomaly, "tls_alert"},
		{"http", netguard.ErrForbidden, Error, "forbidden_target"},
	}
	for _, c := range cases {
		v, mech := judgeStageErr(c.stage, c.err)
		if v != c.v || mech != c.mech {
			t.Errorf("%s/%v: got %s/%s", c.stage, c.err, v, mech)
		}
	}
}

func TestJudgePortsAndSNI(t *testing.T) {
	if v, m := judgePorts([]portResult{{State: "open"}, {State: "refused"}, {State: "timeout"}}); v != Blocked || m != "tcp_timeout" {
		t.Errorf("ports: %s/%s", v, m)
	}
	if v, _ := judgePorts([]portResult{{State: "open"}}); v != OK {
		t.Errorf("all open: %s", v)
	}
	if v, m := judgeSNI("ok", "rst"); v != Blocked || m != "tls_sni_rst" {
		t.Errorf("sni rst: %s/%s", v, m)
	}
	if v, _ := judgeSNI("ok", "alert"); v != OK {
		t.Errorf("server alert must not count as blocking: %s", v)
	}
	if v, m := judgeSNI("timeout", "rst"); v != Unreachable || m != "sni_control_failed" {
		t.Errorf("control failed: %s/%s", v, m)
	}
}

func TestJudgeThrottle(t *testing.T) {
	control := transferSample{Bytes: 5 << 20, Mbps: 100, Complete: true}
	cases := []struct {
		name   string
		target transferSample
		v      Verdict
		mech   string
	}{
		{"healthy", transferSample{Bytes: 5 << 20, Mbps: 80, Complete: true}, OK, ""},
		{"capped", transferSample{Bytes: 1 << 20, Mbps: 1.2, Buckets: []int64{1000, 1000, 1000}}, Throttled, "bandwidth_cap"},
		{"stall", transferSample{Bytes: 16 << 10, Mbps: 0.1, Buckets: []int64{16 << 10, 0, 0, 0, 0, 0, 0, 0, 0}}, Throttled, "stall_after_bytes"},
		{"small file", transferSample{Bytes: 10 << 10, Mbps: 0.5, Complete: true}, OK, ""},
		{"midstream rst", transferSample{Bytes: 40 << 10, reset: true, Buckets: []int64{40 << 10}}, Blocked, "http_rst_midstream"},
		{"connect rst", transferSample{err: syscall.ECONNRESET}, Blocked, "http_rst"},
	}
	for _, c := range cases {
		v, mech := judgeThrottle(c.target, control)
		if v != c.v || mech != c.mech {
			t.Errorf("%s: got %s/%s", c.name, v, mech)
		}
	}
	if v, m := judgeThrottle(transferSample{Bytes: 1 << 20, Mbps: 1, Buckets: []int64{1}}, transferSample{err: errors.New("x")}); v != Error || m != "control_failed" {
		t.Errorf("control failed: %s/%s", v, m)
	}
}

func TestBlockPage(t *testing.T) {
	if !looksLikeBlockPage([]byte("<h1>Access to this website has been blocked</h1>"), http.Header{}) {
		t.Error("english block page")
	}
	if !looksLikeBlockPage([]byte("<html>ok</html>"), http.Header{"Server": {"FortiGuard"}}) {
		t.Error("middlebox header")
	}
	if looksLikeBlockPage([]byte("<p>We blocked a spam comment.</p>"), http.Header{}) {
		t.Error("ordinary page flagged")
	}
	if looksLikeForbiddenBlock(make([]byte, 2048)) {
		t.Error("large 403 must not be flagged")
	}
	if !looksLikeForbiddenBlock([]byte("Access denied")) {
		t.Error("tiny opaque 403")
	}

	article := "<html><head><title>How Iran filters the web</title></head><body>" +
		strings.Repeat("lorem ipsum ", 4000) + "Users see: this site has been blocked.</body></html>"
	if looksLikeBlockPage([]byte(article), http.Header{}) {
		t.Error("large article quoting a block phrase flagged")
	}
	titled := "<html><head><title>This site has been blocked</title></head><body>" + strings.Repeat("x", 64<<10) + "</body></html>"
	if !looksLikeBlockPage([]byte(titled), http.Header{}) {
		t.Error("large page with a block-page title")
	}
}

func TestParseQuoted(t *testing.T) {
	dst := netip.MustParseAddr("93.184.216.34")
	hdr := make([]byte, 28)
	hdr[0] = 0x45
	copy(hdr[16:20], dst.AsSlice())

	hdr[9] = 17
	binary.BigEndian.PutUint16(hdr[20:22], 40123)
	if p, k, ok := parseQuoted(hdr, 7, dst); !ok || p != 17 || k != 40123 {
		t.Errorf("udp: %d %d %v", p, k, ok)
	}

	hdr[9] = 1
	binary.BigEndian.PutUint16(hdr[24:26], 7)
	binary.BigEndian.PutUint16(hdr[26:28], 42)
	if p, k, ok := parseQuoted(hdr, 7, dst); !ok || p != 1 || k != 42 {
		t.Errorf("icmp: %d %d %v", p, k, ok)
	}
	if _, _, ok := parseQuoted(hdr, 8, dst); ok {
		t.Error("foreign echo id accepted")
	}
	if _, _, ok := parseQuoted(hdr, 7, netip.MustParseAddr("1.1.1.1")); ok {
		t.Error("foreign destination accepted")
	}
}

func TestPingSummarize(t *testing.T) {
	s := pingStats{Sent: 4}
	s.summarize([]time.Duration{10 * time.Millisecond, -1, 20 * time.Millisecond, 30 * time.Millisecond})
	if s.Received != 3 || s.LossPct != 25 || s.MinMs != 10 || s.MaxMs != 30 || s.AvgMs != 20 || s.JitterMs != 10 {
		t.Fatalf("%+v", s)
	}
	if v, m := judgePing(s, nil); v != Anomaly || m != "packet_loss" {
		t.Errorf("%s/%s", v, m)
	}
}
