package check

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type pingOptions struct {
	Count      int  `json:"count"`
	IntervalMs int  `json:"interval_ms"`
	WaitMs     int  `json:"wait_ms"`
	TCPPort    *int `json:"tcp_port"`
}

type pingStats struct {
	Mode     string  `json:"mode,omitempty"`
	Port     int     `json:"port,omitempty"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	MinMs    float64 `json:"min_ms,omitempty"`
	AvgMs    float64 `json:"avg_ms,omitempty"`
	MaxMs    float64 `json:"max_ms,omitempty"`
	JitterMs float64 `json:"jitter_ms,omitempty"`
	Error    string  `json:"error,omitempty"`
}

type pingEvidence struct {
	IP   string     `json:"ip"`
	ICMP pingStats  `json:"icmp"`
	TCP  *pingStats `json:"tcp,omitempty"`
}

func preparePing(env *Env, target string, raw json.RawMessage, budget time.Duration) (execFunc, error) {
	o := pingOptions{Count: 4, IntervalMs: 500, WaitMs: 2000}
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(target); err != nil && !validHostname(target) {
		return nil, errors.New("target must be a hostname or IP")
	}
	if o.Count < 1 || o.Count > 20 || o.IntervalMs < 200 || o.IntervalMs > 5000 || o.WaitMs < 200 || o.WaitMs > 5000 {
		return nil, errors.New("count 1-20, interval_ms 200-5000, wait_ms 200-5000")
	}
	tcpPort := 443
	if o.TCPPort != nil {
		tcpPort = *o.TCPPort
	}
	if tcpPort < 0 || tcpPort > 65535 {
		return nil, errors.New("tcp_port must be 0 (disabled) or 1-65535")
	}
	interval, wait := time.Duration(o.IntervalMs)*time.Millisecond, time.Duration(o.WaitMs)*time.Millisecond
	// ICMP probes are paced by interval and drained for wait; TCP probes then
	// run one after another, each taking up to wait.
	gaps := time.Duration(o.Count-1) * interval
	worst := resolveSlack + gaps + wait
	if tcpPort > 0 {
		worst += gaps + time.Duration(o.Count)*wait
	}
	if err := fitBudget(worst, budget); err != nil {
		return nil, err
	}

	return func(ctx context.Context) outcome {
		addrs, fail := resolveTarget(ctx, env, target)
		if fail != nil {
			return *fail
		}
		ip := preferV4(addrs)
		ev := &pingEvidence{IP: ip.String(), ICMP: icmpPing(ctx, ip, o.Count, interval, wait)}
		if tcpPort > 0 {
			st := tcpPing(ctx, env, ip, tcpPort, o.Count, interval, wait)
			ev.TCP = &st
		}
		v, mech := judgePing(ev.ICMP, ev.TCP)
		return outcome{verdict: v, mechanism: mech, evidence: ev}
	}, nil
}

func judgePing(icmpStats pingStats, tcp *pingStats) (Verdict, string) {
	switch {
	case icmpStats.Received > 0 && icmpStats.LossPct >= 20:
		return Anomaly, "packet_loss"
	case icmpStats.Received > 0:
		return OK, ""
	case tcp != nil && tcp.Received > 0:
		return Anomaly, "icmp_filtered"
	case icmpStats.Sent == 0 && tcp == nil:
		return Error, "icmp_unavailable"
	}
	return Unreachable, "no_reply"
}

func icmpPing(ctx context.Context, ip netip.Addr, count int, interval, wait time.Duration) pingStats {
	var st pingStats
	conn, raw, err := listenICMP(ip.Is6())
	if err != nil {
		st.Error = err.Error()
		return st
	}
	defer conn.Close()
	st.Mode = "datagram"
	var dst net.Addr = &net.UDPAddr{IP: ip.AsSlice()}
	if raw {
		st.Mode, dst = "raw", &net.IPAddr{IP: ip.AsSlice()}
	}
	proto, reqType, replyType := 1, icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply)
	if ip.Is6() {
		proto, reqType, replyType = 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := int(binary.BigEndian.Uint16(idb[:]))

	var mu sync.Mutex
	sent := make([]time.Time, count)
	rtts := make([]time.Duration, count)
	for i := range rtts {
		rtts[i] = -1
	}
	deadline := time.Now().Add(time.Duration(count-1)*interval + wait)
	_ = conn.SetReadDeadline(deadline)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		got := 0
		for got < count {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			b := buf[:n]
			if proto == 1 {
				b = stripIPv4Header(b)
			}
			m, err := icmp.ParseMessage(proto, b)
			if err != nil || m.Type != replyType || addrOf(peer) != ip {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if !ok || (raw && echo.ID != id) || echo.Seq < 0 || echo.Seq >= count {
				continue
			}
			mu.Lock()
			if rtts[echo.Seq] < 0 && !sent[echo.Seq].IsZero() {
				rtts[echo.Seq] = time.Since(sent[echo.Seq])
				got++
			}
			mu.Unlock()
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	payload := []byte("netsurveil-tester")
send:
	for seq := range count {
		b, _ := (&icmp.Message{Type: reqType, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}).Marshal(nil)
		mu.Lock()
		sent[seq] = time.Now()
		mu.Unlock()
		if _, err := conn.WriteTo(b, dst); err != nil {
			st.Error = err.Error()
			break
		}
		st.Sent++
		if seq < count-1 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				break send
			}
		}
	}
	if st.Sent == 0 {
		_ = conn.SetReadDeadline(time.Now())
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	st.summarize(rtts[:st.Sent])
	return st
}

// tcpPing measures connect latency; a refusal still proves the host answered.
func tcpPing(ctx context.Context, env *Env, ip netip.Addr, port, count int, interval, wait time.Duration) pingStats {
	st := pingStats{Mode: "tcp_connect", Port: port}
	rtts := make([]time.Duration, 0, count)
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	for i := range count {
		if ctx.Err() != nil {
			break
		}
		st.Sent++
		start := time.Now()
		conn, err := env.Guard.Dialer(wait).DialContext(ctx, "tcp", addr)
		rtt := time.Since(start)
		switch {
		case err == nil:
			_ = conn.Close()
			rtts = append(rtts, rtt)
		case classifyErr(err) == kindRefused:
			rtts = append(rtts, rtt)
		default:
			rtts = append(rtts, -1)
			st.Error = err.Error()
		}
		if i < count-1 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
			}
		}
	}
	st.summarize(rtts)
	return st
}

// summarize fills loss and latency figures; negative entries are lost probes.
func (s *pingStats) summarize(rtts []time.Duration) {
	var ok []float64
	for _, r := range rtts {
		if r >= 0 {
			ok = append(ok, float64(r.Microseconds())/1000)
		}
	}
	s.Received = len(ok)
	if s.Sent > 0 {
		s.LossPct = round2(100 * float64(s.Sent-s.Received) / float64(s.Sent))
	}
	if len(ok) == 0 {
		return
	}
	s.MinMs, s.MaxMs = math.Inf(1), 0
	var sum, jitter float64
	for i, v := range ok {
		sum += v
		s.MinMs, s.MaxMs = math.Min(s.MinMs, v), math.Max(s.MaxMs, v)
		if i > 0 {
			jitter += math.Abs(v - ok[i-1])
		}
	}
	s.AvgMs = round2(sum / float64(len(ok)))
	s.MinMs, s.MaxMs = round2(s.MinMs), round2(s.MaxMs)
	if len(ok) > 1 {
		s.JitterMs = round2(jitter / float64(len(ok)-1))
	}
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
