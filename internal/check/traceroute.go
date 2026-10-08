package check

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type traceOptions struct {
	Mode    string `json:"mode"`
	Port    int    `json:"port"`
	MaxHops int    `json:"max_hops"`
	Probes  int    `json:"probes"`
	WaitMs  int    `json:"wait_ms"`
}

type hopProbe struct {
	IP    string  `json:"ip,omitempty"`
	RTTMs float64 `json:"rtt_ms,omitempty"`
	Reply string  `json:"reply"` // time_exceeded, unreachable, echo_reply, tcp_connect, timeout
}

type hop struct {
	TTL    int        `json:"ttl"`
	Name   string     `json:"name,omitempty"`
	Probes []hopProbe `json:"probes"`
}

type traceEvidence struct {
	Mode    string `json:"mode"`
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	Reached bool   `json:"reached"`
	LastHop string `json:"last_responding_hop,omitempty"`
	Hops    []hop  `json:"hops"`
}

const (
	replyExceeded = "time_exceeded"
	replyUnreach  = "unreachable"
	replyEcho     = "echo_reply"
	replyConnect  = "tcp_connect"
	replyTimeout  = "timeout"
)

func prepareTraceroute(env *Env, target string, raw json.RawMessage, budget time.Duration) (execFunc, error) {
	o := traceOptions{Mode: "icmp", MaxHops: 30, Probes: 3, WaitMs: 1000}
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(target); err != nil && !validHostname(target) {
		return nil, errors.New("target must be a hostname or IP")
	}
	switch o.Mode {
	case "icmp":
		o.Port = 0
	case "udp":
		if o.Port == 0 {
			o.Port = 33434
		}
	case "tcp":
		if o.Port == 0 {
			o.Port = 443
		}
	default:
		return nil, errors.New("mode must be icmp, udp or tcp")
	}
	if o.Port < 0 || o.Port > 65535-30*3 || o.MaxHops < 1 || o.MaxHops > 30 || o.Probes < 1 || o.Probes > 3 || o.WaitMs < 200 || o.WaitMs > 3000 {
		return nil, errors.New("max_hops 1-30, probes 1-3, wait_ms 200-3000, valid port")
	}
	// Each hop waits up to wait_ms for its probes; hop names then get hopNameBudget.
	if err := fitBudget(resolveSlack+time.Duration(o.MaxHops*o.WaitMs)*time.Millisecond+hopNameBudget, budget); err != nil {
		return nil, err
	}

	return func(ctx context.Context) outcome {
		addrs, fail := resolveTarget(ctx, env, target)
		if fail != nil {
			return *fail
		}
		var dst netip.Addr
		for _, a := range addrs {
			if a.Is4() {
				dst = a
				break
			}
		}
		if !dst.IsValid() {
			return outcome{verdict: Error, mechanism: "ipv6_unsupported", err: "traceroute supports IPv4 targets only"}
		}
		ev, err := trace(ctx, env, dst, o)
		if err != nil {
			return outcome{verdict: Error, mechanism: "raw_socket_unavailable", err: err.Error()}
		}
		resolveHopNames(ctx, ev.Hops)
		if ev.Reached {
			return outcome{verdict: OK, evidence: ev}
		}
		return outcome{verdict: Unreachable, mechanism: "path_drop", evidence: ev}
	}, nil
}

type icmpEvent struct {
	from  netip.Addr
	reply string
	proto byte
	key   int
	at    time.Time
}

type probeKey struct {
	proto byte
	key   int
}

func trace(ctx context.Context, env *Env, dst netip.Addr, o traceOptions) (*traceEvidence, error) {
	ln, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("raw ICMP socket unavailable (needs CAP_NET_RAW): %w", err)
	}
	defer ln.Close()

	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := int(binary.BigEndian.Uint16(idb[:]))
	events := make(chan icmpEvent, 128)
	go readTraceICMP(ln, events, id, dst)

	ev := &traceEvidence{Mode: o.Mode, IP: dst.String(), Port: o.Port, Hops: []hop{}}
	wait := time.Duration(o.WaitMs) * time.Millisecond
	connected := make(chan probeKey, o.Probes)

	for ttl := 1; ttl <= o.MaxHops && ctx.Err() == nil; ttl++ {
		h := hop{TTL: ttl, Probes: make([]hopProbe, o.Probes)}
		pending := map[probeKey]int{}
		sentAt := make([]time.Time, o.Probes)
		var cleanup []func()

		for p := range o.Probes {
			h.Probes[p].Reply = replyTimeout
			sentAt[p] = time.Now()
			k, closeFn, err := sendProbe(ctx, env, ln, o, dst, ttl, p, id, wait, connected)
			if err != nil {
				continue
			}
			pending[k] = p
			if closeFn != nil {
				cleanup = append(cleanup, closeFn)
			}
		}

		reached := false
		timer := time.NewTimer(wait)
	collect:
		for len(pending) > 0 {
			select {
			case e := <-events:
				p, ok := pending[probeKey{e.proto, e.key}]
				if !ok {
					continue
				}
				delete(pending, probeKey{e.proto, e.key})
				h.Probes[p] = hopProbe{IP: e.from.String(), RTTMs: msSince(sentAt[p], e.at), Reply: e.reply}
				if e.from == dst {
					reached = true
				}
			case k := <-connected:
				p, ok := pending[k]
				if !ok {
					continue
				}
				delete(pending, k)
				h.Probes[p] = hopProbe{IP: dst.String(), RTTMs: msSince(sentAt[p], time.Now()), Reply: replyConnect}
				reached = true
			case <-timer.C:
				break collect
			case <-ctx.Done():
				break collect
			}
		}
		timer.Stop()
		for _, c := range cleanup {
			c()
		}
		ev.Hops = append(ev.Hops, h)
		for _, pr := range h.Probes {
			if pr.IP != "" {
				ev.LastHop = pr.IP
			}
		}
		if reached {
			ev.Reached = true
			break
		}
	}
	return ev, nil
}

// sendProbe emits one probe with the given TTL and returns the key under which
// its ICMP answer (or TCP connect) will be reported.
func sendProbe(ctx context.Context, env *Env, ln *icmp.PacketConn, o traceOptions, dst netip.Addr, ttl, p, id int, wait time.Duration, connected chan<- probeKey) (probeKey, func(), error) {
	switch o.Mode {
	case "icmp":
		seq := ttl*10 + p
		b, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("netsurveil-tester")}}).Marshal(nil)
		pc := ln.IPv4PacketConn()
		if err := pc.SetTTL(ttl); err != nil {
			return probeKey{}, nil, err
		}
		_, err := ln.WriteTo(b, &net.IPAddr{IP: dst.AsSlice()})
		return probeKey{1, seq}, nil, err

	case "udp":
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return probeKey{}, nil, err
		}
		if err := ipv4.NewConn(c).SetTTL(ttl); err != nil {
			_ = c.Close()
			return probeKey{}, nil, err
		}
		port := o.Port + (ttl-1)*o.Probes + p
		if _, err := c.WriteTo([]byte("netsurveil-tester"), &net.UDPAddr{IP: dst.AsSlice(), Port: port}); err != nil {
			_ = c.Close()
			return probeKey{}, nil, err
		}
		return probeKey{17, c.LocalAddr().(*net.UDPAddr).Port}, func() { _ = c.Close() }, nil

	default: // tcp
		local := 32768 + mrand.IntN(28000)
		k := probeKey{6, local}
		d := env.Guard.Dialer(wait)
		d.LocalAddr = &net.TCPAddr{Port: local}
		guardCtl := d.Control
		d.Control = func(network, address string, c syscall.RawConn) error {
			if err := guardCtl(network, address, c); err != nil {
				return err
			}
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			}); err != nil {
				return err
			}
			return serr
		}
		go func() {
			conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(dst.String(), strconv.Itoa(o.Port)))
			if err == nil {
				_ = conn.Close()
			}
			if err == nil || classifyErr(err) == kindRefused {
				select {
				case connected <- k:
				default:
				}
			}
		}()
		return k, nil, nil
	}
}

// readTraceICMP turns ICMP replies addressed to our probes into events until ln closes.
func readTraceICMP(ln *icmp.PacketConn, out chan<- icmpEvent, id int, dst netip.Addr) {
	buf := make([]byte, 1500)
	for {
		n, peer, err := ln.ReadFrom(buf)
		if err != nil {
			return
		}
		at := time.Now()
		m, err := icmp.ParseMessage(1, stripIPv4Header(buf[:n]))
		if err != nil {
			continue
		}
		e := icmpEvent{from: addrOf(peer), at: at}
		var quoted []byte
		switch m.Type {
		case ipv4.ICMPTypeEchoReply:
			echo, ok := m.Body.(*icmp.Echo)
			if !ok || echo.ID != id {
				continue
			}
			e.reply, e.proto, e.key = replyEcho, 1, echo.Seq
		case ipv4.ICMPTypeTimeExceeded:
			body, ok := m.Body.(*icmp.TimeExceeded)
			if !ok {
				continue
			}
			e.reply, quoted = replyExceeded, body.Data
		case ipv4.ICMPTypeDestinationUnreachable:
			body, ok := m.Body.(*icmp.DstUnreach)
			if !ok {
				continue
			}
			e.reply, quoted = replyUnreach, body.Data
		default:
			continue
		}
		if quoted != nil {
			proto, key, ok := parseQuoted(quoted, id, dst)
			if !ok {
				continue
			}
			e.proto, e.key = proto, key
		}
		select {
		case out <- e:
		default:
		}
	}
}

// parseQuoted extracts the probe key from the original datagram quoted in an
// ICMP error: echo sequence for ICMP, source port for UDP and TCP.
func parseQuoted(b []byte, id int, dst netip.Addr) (byte, int, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return 0, 0, false
	}
	ihl := int(b[0]&0x0f) * 4
	if len(b) < ihl+8 || netip.AddrFrom4([4]byte(b[16:20])) != dst {
		return 0, 0, false
	}
	l4 := b[ihl:]
	switch proto := b[9]; proto {
	case 1:
		if int(binary.BigEndian.Uint16(l4[4:6])) != id {
			return 0, 0, false
		}
		return 1, int(binary.BigEndian.Uint16(l4[6:8])), true
	case 6, 17:
		return proto, int(binary.BigEndian.Uint16(l4[0:2])), true
	}
	return 0, 0, false
}

const hopNameBudget = 2 * time.Second

func resolveHopNames(ctx context.Context, hops []hop) {
	ctx, cancel := context.WithTimeout(ctx, hopNameBudget)
	defer cancel()
	var wg sync.WaitGroup
	for i := range hops {
		for _, p := range hops[i].Probes {
			if p.IP == "" {
				continue
			}
			wg.Go(func() {
				if names, err := net.DefaultResolver.LookupAddr(ctx, p.IP); err == nil && len(names) > 0 {
					hops[i].Name = strings.TrimSuffix(names[0], ".")
				}
			})
			break
		}
	}
	wg.Wait()
}

func msSince(from, to time.Time) float64 {
	return round2(float64(to.Sub(from).Microseconds()) / 1000)
}
