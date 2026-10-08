package check

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
)

// Uncensored resolvers addressed by IP so the control path does not depend on local DNS.
var defaultDoH = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}

// Answers that are never legitimate for a public name: national filtering
// sinkholes (Iran 10.10.34.0/24) and null/loopback routes used by DNS blocklists.
var sinkholes = []netip.Prefix{
	netip.MustParsePrefix("10.10.34.0/24"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
}

func isSinkhole(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range sinkholes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type dnsAnswer struct {
	Source  string   `json:"source"`
	RCode   string   `json:"rcode,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
	Error   string   `json:"error,omitempty"`
	Ms      int64    `json:"ms"`
	timeout bool
}

func (a dnsAnswer) ok() bool { return a.Error == "" && a.RCode == "NOERROR" && len(a.Addrs) > 0 }

func (a *dnsAnswer) fail(err error) {
	a.Error = err.Error()
	a.timeout = classifyErr(err) == kindTimeout
}

// dnsControls are the uncensored vantage points a local answer is compared with.
type dnsControls struct {
	ControlResolvers []string `json:"control_resolvers"`
	DoH              []string `json:"doh"`
	NoControl        bool     `json:"no_control"`
}

func (c dnsControls) validate() error {
	if len(c.ControlResolvers) > 5 || len(c.DoH) > 3 {
		return errors.New("at most 5 control_resolvers and 3 doh endpoints")
	}
	for _, s := range c.ControlResolvers {
		if _, err := parseResolver(s); err != nil {
			return err
		}
	}
	for _, s := range c.DoH {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("doh endpoint %q must be an https URL", s)
		}
	}
	return nil
}

type lookupFunc func(ctx context.Context) dnsAnswer

func (c dnsControls) lookups(env *Env, host string, qtype dnsmessage.Type) []lookupFunc {
	if c.NoControl {
		return nil
	}
	doh := c.DoH
	if len(doh) == 0 && len(c.ControlResolvers) == 0 {
		doh = defaultDoH
	}
	var out []lookupFunc
	for _, s := range c.ControlResolvers {
		ap, _ := parseResolver(s)
		out = append(out, func(ctx context.Context) dnsAnswer { return udpLookup(ctx, env.Guard, ap, host, qtype, 4*time.Second) })
	}
	client := env.Guard.HTTPClient(false)
	for _, u := range doh {
		out = append(out, func(ctx context.Context) dnsAnswer { return dohLookup(ctx, client, u, host, qtype) })
	}
	return out
}

func runLookups(ctx context.Context, fns []lookupFunc) []dnsAnswer {
	out := make([]dnsAnswer, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Go(func() { out[i] = fn(ctx) })
	}
	wg.Wait()
	return out
}

func parseResolver(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a, 53), nil
	}
	return netip.AddrPort{}, fmt.Errorf("resolver %q must be an IP or IP:port", s)
}

// systemLookup uses the node's configured resolver; qtype 0 queries both families.
func systemLookup(ctx context.Context, host string, qtype dnsmessage.Type) dnsAnswer {
	network := "ip"
	switch qtype {
	case dnsmessage.TypeA:
		network = "ip4"
	case dnsmessage.TypeAAAA:
		network = "ip6"
	}
	start := time.Now()
	ans := dnsAnswer{Source: "system"}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	ans.Ms = time.Since(start).Milliseconds()
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		ans.RCode = "NXDOMAIN"
	case err != nil:
		ans.fail(err)
	default:
		ans.RCode = "NOERROR"
		for _, a := range addrs {
			ans.Addrs = append(ans.Addrs, a.Unmap().String())
		}
	}
	return ans
}

func udpLookup(ctx context.Context, g *netguard.Guard, server netip.AddrPort, host string, qtype dnsmessage.Type, timeout time.Duration) (ans dnsAnswer) {
	start := time.Now()
	ans.Source = "udp:" + server.String()
	defer func() { ans.Ms = time.Since(start).Milliseconds() }()

	id, query, err := buildQuery(host, qtype)
	if err != nil {
		ans.fail(err)
		return ans
	}
	conn, err := g.Dialer(timeout).DialContext(ctx, "udp", server.String())
	if err != nil {
		ans.fail(err)
		return ans
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(query); err != nil {
		ans.fail(err)
		return ans
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			ans.fail(err)
			return ans
		}
		rcode, addrs, err := parseResponse(buf[:n], id)
		if err != nil {
			continue // stray or malformed datagram; keep waiting for ours
		}
		ans.RCode, ans.Addrs = rcode, addrs
		return ans
	}
}

func dohLookup(ctx context.Context, client *http.Client, endpoint, host string, qtype dnsmessage.Type) (ans dnsAnswer) {
	start := time.Now()
	ans.Source = "doh:" + endpoint
	defer func() { ans.Ms = time.Since(start).Milliseconds() }()

	_, query, err := buildQuery(host, qtype)
	if err != nil {
		ans.fail(err)
		return ans
	}
	// RFC 8484 recommends id 0 for cache friendliness.
	query[0], query[1] = 0, 0
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		ans.fail(err)
		return ans
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		ans.fail(err)
		return ans
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		ans.fail(err)
		return ans
	}
	if resp.StatusCode != http.StatusOK {
		ans.Error = fmt.Sprintf("http status %d", resp.StatusCode)
		return ans
	}
	rcode, addrs, err := parseResponse(body, 0)
	if err != nil {
		ans.fail(err)
		return ans
	}
	ans.RCode, ans.Addrs = rcode, addrs
	return ans
}

func buildQuery(host string, qtype dnsmessage.Type) (uint16, []byte, error) {
	if qtype == 0 {
		qtype = dnsmessage.TypeA
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return 0, nil, err
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	b, err := msg.Pack()
	return id, b, err
}

func parseResponse(b []byte, id uint16) (string, []string, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return "", nil, err
	}
	if !h.Response || h.ID != id {
		return "", nil, errors.New("not our response")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", nil, err
	}
	var addrs []string
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return "", nil, err
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return "", nil, err
			}
			addrs = append(addrs, netip.AddrFrom4(r.A).String())
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return "", nil, err
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return "", nil, err
			}
		}
	}
	return rcodeName(h.RCode), addrs, nil
}

func rcodeName(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	}
	return fmt.Sprintf("RCODE%d", r)
}

// judgeDNS compares answers seen from the node (local) against uncensored
// controls. injected is a reply received from an address that runs no DNS
// server, which can only come from an on-path injector.
func judgeDNS(local, control []dnsAnswer, injected *dnsAnswer) (Verdict, string) {
	if injected != nil && injected.Error == "" && injected.RCode != "" {
		return Blocked, "dns_injection"
	}

	var localOK, localNX, localTimeout bool
	var localAddrs []netip.Addr
	for _, a := range local {
		localOK = localOK || a.ok()
		localNX = localNX || a.RCode == "NXDOMAIN"
		localTimeout = localTimeout || a.timeout
		localAddrs = append(localAddrs, parseAddrs(a.Addrs)...)
	}
	for _, a := range localAddrs {
		if isSinkhole(a) {
			return Blocked, "dns_sinkhole"
		}
	}

	var controlOK bool
	controlNX := len(control) > 0
	var controlAddrs []netip.Addr
	for _, a := range control {
		controlOK = controlOK || a.ok()
		controlNX = controlNX && a.RCode == "NXDOMAIN"
		if a.ok() {
			controlAddrs = append(controlAddrs, parseAddrs(a.Addrs)...)
		}
	}

	if controlOK {
		switch {
		case !localOK && localNX:
			return Blocked, "dns_nxdomain"
		case !localOK && localTimeout:
			return Blocked, "dns_timeout"
		case !localOK:
			return Blocked, "dns_failure"
		case anyNonPublic(localAddrs) && !anyNonPublic(controlAddrs):
			return Blocked, "dns_private_answer"
		case !overlaps(localAddrs, controlAddrs):
			return Anomaly, "dns_mismatch"
		}
	}
	switch {
	case localOK:
		return OK, ""
	case localNX && controlNX:
		return Unreachable, "domain_not_found"
	case localNX:
		return Unreachable, "dns_nxdomain"
	case localTimeout:
		return Unreachable, "dns_timeout"
	}
	return Unreachable, "dns_failure"
}

func parseAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func anyNonPublic(as []netip.Addr) bool {
	for _, a := range as {
		if !netguard.IsPublic(a) {
			return true
		}
	}
	return false
}

func overlaps(a, b []netip.Addr) bool {
	set := make(map[netip.Addr]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

// preferV4 returns the first IPv4 address, else the first address.
func preferV4(as []netip.Addr) netip.Addr {
	for _, a := range as {
		if a.Is4() {
			return a
		}
	}
	return as[0]
}
