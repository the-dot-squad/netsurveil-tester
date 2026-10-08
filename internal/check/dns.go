package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A reply from an address that runs no DNS server can only be injected on-path.
// Used when injection_probe is "on".
const defaultInjectionProbe = "1.2.3.4"

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$`)

func validHostname(s string) bool {
	return len(s) <= 253 && hostnameRe.MatchString(s)
}

type dnsOptions struct {
	QType          string   `json:"qtype"`
	Resolvers      []string `json:"resolvers"`
	InjectionProbe string   `json:"injection_probe"`
	dnsControls
}

type dnsEvidence struct {
	QType     string      `json:"qtype"`
	Local     []dnsAnswer `json:"local"`
	Control   []dnsAnswer `json:"control,omitempty"`
	Injection *dnsAnswer  `json:"injection,omitempty"`
	// TLSConfirmed is set when answers differed from the control but the local
	// address proved itself with a valid certificate for the name.
	TLSConfirmed bool `json:"tls_confirmed,omitempty"`
}

func prepareDNS(env *Env, target string, raw json.RawMessage, _ time.Duration) (execFunc, error) {
	var o dnsOptions
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if !validHostname(target) {
		return nil, errors.New("target must be a hostname")
	}
	qtype := dnsmessage.TypeA
	switch strings.ToUpper(o.QType) {
	case "", "A":
	case "AAAA":
		qtype = dnsmessage.TypeAAAA
	default:
		return nil, errors.New("qtype must be A or AAAA")
	}
	if err := o.validate(); err != nil {
		return nil, err
	}
	if len(o.Resolvers) > 5 {
		return nil, errors.New("at most 5 resolvers")
	}
	resolvers := make([]netip.AddrPort, 0, len(o.Resolvers))
	for _, s := range o.Resolvers {
		ap, err := parseResolver(s)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, ap)
	}
	// Opt-in: a DNS query to an address that runs no DNS server is a
	// recognisable measurement signature on a monitored network.
	var probe *netip.AddrPort
	switch o.InjectionProbe {
	case "", "off":
	case "on":
		ap := netip.AddrPortFrom(netip.MustParseAddr(defaultInjectionProbe), 53)
		probe = &ap
	default:
		ap, err := parseResolver(o.InjectionProbe)
		if err != nil {
			return nil, err
		}
		probe = &ap
	}

	return func(ctx context.Context) outcome {
		local := []lookupFunc{func(ctx context.Context) dnsAnswer { return systemLookup(ctx, target, qtype) }}
		for _, ap := range resolvers {
			local = append(local, func(ctx context.Context) dnsAnswer {
				return udpLookup(ctx, env.Guard, ap, target, qtype, 4*time.Second)
			})
		}
		controls := o.lookups(env, target, qtype)
		all := append(append([]lookupFunc{}, local...), controls...)
		if probe != nil {
			all = append(all, func(ctx context.Context) dnsAnswer {
				a := udpLookup(ctx, env.Guard, *probe, target, qtype, 3*time.Second)
				a.Source = "injection:" + probe.String()
				return a
			})
		}
		answers := runLookups(ctx, all)

		ev := &dnsEvidence{QType: qtype.String()[4:], Local: answers[:len(local)], Control: answers[len(local) : len(local)+len(controls)]}
		if probe != nil {
			ev.Injection = &answers[len(answers)-1]
		}
		v, mech := judgeDNS(ev.Local, ev.Control, ev.Injection)
		if mech == "dns_mismatch" && localAnswerHasValidCert(ctx, env, target, ev.Local) {
			ev.TLSConfirmed = true
			v, mech = OK, ""
		}
		return outcome{verdict: v, mechanism: mech, evidence: ev}
	}, nil
}

// maxCertProbes bounds how many local addresses localAnswerHasValidCert tries.
const maxCertProbes = 3

// localAnswerHasValidCert resolves a mismatch caused by CDNs and IP rotation:
// an address that presents a valid certificate for host is genuine.
func localAnswerHasValidCert(ctx context.Context, env *Env, host string, local []dnsAnswer) bool {
	var addrs []netip.Addr
	for _, a := range local {
		for _, ip := range parseAddrs(a.Addrs) {
			if env.Guard.Allowed(ip) {
				addrs = append(addrs, ip)
			}
		}
	}
	dialer := env.Guard.Dialer(4 * time.Second)
	dial := func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", ap.String())
	}
	return firstValidCert(ctx, dial, host, 443, addrs, nil)
}

// firstValidCert tries up to maxCertProbes distinct addresses, IPv4 first, and
// reports whether any presents a certificate valid for host under roots (nil
// means the system pool). An address that cannot be reached is skipped.
func firstValidCert(ctx context.Context, dial func(context.Context, netip.AddrPort) (net.Conn, error), host string, port uint16, addrs []netip.Addr, roots *x509.CertPool) bool {
	ordered := slices.Clone(addrs)
	slices.SortStableFunc(ordered, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	ordered = slices.Compact(ordered)
	for i, ip := range ordered {
		if i == maxCertProbes || ctx.Err() != nil {
			break
		}
		if probeCert(ctx, dial, netip.AddrPortFrom(ip, port), host, roots) {
			return true
		}
	}
	return false
}

func probeCert(ctx context.Context, dial func(context.Context, netip.AddrPort) (net.Conn, error), ap netip.AddrPort, host string, roots *x509.CertPool) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, ap)
	if err != nil {
		return false
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	defer tc.Close()
	return tc.HandshakeContext(ctx) == nil
}
