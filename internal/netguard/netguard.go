// Package netguard decides which destination addresses the node may contact.
// Enforcement happens at connect time (net.Dialer.Control), so DNS answers
// that change between resolution and dial cannot bypass it.
package netguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrForbidden marks a destination rejected by policy.
var ErrForbidden = errors.New("target address not allowed")

// Never contacted, even in lab mode: self, metadata services, multicast, reserved.
var alwaysDenied = prefixes(
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128",
)

// Not publicly routable; contacted only when private targets are allowed.
var nonPublic = prefixes(
	"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16",
	"192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"fc00::/7", "2001:db8::/32", "64:ff9b:1::/48",
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IPv6 ranges that carry an IPv4 address the traffic is translated or
// tunnelled to; the policy applies to that address too.
var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
	teredo    = netip.MustParsePrefix("2001::/32")
)

// embeddedV4 returns the IPv4 addresses a NAT64, 6to4 or Teredo address
// reaches. For Teredo that is both the server and the (obfuscated) client.
func embeddedV4(a netip.Addr) []netip.Addr {
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return []netip.Addr{netip.AddrFrom4([4]byte(b[12:16]))}
	case sixToFour.Contains(a):
		return []netip.Addr{netip.AddrFrom4([4]byte(b[2:6]))}
	case teredo.Contains(a):
		client := [4]byte{b[12] ^ 0xff, b[13] ^ 0xff, b[14] ^ 0xff, b[15] ^ 0xff}
		return []netip.Addr{netip.AddrFrom4([4]byte(b[4:8])), netip.AddrFrom4(client)}
	}
	return nil
}

// IsPublic reports whether a is a globally routable unicast address.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || inAny(a, alwaysDenied) || inAny(a, nonPublic) {
		return false
	}
	for _, v4 := range embeddedV4(a) {
		if !IsPublic(v4) {
			return false
		}
	}
	return true
}

// Guard applies the destination policy.
type Guard struct {
	allowPrivate bool
}

// New returns a guard; allowPrivate permits RFC1918/ULA/CGNAT destinations (lab use).
func New(allowPrivate bool) *Guard { return &Guard{allowPrivate: allowPrivate} }

// Allowed reports whether the node may send traffic to a.
func (g *Guard) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || inAny(a, alwaysDenied) || (!g.allowPrivate && inAny(a, nonPublic)) {
		return false
	}
	for _, v4 := range embeddedV4(a) {
		if !g.Allowed(v4) {
			return false
		}
	}
	return true
}

// Check returns ErrForbidden (wrapped) when a is not allowed.
func (g *Guard) Check(a netip.Addr) error {
	if !g.Allowed(a) {
		return fmt.Errorf("%w: %s", ErrForbidden, a)
	}
	return nil
}

// Resolve returns the allowed addresses for host (an IP literal or a name)
// using the system resolver. It fails with ErrForbidden if every answer is disallowed.
func (g *Guard) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if err := g.Check(a); err != nil {
			return nil, err
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if g.Allowed(a) {
			out = append(out, a.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s resolves only to disallowed addresses", ErrForbidden, host)
	}
	return out, nil
}

// Dialer returns a dialer that refuses disallowed destinations at connect time.
func (g *Guard) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrForbidden, address)
			}
			return g.Check(ap.Addr())
		},
	}
}

// HTTPClient returns a client whose every connection (including redirects)
// goes through the guarded dialer and ignores proxy environment variables.
// The caller bounds total time through the request context.
func (g *Guard) HTTPClient(insecure bool) *http.Client {
	return g.PinnedHTTPClient(insecure, "", "")
}

// PinnedHTTPClient is HTTPClient with connections to origin (host:port) sent
// to addr (ip:port), so the request reaches the address a check already chose.
func (g *Guard) PinnedHTTPClient(insecure bool, origin, addr string) *http.Client {
	dialer := g.Dialer(8 * time.Second)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
				if origin != "" && a == origin {
					a = addr
				}
				return dialer.DialContext(ctx, network, a)
			},
			TLSClientConfig:        &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // opt-in per check
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  15 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
			ForceAttemptHTTP2:      true,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}
