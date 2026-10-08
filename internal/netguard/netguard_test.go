package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAllowedPolicy(t *testing.T) {
	strict, lab := New(false), New(true)
	cases := []struct {
		addr        string
		strict, lab bool
	}{
		{"1.1.1.1", true, true},
		{"2606:4700:4700::1111", true, true},
		{"10.10.34.34", false, true},
		{"172.30.0.20", false, true},
		{"192.168.1.1", false, true},
		{"100.64.0.1", false, true},
		{"fd12::1", false, true},
		{"127.0.0.1", false, false},
		{"::1", false, false},
		{"169.254.169.254", false, false},
		{"fd00:ec2::254", false, false},
		{"0.0.0.0", false, false},
		{"224.0.0.1", false, false},
		{"255.255.255.255", false, false},
		{"::ffff:127.0.0.1", false, false},
		{"::ffff:8.8.8.8", true, true},
		// NAT64, 6to4 and Teredo reach the IPv4 address they embed.
		{"64:ff9b::8.8.8.8", true, true},
		{"64:ff9b::a9fe:a9fe", false, false}, // 169.254.169.254
		{"64:ff9b::7f00:1", false, false},    // 127.0.0.1
		{"64:ff9b::a00:1", false, true},      // 10.0.0.1
		{"2002:0808:0808::1", true, true},
		{"2002:c0a8:0101::1", false, true}, // 192.168.1.1
		{"2002:7f00:0001::1", false, false},
		{"2001:0:0808:0808::f7f7:f7f7", true, true},   // server 8.8.8.8, client 8.8.8.8
		{"2001:0:0808:0808::80ff:fffe", false, false}, // client 127.0.0.1
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		if got := strict.Allowed(a); got != c.strict {
			t.Errorf("strict %s = %v, want %v", c.addr, got, c.strict)
		}
		if got := lab.Allowed(a); got != c.lab {
			t.Errorf("lab %s = %v, want %v", c.addr, got, c.lab)
		}
		if got := IsPublic(a); got != c.strict {
			t.Errorf("IsPublic(%s) = %v, want %v", c.addr, got, c.strict)
		}
	}
}

func TestDialerBlocksAtConnectTime(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = New(true).Dialer(time.Second).DialContext(context.Background(), "tcp", ln.Addr().String())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("loopback dial must be forbidden, got %v", err)
	}
}

func TestResolveLiteral(t *testing.T) {
	g := New(false)
	if _, err := g.Resolve(context.Background(), "10.0.0.1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("private literal must be forbidden: %v", err)
	}
	got, err := g.Resolve(context.Background(), "8.8.8.8")
	if err != nil || len(got) != 1 {
		t.Fatalf("public literal: %v %v", got, err)
	}
	if _, err := g.Resolve(context.Background(), "localhost"); err == nil {
		t.Fatal("localhost must not resolve to an allowed address")
	}
}
