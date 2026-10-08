package check

import (
	"net"
	"net/netip"

	"golang.org/x/net/icmp"
)

// listenICMP opens a raw ICMP socket when the process holds CAP_NET_RAW,
// otherwise an unprivileged datagram ICMP socket (Linux ping_group_range, macOS).
func listenICMP(v6 bool) (conn *icmp.PacketConn, raw bool, err error) {
	rawNet, dgramNet := "ip4:icmp", "udp4"
	if v6 {
		rawNet, dgramNet = "ip6:ipv6-icmp", "udp6"
	}
	if conn, err = icmp.ListenPacket(rawNet, ""); err == nil {
		return conn, true, nil
	}
	conn, err = icmp.ListenPacket(dgramNet, "")
	return conn, false, err
}

// stripIPv4Header drops a leading IPv4 header some platforms deliver on ICMP
// sockets. ICMP types 64-79 are unassigned, so a 0x4_ first byte is a header.
func stripIPv4Header(b []byte) []byte {
	if len(b) >= 20 && b[0]>>4 == 4 {
		if ihl := int(b[0]&0x0f) * 4; ihl >= 20 && len(b) >= ihl {
			return b[ihl:]
		}
	}
	return b
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}
