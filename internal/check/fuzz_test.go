package check

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func FuzzParseDNSResponse(f *testing.F) {
	name := dnsmessage.MustNewName("example.com.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}},
		},
	}
	b, err := msg.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	_, q, err := buildQuery("example.com", dnsmessage.TypeAAAA)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(q)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, addrs, err := parseResponse(raw, 7)
		for _, a := range addrs {
			if _, perr := netip.ParseAddr(a); err == nil && perr != nil {
				t.Fatalf("unparsable address %q", a)
			}
		}
	})
}

func FuzzParseQuoted(f *testing.F) {
	dst := netip.MustParseAddr("8.8.8.8")
	hdr := make([]byte, 28)
	hdr[0], hdr[9] = 0x45, 17
	copy(hdr[16:20], dst.AsSlice())
	f.Add(hdr)
	f.Add([]byte{0x40, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, raw []byte) {
		parseQuoted(raw, 7, dst)
	})
}
