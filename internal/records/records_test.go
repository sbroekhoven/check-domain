package records

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestValue(t *testing.T) {
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")}
	if got := value(a); got != "192.0.2.1" {
		t.Errorf("value(A) = %q", got)
	}
	mx := &dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mail.example.com."}
	if got := value(mx); got != "10 mail.example.com." {
		t.Errorf("value(MX) = %q", got)
	}
}

func TestSortAndByType(t *testing.T) {
	info := &Info{Records: []Record{{Type: "MX"}, {Type: "A"}, {Type: "SOA"}, {Type: "A"}}}
	sortRecords(info.Records)
	if info.Records[0].Type != "SOA" || info.Records[1].Type != "A" || info.Records[3].Type != "MX" {
		t.Errorf("sorted = %+v", info.Records)
	}
	if len(info.ByType("A")) != 2 {
		t.Error("ByType")
	}
}
