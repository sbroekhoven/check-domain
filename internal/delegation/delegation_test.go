package delegation

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func TestParseReferral(t *testing.T) {
	ns := func(owner, target string) dns.RR {
		return &dns.NS{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800}, Ns: target}
	}
	a := func(owner, ip string) dns.RR {
		return &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(ip)}
	}
	resp := new(dns.Msg)
	resp.Ns = []dns.RR{ns("example.com.", "NS2.example.com."), ns("example.com.", "ns1.example.com."), ns("other.com.", "x.other.com.")}
	resp.Extra = []dns.RR{a("ns1.example.com.", "192.0.2.1"), a("ns2.example.com.", "192.0.2.2"), a("unrelated.net.", "192.0.2.9")}

	d := &Delegation{Zone: "example.com", Glue: map[string][]string{}}
	if !d.parse(resp) {
		t.Fatal("parse returned false")
	}
	if want := []string{"ns1.example.com", "ns2.example.com"}; !reflect.DeepEqual(d.NS, want) || d.NSTTL != 172800 {
		t.Errorf("NS = %v (ttl %d), want %v", d.NS, d.NSTTL, want)
	}
	if want := map[string][]string{"ns1.example.com": {"192.0.2.1"}, "ns2.example.com": {"192.0.2.2"}}; !reflect.DeepEqual(d.Glue, want) {
		t.Errorf("Glue = %v", d.Glue)
	}

	empty := &Delegation{Zone: "missing.com", Glue: map[string][]string{}}
	if empty.parse(resp) {
		t.Error("a response without NS records for the zone should not parse")
	}
}

func TestInBailiwick(t *testing.T) {
	for _, tt := range []struct {
		ns, zone string
		want     bool
	}{
		{"ns1.example.com", "example.com", true},
		{"NS1.Example.COM.", "example.com", true},
		{"example.com", "example.com", true},
		{"ns1.example.net", "example.com", false},
		{"ns1.notexample.com", "example.com", false},
	} {
		if got := InBailiwick(tt.ns, tt.zone); got != tt.want {
			t.Errorf("InBailiwick(%q, %q) = %v", tt.ns, tt.zone, got)
		}
	}
}

func TestParentName(t *testing.T) {
	for in, want := range map[string]string{"example.com": "com", "a.b.example.co.uk": "b.example.co.uk", "nl": "."} {
		if got := ParentName(in); got != want {
			t.Errorf("ParentName(%q) = %q, want %q", in, got, want)
		}
	}
}
