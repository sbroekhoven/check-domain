package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMatchesKey(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	if _, err := key.Generate(256); err != nil {
		t.Fatal(err)
	}
	real := key.ToDS(dns.SHA256)
	ds := DS{KeyTag: real.KeyTag, Algorithm: real.Algorithm, DigestType: real.DigestType, Digest: real.Digest}

	if !matchesKey(ds, []*dns.DNSKEY{key}) {
		t.Error("the DS computed from the key should match")
	}
	wrong := ds
	wrong.Digest = "00" + ds.Digest[2:]
	if matchesKey(wrong, []*dns.DNSKEY{key}) {
		t.Error("a different digest should not match")
	}
	if matchesKey(ds, nil) {
		t.Error("no keys should not match")
	}
}

func TestNames(t *testing.T) {
	if AlgorithmName(13) != "ECDSAP256SHA256" || AlgorithmName(200) != "unknown" {
		t.Error("AlgorithmName")
	}
	if DigestName(2) != "SHA256" {
		t.Errorf("DigestName(2) = %q", DigestName(2))
	}
}
