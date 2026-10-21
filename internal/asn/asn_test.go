package asn

import "testing"

func TestParseOrigin(t *testing.T) {
	info, ok := ParseOrigin("15169 | 8.8.8.0/24 | US | arin | 2023-12-28")
	if !ok || info.ASN != "15169" || info.Prefix != "8.8.8.0/24" || info.Country != "US" {
		t.Errorf("ParseOrigin = %+v, %v", info, ok)
	}
	if info, _ := ParseOrigin("1921 207021 | 176.97.158.0/24 | NL | ripencc |"); info.ASN != "1921 207021" {
		t.Errorf("multiple origins: %+v", info)
	}
	if _, ok := ParseOrigin("garbage"); ok {
		t.Error("garbage should not parse")
	}
	if got := ParseASName("15169 | US | arin | 2000-03-30 | GOOGLE, US"); got != "GOOGLE, US" {
		t.Errorf("ParseASName = %q", got)
	}
}

func TestOriginName(t *testing.T) {
	if got, _ := originName("192.0.2.10"); got != "10.2.0.192.origin.asn.cymru.com" {
		t.Errorf("IPv4: %q", got)
	}
	got, ok := originName("2001:db8::1")
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com"
	if !ok || got != want {
		t.Errorf("IPv6: %q", got)
	}
	if _, ok := originName("not-an-ip"); ok {
		t.Error("invalid address accepted")
	}
}
