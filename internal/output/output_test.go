package output

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sbroekhoven/check-domain/internal/collector"
	"github.com/sbroekhoven/check-domain/internal/delegation"
	"github.com/sbroekhoven/check-domain/internal/nameservers"
	"github.com/sbroekhoven/check-domain/internal/records"
	"github.com/sbroekhoven/check-domain/internal/rules"
)

// testReport builds a small domain: one nameserver that is an open resolver
func testReport() *rules.Report {
	info := collector.NewDomainInfo("www.example.com")
	info.Zone = "example.com"
	info.QueryTime = time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	info.Delegation = &delegation.Delegation{Zone: "example.com", Parent: "com", NS: []string{"ns1.example.com"},
		Glue: map[string][]string{"ns1.example.com": {"192.0.2.1"}}}
	info.ZoneNS = []string{"ns1.example.com"}
	info.Nameservers = []nameservers.Server{{
		Name: "ns1.example.com", InParent: true, InZone: true, Resolves: true,
		Addresses: []nameservers.Address{{
			IP: "192.0.2.1", Responds: true, Rcode: "NOERROR", Authoritative: true, Recursive: true, TCP: true, EDNS: true,
			SOA: &nameservers.SOA{MName: "ns1.example.com", RName: "hostmaster.example.com", Serial: 2026010201,
				Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 3600},
			NS: []string{"ns1.example.com"},
		}},
	}}
	info.Records = &records.Info{Server: "192.0.2.1:53", Records: []records.Record{
		{Type: "A", Value: `<script>alert(1)</script>`, TTL: 3600},
	}}
	return rules.Evaluate(info)
}

func TestWrap(t *testing.T) {
	tests := []struct {
		text  string
		width int
		want  []string
	}{
		{"", 10, []string{""}},
		{"one two three four", 9, []string{"one two", "three", "four"}},
		{"averyveryverylongword fits", 5, []string{"averyveryverylongword", "fits"}},
	}
	for _, tt := range tests {
		if got := wrap(tt.text, tt.width); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("wrap(%q, %d) = %q, want %q", tt.text, tt.width, got, tt.want)
		}
	}
}

func TestConsolePrint(t *testing.T) {
	var out strings.Builder
	c := &Console{w: &out, width: 100}
	c.Print(testReport(), "8.8.8.8:53")
	got := out.String()

	for _, want := range []string{
		"www.example.com  ·  2026-01-02 03:04  ·  via 8.8.8.8\n",
		"Delegation   ✗  ns1.example.com\n",
		"             ✗  1 nameserver\n",
		"             ✗  Open recursion\n",
		"SOA          ✓  serial 2026010201 · primary ns1.example.com\n",
		" passed · ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Registration ") {
		t.Error("an area without results should not be printed")
	}
	if strings.Contains(got, "\033[") {
		t.Error("ANSI codes while colour is off")
	}
}

func TestWriteHTML(t *testing.T) {
	var out strings.Builder
	if err := WriteHTML(&out, testReport(), "8.8.8.8:53", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	html := out.String()

	for _, want := range []string{
		"<title>Domain report: www.example.com</title>",
		"Zone example.com · Checked 2 January 2026, 03:04 UTC · via 8.8.8.8",
		`<section class="card fail" id="delegation">`,
		`<section class="card fail" id="nameservers">`,
		`id="soa"`, `id="records"`,
		"<td>OPEN</td>",
		"check-domain</a> 1.2.3",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if strings.Contains(html, "<script>alert") || !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("DNS data is not escaped")
	}
	if n := strings.Count(html, `href="http`); n != 1 {
		t.Errorf("report contains %d external links, want only the footer link", n)
	}
	if strings.Contains(html, `src="`) || strings.Contains(html, "<link") {
		t.Error("report loads external resources")
	}
}
