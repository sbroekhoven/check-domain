package nameservers

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// fakeServer is a minimal authoritative server for example.test
type fakeServer struct {
	authoritative bool
	recursive     bool   // answers out-of-zone queries with RA set
	version       string // answer to version.bind CH TXT
	allowAXFR     bool
}

func (f fakeServer) records() (soa, ns, a dns.RR) {
	soa, _ = dns.NewRR("example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026102101 7200 3600 1209600 3600")
	ns, _ = dns.NewRR("example.test. 3600 IN NS ns1.example.test.")
	a, _ = dns.NewRR("ns1.example.test. 3600 IN A 192.0.2.53")
	return soa, ns, a
}

func (f fakeServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = f.authoritative
	if r.IsEdns0() != nil {
		m.SetEdns0(1232, false)
	}
	soa, ns, a := f.records()
	q := r.Question[0]

	switch {
	case q.Qclass == dns.ClassCHAOS && q.Name == "version.bind.":
		if f.version != "" {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS}, Txt: []string{f.version}})
		}
	case q.Qtype == dns.TypeAXFR:
		if !f.allowAXFR {
			m.Rcode = dns.RcodeRefused
			break
		}
		ch := make(chan *dns.Envelope)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = new(dns.Transfer).Out(w, r, ch)
		}()
		ch <- &dns.Envelope{RR: []dns.RR{soa, ns, a, soa}}
		close(ch)
		wg.Wait()
		return
	case q.Name == "example.test." && q.Qtype == dns.TypeSOA:
		m.Answer = append(m.Answer, soa)
	case q.Name == "example.test." && q.Qtype == dns.TypeNS:
		m.Answer = append(m.Answer, ns)
	case q.Name == "www.iana.org." && r.RecursionDesired && f.recursive:
		m.RecursionAvailable = true
		m.Authoritative = false
		rr, _ := dns.NewRR("www.iana.org. 300 IN A 192.0.43.8")
		m.Answer = append(m.Answer, rr)
	default:
		m.Rcode = dns.RcodeRefused
	}
	_ = w.WriteMsg(m)
}

// start runs the fake server on UDP and TCP on the same local port and points DNSPort at it
func start(t *testing.T, f fakeServer) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		pc.Close()
		t.Skipf("TCP port %s not free: %v", port, err)
	}

	servers := []*dns.Server{{PacketConn: pc, Handler: f}, {Listener: l, Handler: f}}
	for _, s := range servers {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		<-started
	}
	t.Cleanup(func() {
		for _, s := range servers {
			_ = s.Shutdown()
		}
	})

	old := resolver.DNSPort
	resolver.DNSPort = port
	t.Cleanup(func() { resolver.DNSPort = old })
}

func probe(t *testing.T, f fakeServer) Address {
	start(t, f)
	res := resolver.New("127.0.0.1", "", 2*time.Second)
	a := Address{IP: "127.0.0.1"}
	probeAddress("example.test", &a, res, Options{AXFR: true})
	return a
}

func TestProbeWellConfigured(t *testing.T) {
	a := probe(t, fakeServer{authoritative: true})

	if !a.Responds || !a.Authoritative || a.Rcode != "NOERROR" {
		t.Fatalf("expected an authoritative answer: %+v", a)
	}
	if a.SOA == nil || a.SOA.Serial != 2026102101 || a.SOA.MName != "ns1.example.test" || a.SOA.RName != "hostmaster.example.test" || a.SOA.Expire != 1209600 {
		t.Errorf("SOA = %+v", a.SOA)
	}
	if len(a.NS) != 1 || a.NS[0] != "ns1.example.test" {
		t.Errorf("NS = %v", a.NS)
	}
	if a.Recursive || a.Version != "" || !a.TCP || !a.EDNS || !a.AXFRTested || a.AXFR {
		t.Errorf("recursive=%v version=%q tcp=%v edns=%v axfr=%v", a.Recursive, a.Version, a.TCP, a.EDNS, a.AXFR)
	}
}

func TestProbeMisconfigured(t *testing.T) {
	a := probe(t, fakeServer{authoritative: false, recursive: true, version: "BIND 9.18.1", allowAXFR: true})

	if !a.Responds || a.Authoritative {
		t.Errorf("expected a non-authoritative answer: %+v", a)
	}
	if !a.Recursive {
		t.Error("open recursion not detected")
	}
	if a.Version != "BIND 9.18.1" || a.VersionQuery != "version.bind" {
		t.Errorf("version = %q via %q", a.Version, a.VersionQuery)
	}
	if !a.AXFR || a.AXFRRecords != 4 {
		t.Errorf("AXFR = %v with %d records, want allowed with 4", a.AXFR, a.AXFRRecords)
	}
}

func TestProbeNoResponse(t *testing.T) {
	old := resolver.DNSPort
	resolver.DNSPort = "1" // nothing listens here
	defer func() { resolver.DNSPort = old }()

	a := Address{IP: "127.0.0.1"}
	probeAddress("example.test", &a, resolver.New("127.0.0.1", "", 500*time.Millisecond), Options{AXFR: true})
	if a.Responds || a.Error == "" || a.AXFRTested {
		t.Errorf("unreachable server: %+v", a)
	}
}

func TestRecursionTestName(t *testing.T) {
	for zone, want := range map[string]string{"example.com": "www.iana.org", "iana.org": "www.ripe.net", "org": "www.ripe.net"} {
		if got := recursionTestName(zone); got != want {
			t.Errorf("recursionTestName(%q) = %q, want %q", zone, got, want)
		}
	}
}
