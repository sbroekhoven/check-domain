package rules

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/sbroekhoven/check-domain/internal/asn"
	"github.com/sbroekhoven/check-domain/internal/collector"
	"github.com/sbroekhoven/check-domain/internal/delegation"
	"github.com/sbroekhoven/check-domain/internal/dnssec"
	"github.com/sbroekhoven/check-domain/internal/nameservers"
	"github.com/sbroekhoven/check-domain/internal/rdap"
	"github.com/sbroekhoven/check-domain/internal/records"
	"github.com/sbroekhoven/check-domain/internal/tld"
)

var queryTime = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

func goodSOA() *nameservers.SOA {
	return &nameservers.SOA{MName: "ns1.example.com", RName: "hostmaster.example.com", Serial: 2026011501,
		Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 3600, TTL: 3600}
}

// addr is a well-behaved nameserver address
func addr(ip string) nameservers.Address {
	return nameservers.Address{
		IP: ip, Responds: true, Rcode: "NOERROR", Authoritative: true, SOA: goodSOA(),
		NS: []string{"ns1.example.com", "ns2.example.net", "ns3.example.org"}, TCP: true, EDNS: true, AXFRTested: true,
	}
}

// healthy fills in a well-configured domain: three nameservers in different networks, TLDs and ASes
func healthy(d *collector.DomainInfo) {
	d.Zone = "example.com"
	d.TLD = &tld.Info{TLD: "com", Type: tld.Generic, ICANNPolicy: "yes", Description: "gTLD", InRoot: true, Signed: true, PublicSuffix: "com"}
	d.Registration = &rdap.Domain{Registrar: "Registrar", Expires: queryTime.AddDate(1, 0, 0),
		Status: []string{"client transfer prohibited"}, Nameservers: []string{"ns1.example.com", "ns2.example.net", "ns3.example.org"}}
	d.Delegation = &delegation.Delegation{Zone: "example.com", Parent: "com", NSTTL: 172800,
		NS:   []string{"ns1.example.com", "ns2.example.net", "ns3.example.org"},
		Glue: map[string][]string{"ns1.example.com": {"192.0.2.1", "2001:db8:1::1"}}}
	d.ZoneNS = []string{"ns1.example.com", "ns2.example.net", "ns3.example.org"}

	mk := func(name string, ips []string, asNumber string) nameservers.Server {
		s := nameservers.Server{Name: name, InParent: true, InZone: true, Resolves: true}
		for _, ip := range ips {
			a := addr(ip)
			a.ASN = &asn.Info{ASN: asNumber}
			s.Addresses = append(s.Addresses, a)
		}
		return s
	}
	d.Nameservers = []nameservers.Server{
		mk("ns1.example.com", []string{"192.0.2.1", "2001:db8:1::1"}, "64500"),
		mk("ns2.example.net", []string{"198.51.100.1", "2001:db8:2::1"}, "64501"),
		mk("ns3.example.org", []string{"203.0.113.1", "2001:db8:3::1"}, "64502"),
	}
	d.MName = &collector.MName{Name: "ns1.example.com", Addresses: []string{"192.0.2.1"}}
	d.DNSSEC = &dnssec.Info{
		DS:        []dnssec.DS{{KeyTag: 1, Algorithm: 13, DigestType: 2, Matches: true}},
		DNSKEY:    []dnssec.Key{{KeyTag: 1, Algorithm: 13, Flags: 257, KSK: true}, {KeyTag: 2, Algorithm: 13, Flags: 256}},
		Validated: true, SignatureInception: queryTime.AddDate(0, 0, -7), SignatureExpiry: queryTime.AddDate(0, 0, 14),
		Denial: "NSEC3", NSEC3: &dnssec.NSEC3Param{},
	}
	d.Records = &records.Info{
		Records: []records.Record{{Type: "NS", TTL: 172800}, {Type: "A", TTL: 3600}, {Type: "MX", TTL: 3600}},
		CAA:     []records.CAA{{Tag: "issue", Value: "letsencrypt.org"}},
	}
}

// newInfo returns a healthy domain, modified by setup
func newInfo(setup func(*collector.DomainInfo)) *collector.DomainInfo {
	d := collector.NewDomainInfo("example.com")
	d.QueryTime = queryTime
	healthy(d)
	if setup != nil {
		setup(d)
	}
	return d
}

func ruleByID(t *testing.T, id int) Rule {
	t.Helper()
	for _, r := range Rules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule with ID %d", id)
	return Rule{}
}

func evalRule(t *testing.T, id int, d *collector.DomainInfo) *Outcome {
	t.Helper()
	return ruleByID(t, id).Check(d)
}

func statusOf(t *testing.T, id int, d *collector.DomainInfo) Status {
	t.Helper()
	if o := evalRule(t, id, d); o != nil {
		return o.Status
	}
	return ""
}

type ruleCase struct {
	name  string
	setup func(*collector.DomainInfo)
	want  Status
}

func runRuleCases(t *testing.T, ruleID int, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusOf(t, ruleID, newInfo(tc.setup)); got != tc.want {
				o := evalRule(t, ruleID, newInfo(tc.setup))
				t.Errorf("status = %q, want %q (outcome %+v)", got, tc.want, o)
			}
		})
	}
}

// eachAddress applies f to every probed address
func eachAddress(f func(*nameservers.Address)) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) {
		for i := range d.Nameservers {
			for j := range d.Nameservers[i].Addresses {
				f(&d.Nameservers[i].Addresses[j])
			}
		}
	}
}

// firstAddress applies f to the first probed address only
func firstAddress(f func(*nameservers.Address)) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) { f(&d.Nameservers[0].Addresses[0]) }
}

func failed(check collector.Check) func(*collector.DomainInfo) {
	return func(d *collector.DomainInfo) {
		d.Errors[check], d.Failed[check] = "i/o timeout", true
	}
}

func TestHealthyDomainHasNoProblems(t *testing.T) {
	report := Evaluate(newInfo(nil))
	for _, r := range report.RuleResults {
		if r.Status == StatusFail || r.Status == StatusWarn {
			t.Errorf("rule %d (%s) = %s: %s", r.RuleID, r.Description, r.Status, r.Message)
		}
	}
}

func TestRegistrationRules(t *testing.T) {
	t.Run("tld type", func(t *testing.T) {
		runRuleCases(t, 1, []ruleCase{
			{"gTLD", nil, StatusInfo},
			{"no data", func(d *collector.DomainInfo) { d.TLD = nil }, ""},
			{"lookup failed", failed(collector.CheckTLD), StatusInfo},
		})
	})
	t.Run("root", func(t *testing.T) {
		runRuleCases(t, 2, []ruleCase{
			{"signed", nil, StatusPass},
			{"unsigned", func(d *collector.DomainInfo) { d.TLD.Signed = false }, StatusWarn},
			{"not in root", func(d *collector.DomainInfo) { d.TLD.InRoot = false }, StatusFail},
		})
	})
	t.Run("expiry", func(t *testing.T) {
		expires := func(days int) func(*collector.DomainInfo) {
			return func(d *collector.DomainInfo) { d.Registration.Expires = queryTime.AddDate(0, 0, days) }
		}
		runRuleCases(t, 3, []ruleCase{
			{"a year", nil, StatusPass},
			{"20 days", expires(20), StatusWarn},
			{"5 days", expires(5), StatusFail},
			{"expired", expires(-1), StatusFail},
			{"not published", func(d *collector.DomainInfo) { d.Registration.Expires = time.Time{} }, StatusInfo},
			{"no RDAP service", func(d *collector.DomainInfo) {
				d.Registration = nil
				d.Errors[collector.CheckRDAP] = "the registry of .nl offers no RDAP service"
			}, StatusInfo},
			{"RDAP failed", func(d *collector.DomainInfo) { d.Registration = nil; failed(collector.CheckRDAP)(d) }, StatusInfo},
			{"RDAP disabled", func(d *collector.DomainInfo) { d.Registration = nil }, ""},
		})
	})
	t.Run("status", func(t *testing.T) {
		runRuleCases(t, 4, []ruleCase{
			{"locked", nil, StatusPass},
			{"locked ccTLD style", func(d *collector.DomainInfo) { d.Registration.Status = []string{"locked"} }, StatusPass},
			{"no lock", func(d *collector.DomainInfo) { d.Registration.Status = []string{"active"} }, StatusInfo},
			{"on hold", func(d *collector.DomainInfo) { d.Registration.Status = []string{"serverHold"} }, StatusFail},
			{"pending delete", func(d *collector.DomainInfo) { d.Registration.Status = []string{"pending delete"} }, StatusFail},
		})
	})
	t.Run("registry ns", func(t *testing.T) {
		runRuleCases(t, 5, []ruleCase{
			{"match", nil, StatusPass},
			{"differ", func(d *collector.DomainInfo) {
				d.Registration.Nameservers = []string{"ns1.example.com", "old.example.net"}
			}, StatusWarn},
			{"none at registry", func(d *collector.DomainInfo) { d.Registration.Nameservers = nil }, ""},
		})
	})
}

func TestDelegationRules(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		runRuleCases(t, 6, []ruleCase{
			{"three", nil, StatusPass},
			{"two", func(d *collector.DomainInfo) { d.Delegation.NS = d.Delegation.NS[:2] }, StatusInfo},
			{"one", func(d *collector.DomainInfo) { d.Delegation.NS = d.Delegation.NS[:1] }, StatusFail},
			{"not delegated", func(d *collector.DomainInfo) { d.Delegation = nil }, StatusFail},
			{"does not exist", func(d *collector.DomainInfo) {
				d.Delegation = nil
				d.Errors[collector.CheckZone] = "NXDOMAIN"
			}, StatusFail},
			{"delegation lookup failed", func(d *collector.DomainInfo) { d.Delegation = nil; failed(collector.CheckDelegation)(d) }, StatusInfo},
		})
	})
	t.Run("ns match", func(t *testing.T) {
		runRuleCases(t, 7, []ruleCase{
			{"match", nil, StatusPass},
			{"zone differs", func(d *collector.DomainInfo) { d.ZoneNS = []string{"ns1.example.com", "ns9.example.net"} }, StatusWarn},
			{"one server differs", firstAddress(func(a *nameservers.Address) { a.NS = []string{"ns1.example.com"} }), StatusWarn},
		})
	})
	t.Run("glue", func(t *testing.T) {
		runRuleCases(t, 8, []ruleCase{
			{"present and correct", nil, StatusPass},
			{"missing", func(d *collector.DomainInfo) { d.Delegation.Glue = map[string][]string{} }, StatusFail},
			{"different", func(d *collector.DomainInfo) { d.Delegation.Glue["ns1.example.com"] = []string{"192.0.2.99"} }, StatusWarn},
			{"not needed", func(d *collector.DomainInfo) {
				d.Delegation.NS = []string{"ns2.example.net", "ns3.example.org"}
				d.Delegation.Glue = map[string][]string{}
			}, StatusPass},
		})
	})
	t.Run("names resolve", func(t *testing.T) {
		runRuleCases(t, 9, []ruleCase{
			{"all resolve", nil, StatusPass},
			{"cname", func(d *collector.DomainInfo) { d.Nameservers[0].CNAME = "elsewhere.example.net" }, StatusFail},
			{"no address", func(d *collector.DomainInfo) {
				d.Nameservers[1].Resolves, d.Nameservers[1].Addresses = false, nil
			}, StatusFail},
			{"lookup failed", func(d *collector.DomainInfo) {
				d.Nameservers[1].Resolves, d.Nameservers[1].Addresses, d.Nameservers[1].Error = false, nil, "timeout"
			}, StatusInfo},
		})
	})
	t.Run("networks", func(t *testing.T) {
		sameNet := func(d *collector.DomainInfo) {
			for i := range d.Nameservers {
				d.Nameservers[i].Addresses[0].IP = "192.0.2." + strconv.Itoa(i+1)
				d.Nameservers[i].Addresses[1].IP = "2001:db8:1::" + strconv.Itoa(i+1)
			}
		}
		onlyV6Same := func(d *collector.DomainInfo) {
			for i := range d.Nameservers {
				d.Nameservers[i].Addresses[1].IP = "2001:db8:1::" + strconv.Itoa(i+1)
			}
		}
		runRuleCases(t, 10, []ruleCase{
			{"spread", nil, StatusPass},
			{"all in one /24 and /48", sameNet, StatusWarn},
			{"only IPv6 in one /48", onlyV6Same, StatusInfo},
		})
	})
	t.Run("asn", func(t *testing.T) {
		runRuleCases(t, 11, []ruleCase{
			{"three", nil, StatusPass},
			{"one", eachAddress(func(a *nameservers.Address) { a.ASN = &asn.Info{ASN: "64500"} }), StatusInfo},
			{"unknown", eachAddress(func(a *nameservers.Address) { a.ASN = nil }), ""},
		})
	})
	t.Run("tlds", func(t *testing.T) {
		runRuleCases(t, 12, []ruleCase{
			{"three", nil, StatusPass},
			{"one", func(d *collector.DomainInfo) { d.Delegation.NS = []string{"ns1.example.com", "ns2.example.com"} }, StatusInfo},
		})
	})
	t.Run("ipv6", func(t *testing.T) {
		v4only := func(s *nameservers.Server) { s.Addresses = s.Addresses[:1] }
		runRuleCases(t, 13, []ruleCase{
			{"all", nil, StatusPass},
			{"some", func(d *collector.DomainInfo) { v4only(&d.Nameservers[0]) }, StatusInfo},
			{"none", func(d *collector.DomainInfo) {
				for i := range d.Nameservers {
					v4only(&d.Nameservers[i])
				}
			}, StatusWarn},
		})
	})
}

func TestNameserverRules(t *testing.T) {
	noResponse := func(a *nameservers.Address) { a.Responds, a.Error = false, "i/o timeout" }
	runRuleCases(t, 14, []ruleCase{
		{"all respond", nil, StatusPass},
		{"one silent", firstAddress(noResponse), StatusFail},
		{"all silent", eachAddress(noResponse), StatusFail},
	})
	runRuleCases(t, 15, []ruleCase{
		{"authoritative", nil, StatusPass},
		{"lame", firstAddress(func(a *nameservers.Address) { a.Authoritative = false }), StatusFail},
		{"refused", firstAddress(func(a *nameservers.Address) { a.Rcode, a.SOA = "REFUSED", nil }), StatusFail},
	})
	runRuleCases(t, 16, []ruleCase{
		{"no recursion", nil, StatusPass},
		{"open resolver", firstAddress(func(a *nameservers.Address) { a.Recursive = true }), StatusFail},
	})
	runRuleCases(t, 17, []ruleCase{
		{"nothing", nil, StatusPass},
		{"version", firstAddress(func(a *nameservers.Address) { a.Version = "9.18.24-1-Debian" }), StatusWarn},
		{"product with version", firstAddress(func(a *nameservers.Address) { a.Version = "Knot DNS 3.6.2" }), StatusWarn},
		{"custom string", firstAddress(func(a *nameservers.Address) { a.Version = "go away" }), StatusInfo},
		{"commit hash", firstAddress(func(a *nameservers.Address) { a.Version = "19dd46e347df36b7" }), StatusInfo},
	})
	runRuleCases(t, 18, []ruleCase{
		{"refused", nil, StatusPass},
		{"allowed", firstAddress(func(a *nameservers.Address) { a.AXFR, a.AXFRRecords = true, 52 }), StatusFail},
		{"not tested", eachAddress(func(a *nameservers.Address) { a.AXFRTested = false }), ""},
	})
	runRuleCases(t, 19, []ruleCase{
		{"tcp", nil, StatusPass},
		{"no tcp", firstAddress(func(a *nameservers.Address) { a.TCP, a.TCPError = false, "connection refused" }), StatusFail},
	})
	runRuleCases(t, 20, []ruleCase{
		{"edns", nil, StatusPass},
		{"no edns", firstAddress(func(a *nameservers.Address) { a.EDNS = false }), StatusWarn},
	})
	runRuleCases(t, 21, []ruleCase{
		{"public", func(d *collector.DomainInfo) {
			// documentation ranges are not "global unicast" for some checks; use real public addresses here
			eachAddress(func(a *nameservers.Address) { a.IP = "8.8.8.8" })(d)
		}, StatusPass},
		{"private", firstAddress(func(a *nameservers.Address) { a.IP = "10.0.0.53" }), StatusFail},
		{"loopback", firstAddress(func(a *nameservers.Address) { a.IP = "127.0.0.1" }), StatusFail},
	})
}

func TestSOARules(t *testing.T) {
	soa := func(f func(*nameservers.SOA)) func(*collector.DomainInfo) {
		return eachAddress(func(a *nameservers.Address) { f(a.SOA) })
	}
	runRuleCases(t, 22, []ruleCase{
		{"same", nil, StatusPass},
		{"different", firstAddress(func(a *nameservers.Address) { a.SOA = goodSOA(); a.SOA.Serial = 2026011401 }), StatusWarn},
	})
	runRuleCases(t, 23, []ruleCase{
		{"recommended", nil, StatusPass},
		{"refresh too short", soa(func(s *nameservers.SOA) { s.Refresh = 300 }), StatusWarn},
		{"retry >= refresh", soa(func(s *nameservers.SOA) { s.Retry = 7200 }), StatusWarn},
		{"expire too short", soa(func(s *nameservers.SOA) { s.Expire = 86400 }), StatusWarn},
		{"negative ttl too long", soa(func(s *nameservers.SOA) { s.Minimum = 604800 }), StatusWarn},
	})
	runRuleCases(t, 24, []ruleCase{
		{"listed", nil, StatusPass},
		{"hidden master", soa(func(s *nameservers.SOA) { s.MName = "hidden.example.com" }), StatusInfo},
		{"hidden, not resolvable", func(d *collector.DomainInfo) {
			soa(func(s *nameservers.SOA) { s.MName = "hidden.example.com" })(d)
			d.MName = &collector.MName{Name: "hidden.example.com"}
		}, StatusInfo},
		{"empty", soa(func(s *nameservers.SOA) { s.MName = "" }), StatusWarn},
	})
	runRuleCases(t, 25, []ruleCase{
		{"valid", nil, StatusPass},
		{"with @", soa(func(s *nameservers.SOA) { s.RName = "hostmaster@example.com" }), StatusFail},
		{"no domain", soa(func(s *nameservers.SOA) { s.RName = "hostmaster" }), StatusWarn},
	})
	runRuleCases(t, 26, []ruleCase{
		{"date", nil, StatusPass},
		{"date in the future", soa(func(s *nameservers.SOA) { s.Serial = 2027010101 }), StatusWarn},
		{"unix time", soa(func(s *nameservers.SOA) { s.Serial = 1768478400 }), StatusPass},
		{"counter", soa(func(s *nameservers.SOA) { s.Serial = 42 }), StatusPass},
	})
}

func TestRNameToEmail(t *testing.T) {
	for rname, want := range map[string]string{
		"hostmaster.example.com":      "hostmaster@example.com",
		"hostmaster.example.com.":     "hostmaster@example.com",
		`john\.doe.example.com`:       "john.doe@example.com",
		"dns-admin.sub.example.co.uk": "dns-admin@sub.example.co.uk",
	} {
		if got, ok := RNameToEmail(rname); !ok || got != want {
			t.Errorf("RNameToEmail(%q) = %q, %v; want %q", rname, got, ok, want)
		}
	}
	for _, bad := range []string{"hostmaster", "hostmaster.com", ".example.com"} {
		if _, ok := RNameToEmail(bad); ok {
			t.Errorf("RNameToEmail(%q) should fail", bad)
		}
	}
}

func TestSerialFormat(t *testing.T) {
	for serial, want := range map[uint32]string{2026011501: "date", 1768478400: "unixtime", 42: "counter", 2026139901: "unixtime"} {
		if got, _ := SerialFormat(serial); got != want {
			t.Errorf("SerialFormat(%d) = %q, want %q", serial, got, want)
		}
	}
}

func TestDNSSECRules(t *testing.T) {
	sec := func(f func(*dnssec.Info)) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) { f(d.DNSSEC) }
	}
	runRuleCases(t, 27, []ruleCase{
		{"validated", nil, StatusPass},
		{"not validated", sec(func(s *dnssec.Info) { s.Validated = false }), StatusWarn},
		{"bogus", sec(func(s *dnssec.Info) { s.Bogus = true }), StatusFail},
		{"no DS", sec(func(s *dnssec.Info) { s.DS = nil }), StatusWarn},
		{"DS without keys", sec(func(s *dnssec.Info) { s.DNSKEY = nil }), StatusFail},
		{"unsigned", sec(func(s *dnssec.Info) { s.DS, s.DNSKEY = nil, nil }), StatusWarn},
		{"lookup failed", failed(collector.CheckDNSSEC), StatusInfo},
	})
	runRuleCases(t, 28, []ruleCase{
		{"matches", nil, StatusPass},
		{"broken", sec(func(s *dnssec.Info) { s.DS[0].Matches = false }), StatusFail},
		{"extra DS", sec(func(s *dnssec.Info) { s.DS = append(s.DS, dnssec.DS{KeyTag: 9, DigestType: 2}) }), StatusInfo},
	})
	runRuleCases(t, 29, []ruleCase{
		{"ecdsa", nil, StatusPass},
		{"rsasha1", sec(func(s *dnssec.Info) { s.DNSKEY[0].Algorithm = 7 }), StatusWarn},
		{"rsamd5", sec(func(s *dnssec.Info) { s.DNSKEY[0].Algorithm = 1 }), StatusFail},
		{"sha1 DS only", sec(func(s *dnssec.Info) { s.DS[0].DigestType = 1 }), StatusWarn},
	})
	runRuleCases(t, 30, []ruleCase{
		{"two weeks", nil, StatusPass},
		{"three days", sec(func(s *dnssec.Info) { s.SignatureExpiry = queryTime.AddDate(0, 0, 3) }), StatusWarn},
		{"expired", sec(func(s *dnssec.Info) { s.SignatureExpiry = queryTime.Add(-time.Hour) }), StatusFail},
		{"online signing", sec(func(s *dnssec.Info) {
			s.SignatureInception, s.SignatureExpiry = queryTime.Add(-time.Hour), queryTime.Add(36*time.Hour)
		}), StatusPass},
	})
	runRuleCases(t, 31, []ruleCase{
		{"nsec3 recommended", nil, StatusPass},
		{"nsec3 iterations", sec(func(s *dnssec.Info) { s.NSEC3 = &dnssec.NSEC3Param{Iterations: 10, SaltLength: 8} }), StatusWarn},
		{"nsec", sec(func(s *dnssec.Info) { s.Denial, s.NSEC3 = "NSEC", nil }), StatusInfo},
		{"unsigned", sec(func(s *dnssec.Info) { s.DNSKEY = nil }), ""},
	})
}

func TestRecordRules(t *testing.T) {
	rec := func(f func(*records.Info)) func(*collector.DomainInfo) {
		return func(d *collector.DomainInfo) { f(d.Records) }
	}
	runRuleCases(t, 32, []ruleCase{
		{"normal", nil, StatusPass},
		{"low", rec(func(r *records.Info) { r.Records[1].TTL = 60 }), StatusWarn},
		{"high", rec(func(r *records.Info) { r.Records[1].TTL = 2592000 }), StatusWarn},
		{"low TXT ignored", rec(func(r *records.Info) { r.Records = append(r.Records, records.Record{Type: "TXT", TTL: 60}) }), StatusPass},
	})
	runRuleCases(t, 33, []ruleCase{
		{"none", nil, StatusPass},
		{"cname", rec(func(r *records.Info) { r.ApexCNAME = "example.net" }), StatusFail},
	})
	runRuleCases(t, 34, []ruleCase{
		{"none", nil, StatusPass},
		{"wildcard", rec(func(r *records.Info) { r.Wildcard = true }), StatusInfo},
	})
	runRuleCases(t, 35, []ruleCase{
		{"present", nil, StatusPass},
		{"missing", rec(func(r *records.Info) { r.CAA = nil }), StatusInfo},
		{"unknown tag", rec(func(r *records.Info) { r.CAA = append(r.CAA, records.CAA{Flag: 128, Tag: "tbs"}) }), StatusWarn},
	})
}

func TestEvaluate(t *testing.T) {
	report := Evaluate(newInfo(func(d *collector.DomainInfo) { d.Delegation.NS = d.Delegation.NS[:1] }))
	for i := 1; i < len(report.RuleResults); i++ {
		if report.RuleResults[i-1].RuleID >= report.RuleResults[i].RuleID {
			t.Fatalf("results not sorted by rule ID")
		}
	}
	if !report.HasStatus(StatusFail) || report.Worst() != StatusFail {
		t.Error("a single nameserver should fail")
	}
}

func TestRegistry(t *testing.T) {
	areas := map[Area]bool{}
	for _, a := range Areas {
		areas[a] = true
	}
	prev := 0
	for _, r := range Rules() {
		if r.ID <= prev {
			t.Errorf("rule %d: IDs must be unique and ascending (previous %d)", r.ID, prev)
		}
		prev = r.ID
		if !areas[r.Area] || r.Name == "" || r.Check == nil {
			t.Errorf("rule %d is incomplete: %+v", r.ID, r)
		}
	}
}

// TestRegistryMatchesReadme keeps the rule table in README.md in sync with the registry
func TestRegistryMatchesReadme(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[int]Area{}
	for _, m := range regexp.MustCompile(`(?m)^\| (\d+) \| (\w+) \|`).FindAllStringSubmatch(string(readme), -1) {
		id, _ := strconv.Atoi(m[1])
		documented[id] = Area(m[2])
	}
	for _, r := range Rules() {
		if area, ok := documented[r.ID]; !ok || area != r.Area {
			t.Errorf("rule %d (%s, %s) is missing or has the wrong area in the README rule table", r.ID, r.Area, r.Name)
		}
		delete(documented, r.ID)
	}
	for id := range documented {
		t.Errorf("README documents rule %d, which does not exist", id)
	}
}

func TestStatusSeverity(t *testing.T) {
	order := []Status{StatusPass, StatusInfo, StatusWarn, StatusFail}
	for i := 1; i < len(order); i++ {
		if Worst(order[i-1], order[i]) != order[i] || Worst(order[i], order[i-1]) != order[i] {
			t.Errorf("Worst(%s, %s) should be %s", order[i-1], order[i], order[i])
		}
	}
}
