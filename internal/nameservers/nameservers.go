// Package nameservers resolves a zone's nameservers and probes each of their addresses directly
package nameservers

import (
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/asn"
	"github.com/sbroekhoven/check-domain/internal/delegation"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// Server is one nameserver name with its addresses
type Server struct {
	Name      string    `json:"name"`
	InParent  bool      `json:"in_parent"`       // listed in the parent's delegation
	InZone    bool      `json:"in_zone"`         // listed in the zone's own NS records
	CNAME     string    `json:"cname,omitempty"` // the NS name is an alias, which RFC 2181 forbids
	Resolves  bool      `json:"resolves"`        // the name has at least one A or AAAA record
	Error     string    `json:"error,omitempty"` // resolving the name failed (not: it doesn't exist)
	Addresses []Address `json:"addresses"`
}

// Address is the result of probing one nameserver address
type Address struct {
	IP            string    `json:"ip"`
	Responds      bool      `json:"responds"`
	Error         string    `json:"error,omitempty"`
	RTTMillis     int64     `json:"rtt_ms"`
	Rcode         string    `json:"rcode"`
	Authoritative bool      `json:"authoritative"` // AA flag on the SOA answer
	SOA           *SOA      `json:"soa,omitempty"`
	NS            []string  `json:"ns"`        // the zone's NS set as this server reports it
	Recursive     bool      `json:"recursive"` // answered an out-of-zone query with recursion
	Version       string    `json:"version,omitempty"`
	VersionQuery  string    `json:"version_query,omitempty"` // which CHAOS name gave the version
	TCP           bool      `json:"tcp"`
	TCPError      string    `json:"tcp_error,omitempty"`
	EDNS          bool      `json:"edns"`
	AXFRTested    bool      `json:"axfr_tested"`
	AXFR          bool      `json:"axfr"` // the server handed out the full zone
	AXFRRecords   int       `json:"axfr_records,omitempty"`
	ASN           *asn.Info `json:"asn,omitempty"`
}

// SOA is a parsed SOA record
type SOA struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"` // negative caching TTL (RFC 2308)
	TTL     uint32 `json:"ttl"`
}

// Options controls the probes
type Options struct {
	AXFR bool // try a zone transfer from every address
}

// Probe resolves every nameserver name and probes all its addresses concurrently. parentNS and
// zoneNS mark where each name was listed; the union of both is probed.
func Probe(zone string, parentNS, zoneNS []string, res *resolver.Resolver, opts Options) []Server {
	inParent, inZone := set(parentNS), set(zoneNS)
	var names []string
	for name := range union(inParent, inZone) {
		names = append(names, name)
	}
	sort.Strings(names)

	servers := make([]Server, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers[i] = probeServer(zone, name, res, opts)
			servers[i].InParent, servers[i].InZone = inParent[name], inZone[name]
		}()
	}
	wg.Wait()

	// Origin AS of every address
	var ips []string
	for _, s := range servers {
		for _, a := range s.Addresses {
			ips = append(ips, a.IP)
		}
	}
	origins := asn.Lookup(ips, res)
	for i := range servers {
		for j := range servers[i].Addresses {
			if info, ok := origins[servers[i].Addresses[j].IP]; ok {
				servers[i].Addresses[j].ASN = &info
			}
		}
	}
	return servers
}

func probeServer(zone, name string, res *resolver.Resolver, opts Options) Server {
	s := Server{Name: name, Addresses: []Address{}}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r, err := res.Query(name, qtype, false)
		if err != nil {
			if !resolver.IsNotFound(err) {
				s.Error = err.Error()
			}
			continue
		}
		for _, rr := range r.Answer {
			switch a := rr.(type) {
			case *dns.CNAME:
				if delegation.Name(a.Hdr.Name) == name {
					s.CNAME = delegation.Name(a.Target)
				}
			case *dns.A:
				s.Addresses = append(s.Addresses, Address{IP: a.A.String()})
			case *dns.AAAA:
				s.Addresses = append(s.Addresses, Address{IP: a.AAAA.String()})
			}
		}
	}
	s.Resolves = len(s.Addresses) > 0

	var wg sync.WaitGroup
	for i := range s.Addresses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			probeAddress(zone, &s.Addresses[i], res, opts)
		}()
	}
	wg.Wait()
	return s
}

// probeAddress sends the test queries to one address
func probeAddress(zone string, a *Address, res *resolver.Resolver, opts Options) {
	server := resolver.ServerAddr(a.IP)

	// SOA over UDP with EDNS; retry without EDNS if the server rejects it
	resp, rtt, err := res.QueryServer(server, zone, dns.TypeSOA, resolver.ServerOptions{})
	if err == nil && resp.Rcode == dns.RcodeFormatError {
		resp, rtt, err = res.QueryServer(server, zone, dns.TypeSOA, resolver.ServerOptions{NoEDNS: true})
	} else if err == nil {
		a.EDNS = resp.IsEdns0() != nil
	}
	if err != nil {
		a.Error = err.Error()
		return
	}
	a.Responds = true
	a.RTTMillis = rtt.Milliseconds()
	a.Rcode = dns.RcodeToString[resp.Rcode]
	a.Authoritative = resp.Authoritative
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			a.SOA = &SOA{
				MName: delegation.Name(soa.Ns), RName: delegation.Name(soa.Mbox),
				Serial: soa.Serial, Refresh: soa.Refresh, Retry: soa.Retry,
				Expire: soa.Expire, Minimum: soa.Minttl, TTL: soa.Hdr.Ttl,
			}
		}
	}

	// The zone's NS set as this server sees it
	a.NS = []string{}
	if resp, _, err := res.QueryServer(server, zone, dns.TypeNS, resolver.ServerOptions{}); err == nil {
		for _, rr := range resp.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				a.NS = append(a.NS, delegation.Name(ns.Ns))
			}
		}
		sort.Strings(a.NS)
	}

	// Recursion: ask for a name outside the zone with RD set
	if resp, _, err := res.QueryServer(server, recursionTestName(zone), dns.TypeA, resolver.ServerOptions{Recursion: true}); err == nil {
		a.Recursive = resp.RecursionAvailable && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0
	}

	a.Version, a.VersionQuery = versionString(server, res)

	if resp, _, err := res.QueryServer(server, zone, dns.TypeSOA, resolver.ServerOptions{TCP: true}); err != nil {
		a.TCPError = err.Error()
	} else {
		a.TCP = resp.Rcode == dns.RcodeSuccess
	}

	if opts.AXFR {
		a.AXFRTested = true
		if n, err := res.AXFR(server, zone); err == nil && n > 0 {
			a.AXFR, a.AXFRRecords = true, n
		}
	}
}

// recursionTestName returns a name outside the checked zone for the recursion test; an
// authoritative-only server can't answer it
func recursionTestName(zone string) string {
	for _, name := range []string{"www.iana.org", "www.ripe.net"} {
		if !delegation.InBailiwick(name, zone) {
			return name
		}
	}
	return "www.icann.org" // only reached for a zone containing both names, i.e. the root
}

// versionString asks the CHAOS-class names that servers commonly use to report their software
func versionString(server string, res *resolver.Resolver) (string, string) {
	for _, name := range []string{"version.bind", "version.server"} {
		resp, _, err := res.QueryServer(server, name, dns.TypeTXT, resolver.ServerOptions{Class: dns.ClassCHAOS, NoEDNS: true})
		if err != nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range resp.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				if v := strings.TrimSpace(strings.Join(txt.Txt, "")); v != "" {
					return v, name
				}
			}
		}
	}
	return "", ""
}

func set(names []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[delegation.Name(n)] = true
	}
	return m
}

func union(a, b map[string]bool) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}
