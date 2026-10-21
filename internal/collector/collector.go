package collector

import (
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/delegation"
	"github.com/sbroekhoven/check-domain/internal/dnssec"
	"github.com/sbroekhoven/check-domain/internal/nameservers"
	"github.com/sbroekhoven/check-domain/internal/rdap"
	"github.com/sbroekhoven/check-domain/internal/records"
	"github.com/sbroekhoven/check-domain/internal/resolver"
	"github.com/sbroekhoven/check-domain/internal/tld"
	"golang.org/x/net/publicsuffix"
)

// Check identifies one lookup of the collection; it is the key of Errors and Failed
type Check string

const (
	CheckZone        Check = "zone"
	CheckTLD         Check = "tld"
	CheckRDAP        Check = "rdap"
	CheckDelegation  Check = "delegation"
	CheckZoneNS      Check = "zone-ns"
	CheckNameservers Check = "nameservers"
	CheckDNSSEC      Check = "dnssec"
	CheckRecords     Check = "records"
)

// DomainInfo is everything collected about a domain
type DomainInfo struct {
	Domain       string                 `json:"domain"` // as given, normalized
	Zone         string                 `json:"zone"`   // the zone apex that was checked
	QueryTime    time.Time              `json:"query_time"`
	TLD          *tld.Info              `json:"tld"`
	Registration *rdap.Domain           `json:"registration"`
	Delegation   *delegation.Delegation `json:"delegation"`
	ZoneNS       []string               `json:"zone_ns"` // the zone's own NS records, via the resolver
	Nameservers  []nameservers.Server   `json:"nameservers"`
	DNSSEC       *dnssec.Info           `json:"dnssec"`
	Records      *records.Info          `json:"records"`
	MName        *MName                 `json:"mname"`                    // the SOA primary nameserver
	Errors       map[Check]string       `json:"errors,omitempty"`         // Lookup errors per check, including "not found"
	Failed       map[Check]bool         `json:"failed_lookups,omitempty"` // Checks whose lookup failed, so their result is unknown

	mu sync.Mutex
}

// MName is the primary nameserver named in the SOA record
type MName struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"` // empty when the name does not resolve
}

// Options tunes what is collected
type Options struct {
	AXFR    bool          // try zone transfers from the nameservers
	RDAP    bool          // look up the registration via RDAP
	Timeout time.Duration // timeout for the RDAP requests
}

// NewDomainInfo creates a new DomainInfo structure
func NewDomainInfo(domain string) *DomainInfo {
	return &DomainInfo{
		Domain:    domain,
		QueryTime: time.Now(),
		Errors:    make(map[Check]string),
		Failed:    make(map[Check]bool),
	}
}

// CollectDomainInfo gathers all information about the domain's zone, in three phases:
//  1. the zone apex, then (concurrently) the delegation, TLD, registration and the zone's NS records
//  2. probing every nameserver address
//  3. DNSSEC and the apex records, read from an authoritative nameserver
//
// Failures are recorded per check in Errors rather than aborting the collection.
func CollectDomainInfo(domain string, res *resolver.Resolver, opts Options) *DomainInfo {
	info := NewDomainInfo(domain)

	var wg sync.WaitGroup
	run := func(name Check, lookup func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := lookup(); err != nil {
				info.recordError(name, err)
			}
		}()
	}

	zone, err := delegation.FindZone(domain, res)
	if err != nil {
		info.recordError(CheckZone, err)
		return info
	}
	info.Zone = zone

	run(CheckDelegation, func() (err error) {
		info.Delegation, err = delegation.Lookup(zone, res)
		return err
	})
	run(CheckTLD, func() (err error) {
		suffix, _ := publicsuffix.PublicSuffix(zone)
		info.TLD, err = tld.Lookup(zone, suffix, res)
		return err
	})
	if opts.RDAP {
		run(CheckRDAP, func() (err error) {
			timeout := opts.Timeout
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			info.Registration, err = rdap.NewClient(timeout).Lookup(registeredDomain(zone))
			return err
		})
	}
	run(CheckZoneNS, func() error {
		r, err := res.Query(zone, dns.TypeNS, false)
		if err != nil {
			return err
		}
		info.ZoneNS = []string{}
		for _, rr := range r.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				info.ZoneNS = append(info.ZoneNS, delegation.Name(ns.Ns))
			}
		}
		sort.Strings(info.ZoneNS)
		return nil
	})
	wg.Wait()

	// Phase 2: the nameservers named by the parent and by the zone itself
	var parentNS []string
	if info.Delegation != nil {
		parentNS = info.Delegation.NS
	}
	if len(parentNS)+len(info.ZoneNS) > 0 {
		info.Nameservers = nameservers.Probe(zone, parentNS, info.ZoneNS, res, nameservers.Options{AXFR: opts.AXFR})
	}

	// Phase 3: read the zone data from a server that answers authoritatively
	server := info.authoritativeServer()
	run(CheckDNSSEC, func() (err error) {
		info.DNSSEC, err = dnssec.Lookup(zone, server, res)
		return err
	})
	if server != "" {
		run(CheckRecords, func() (err error) {
			info.Records, err = records.Lookup(zone, server, res)
			return err
		})
	}
	if soa := info.SOA(); soa != nil && soa.MName != "" {
		run(CheckNameservers, func() error {
			info.MName = &MName{Name: soa.MName, Addresses: resolveHost(soa.MName, res)}
			return nil
		})
	}
	wg.Wait()
	return info
}

func (di *DomainInfo) recordError(check Check, err error) {
	di.mu.Lock()
	defer di.mu.Unlock()
	di.Errors[check] = err.Error()
	if !resolver.IsNotFound(err) {
		di.Failed[check] = true
	}
}

// authoritativeServer returns host:port of the first address that answered authoritatively
func (di *DomainInfo) authoritativeServer() string {
	for _, s := range di.Nameservers {
		for _, a := range s.Addresses {
			if a.Responds && a.Authoritative {
				return resolver.ServerAddr(a.IP)
			}
		}
	}
	return ""
}

// registeredDomain returns the domain as registered at the registry, e.g. bbc.co.uk for
// news.bbc.co.uk when news.bbc.co.uk is its own zone
func registeredDomain(zone string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(zone); err == nil {
		return d
	}
	return zone
}

// HasErrors returns true if any errors were encountered during collection
func (di *DomainInfo) HasErrors() bool {
	return len(di.Errors) > 0
}

// HasFailedLookups returns true if any lookup failed, so the results are incomplete
func (di *DomainInfo) HasFailedLookups() bool {
	return len(di.Failed) > 0
}

// LookupFailure returns the error of a failed lookup for a check, if it failed
func (di *DomainInfo) LookupFailure(check Check) (string, bool) {
	if !di.Failed[check] {
		return "", false
	}
	return di.Errors[check], true
}

// Addresses returns every probed nameserver address
func (di *DomainInfo) Addresses() []nameservers.Address {
	var all []nameservers.Address
	for _, s := range di.Nameservers {
		all = append(all, s.Addresses...)
	}
	return all
}

// SOA returns the SOA record of the first authoritative answer
func (di *DomainInfo) SOA() *nameservers.SOA {
	for _, a := range di.Addresses() {
		if a.Authoritative && a.SOA != nil {
			return a.SOA
		}
	}
	return nil
}

// resolveHost returns the A and AAAA addresses of a host via the resolver
func resolveHost(host string, res *resolver.Resolver) []string {
	ips := []string{}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r, err := res.Query(host, qtype, false)
		if err != nil {
			continue
		}
		for _, rr := range r.Answer {
			switch a := rr.(type) {
			case *dns.A:
				ips = append(ips, a.A.String())
			case *dns.AAAA:
				ips = append(ips, a.AAAA.String())
			}
		}
	}
	return ips
}
