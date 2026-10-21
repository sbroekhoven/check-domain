// Package delegation finds the zone of a domain and the delegation its parent zone publishes
package delegation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// Delegation is the NS set and glue for a zone, as served by the parent zone's nameservers
type Delegation struct {
	Zone          string              `json:"zone"`
	Parent        string              `json:"parent"`         // apex of the parent zone, "." for a TLD
	ParentServers []string            `json:"parent_servers"` // NS names of the parent zone
	AnsweredBy    string              `json:"answered_by"`    // parent server (name and address) that gave the referral
	NS            []string            `json:"ns"`             // delegated nameservers, lowercase, sorted
	NSTTL         uint32              `json:"ns_ttl"`
	Glue          map[string][]string `json:"glue"` // NS name -> addresses from the additional section
}

// Name normalizes a domain name: lowercase, without trailing dot
func Name(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// FindZone returns the apex of the zone that contains name, using the owner of the SOA record.
// A name that does not exist returns a *resolver.RcodeError (NXDOMAIN).
func FindZone(name string, res *resolver.Resolver) (string, error) {
	r, err := res.Query(name, dns.TypeSOA, false)
	if r == nil || resolver.IsNXDomain(err) {
		return "", err
	}

	// A CNAME can't be a zone apex, and the SOA in the answer would belong to the CNAME target's
	// zone; continue the search from the parent name
	for _, rr := range r.Answer {
		if cname, ok := rr.(*dns.CNAME); ok && Name(cname.Hdr.Name) == Name(name) {
			if parent := ParentName(Name(name)); parent != "." {
				return FindZone(parent, res)
			}
		}
	}

	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return Name(soa.Hdr.Name), nil
		}
	}
	for _, rr := range r.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return Name(soa.Hdr.Name), nil
		}
	}
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("no SOA record found for %s or its parents", name)
}

// ParentName returns the name one label up, "." for a TLD
func ParentName(zone string) string {
	_, parent, found := strings.Cut(zone, ".")
	if !found || parent == "" {
		return "."
	}
	return parent
}

// Lookup asks the parent zone's nameservers for the delegation of zone
func Lookup(zone string, res *resolver.Resolver) (*Delegation, error) {
	d := &Delegation{Zone: zone, Glue: map[string][]string{}}

	parent := "."
	if p := ParentName(zone); p != "." {
		var err error
		if parent, err = FindZone(p, res); err != nil {
			return nil, fmt.Errorf("finding the parent zone of %s: %w", zone, err)
		}
	}
	d.Parent = parent

	r, err := res.Query(parent, dns.TypeNS, false)
	if err != nil {
		return nil, fmt.Errorf("looking up the nameservers of %s: %w", parent, err)
	}
	for _, rr := range r.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			d.ParentServers = append(d.ParentServers, Name(ns.Ns))
		}
	}
	sort.Strings(d.ParentServers)
	if len(d.ParentServers) == 0 {
		return nil, fmt.Errorf("the parent zone %s has no nameservers", parent)
	}

	// Ask the parent servers one by one until one gives a usable answer
	var lastErr error
	for _, server := range d.ParentServers {
		for _, ip := range addresses(server, res) {
			resp, _, err := res.QueryServer(resolver.ServerAddr(ip), zone, dns.TypeNS, resolver.ServerOptions{})
			if err != nil {
				lastErr = err
				continue
			}
			if resp.Rcode == dns.RcodeNameError {
				return nil, &resolver.NotFoundError{What: "delegation", Name: zone + " in " + parent}
			}
			if resp.Rcode != dns.RcodeSuccess {
				lastErr = &resolver.RcodeError{Name: zone, Rcode: resp.Rcode}
				continue
			}
			if d.parse(resp) {
				d.AnsweredBy = fmt.Sprintf("%s (%s)", server, ip)
				return d, nil
			}
			lastErr = fmt.Errorf("%s gave no NS records for %s", server, zone)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address found for the nameservers of %s", parent)
	}
	return nil, fmt.Errorf("asking the parent zone %s for the delegation: %w", parent, lastErr)
}

// parse reads the NS set from a referral (authority section) or an authoritative answer, and the
// glue from the additional section. It returns false when there are no NS records for the zone.
func (d *Delegation) parse(resp *dns.Msg) bool {
	seen := map[string]bool{}
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			ns, ok := rr.(*dns.NS)
			if !ok || Name(ns.Hdr.Name) != d.Zone {
				continue
			}
			name := Name(ns.Ns)
			if !seen[name] {
				seen[name] = true
				d.NS = append(d.NS, name)
				d.NSTTL = ns.Hdr.Ttl
			}
		}
	}
	sort.Strings(d.NS)

	for _, rr := range resp.Extra {
		owner := Name(rr.Header().Name)
		if !seen[owner] {
			continue
		}
		switch a := rr.(type) {
		case *dns.A:
			d.Glue[owner] = append(d.Glue[owner], a.A.String())
		case *dns.AAAA:
			d.Glue[owner] = append(d.Glue[owner], a.AAAA.String())
		}
	}
	return len(d.NS) > 0
}

// addresses resolves the IPv4 and IPv6 addresses of a host through the recursive resolver
func addresses(host string, res *resolver.Resolver) []string {
	var ips []string
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

// InBailiwick reports whether a nameserver name is inside the zone, so the parent must publish
// glue for it (RFC 9471)
func InBailiwick(ns, zone string) bool {
	ns, zone = Name(ns), Name(zone)
	return ns == zone || strings.HasSuffix(ns, "."+zone)
}
