package rules

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/sbroekhoven/check-domain/internal/collector"
	"github.com/sbroekhoven/check-domain/internal/delegation"
)

// checkNSCount verifies the domain exists and is delegated to enough nameservers (RFC 1034, RFC 2182)
func checkNSCount(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckZone, "zone"); o != nil {
		return o
	}
	if err, ok := d.Errors[collector.CheckZone]; ok {
		return fail("Domain does not exist", "The domain does not exist in DNS: "+err+".")
	}
	if o := unchecked(d, collector.CheckDelegation, "delegation"); o != nil {
		return o
	}
	if d.Delegation == nil {
		return fail("Not delegated", fmt.Sprintf("The parent zone has no delegation for %s.", d.Zone))
	}

	n := len(d.Delegation.NS)
	list := strings.Join(d.Delegation.NS, ", ")
	switch {
	case n < 2:
		return fail(plural(n, "nameserver"),
			"At least two nameservers are required (RFC 1034), so the domain keeps working when one is down: "+list+".")
	case n == 2:
		return inform("2 nameservers",
			"Two nameservers meet the minimum; RFC 2182 recommends three or more for important zones: "+list+".")
	default:
		return pass(fmt.Sprintf("%d nameservers", n), "Delegated to "+list+".")
	}
}

// checkNSMatch compares the parent delegation with the zone's own NS records on every nameserver
func checkNSMatch(d *collector.DomainInfo) *Outcome {
	if d.Delegation == nil {
		return nil
	}
	parent := d.Delegation.NS

	var problems []string
	if len(d.ZoneNS) > 0 {
		if onlyParent, onlyZone := diff(parent, d.ZoneNS); len(onlyParent)+len(onlyZone) > 0 {
			problems = append(problems, describeDiff("parent", onlyParent, "zone", onlyZone))
		}
	}

	// Nameservers that report a different NS set than the parent
	sets := map[string][]string{}
	for _, s := range d.Nameservers {
		for _, a := range s.Addresses {
			if !a.Authoritative || len(a.NS) == 0 {
				continue
			}
			key := strings.Join(a.NS, " ")
			if key != strings.Join(parent, " ") {
				sets[key] = append(sets[key], s.Name)
			}
		}
	}
	for set, servers := range sets {
		problems = append(problems, fmt.Sprintf("%s report NS %s.", strings.Join(unique(servers), ", "), set))
	}
	sort.Strings(problems)

	if len(problems) > 0 {
		return warn("NS sets differ",
			"The nameservers at the parent and in the zone should be the same. "+strings.Join(problems, " "))
	}
	return pass("Parent and zone agree", "The parent delegation and the zone's NS records list the same nameservers.")
}

// checkGlue verifies glue for nameservers inside the zone, and that glue matches the real addresses
func checkGlue(d *collector.DomainInfo) *Outcome {
	if d.Delegation == nil {
		return nil
	}

	resolved := map[string][]string{}
	for _, s := range d.Nameservers {
		for _, a := range s.Addresses {
			resolved[s.Name] = append(resolved[s.Name], a.IP)
		}
	}

	var missing, mismatch, needed []string
	for _, ns := range d.Delegation.NS {
		glue := d.Delegation.Glue[ns]
		if delegation.InBailiwick(ns, d.Zone) {
			needed = append(needed, ns)
			if len(glue) == 0 {
				missing = append(missing, ns)
				continue
			}
		}
		if len(glue) > 0 && len(resolved[ns]) > 0 {
			if onlyGlue, onlyZone := diff(glue, resolved[ns]); len(onlyGlue)+len(onlyZone) > 0 {
				mismatch = append(mismatch, fmt.Sprintf("%s (glue %s, zone %s)", ns, strings.Join(glue, ", "), strings.Join(resolved[ns], ", ")))
			}
		}
	}

	switch {
	case len(missing) > 0:
		return fail("Glue missing",
			"These nameservers are inside the zone, so the parent must publish their addresses (glue), or they can't be found: "+strings.Join(missing, ", ")+".")
	case len(mismatch) > 0:
		return warn("Glue differs from the zone",
			"The addresses at the parent (glue) differ from the addresses in the zone: "+strings.Join(mismatch, "; ")+". Update the glue at your registrar.")
	case len(needed) > 0:
		return pass("Glue present and correct", "Glue is published for the nameservers inside the zone: "+strings.Join(needed, ", ")+".")
	default:
		return pass("No glue needed", "All nameservers are outside the zone, so no glue records are needed.")
	}
}

// checkNSResolve verifies that every nameserver name resolves and is not a CNAME (RFC 2181 10.3)
func checkNSResolve(d *collector.DomainInfo) *Outcome {
	if len(d.Nameservers) == 0 {
		return nil
	}

	var aliases, unresolved, failed []string
	for _, s := range d.Nameservers {
		switch {
		case s.CNAME != "":
			aliases = append(aliases, fmt.Sprintf("%s -> %s", s.Name, s.CNAME))
		case !s.Resolves && s.Error != "":
			failed = append(failed, fmt.Sprintf("%s (%s)", s.Name, s.Error))
		case !s.Resolves:
			unresolved = append(unresolved, s.Name)
		}
	}

	switch {
	case len(unresolved) > 0:
		return fail("Nameserver names don't resolve",
			"These nameservers have no A or AAAA record, so they can't be reached (lame delegation): "+strings.Join(unresolved, ", ")+".")
	case len(aliases) > 0:
		return fail("Nameserver names are CNAMEs", "Nameserver names must not be aliases (RFC 2181 10.3): "+strings.Join(aliases, ", ")+".")
	case len(failed) > 0:
		return inform("Could not be checked", "Resolving these nameserver names failed: "+strings.Join(failed, "; ")+".")
	default:
		return pass("All names resolve", "Every nameserver name has an address and is not an alias.")
	}
}

// checkNSNetworks verifies that the nameservers are not all in one IPv4 /24 or IPv6 /48 (RFC 2182)
func checkNSNetworks(d *collector.DomainInfo) *Outcome {
	v4, v6 := map[string]bool{}, map[string]bool{}
	count4, count6 := 0, 0
	for _, a := range d.Addresses() {
		ip := net.ParseIP(a.IP)
		if ip == nil {
			continue
		}
		if v := ip.To4(); v != nil {
			count4++
			v4[v.Mask(net.CIDRMask(24, 32)).String()+"/24"] = true
		} else {
			count6++
			v6[ip.Mask(net.CIDRMask(48, 128)).String()+"/48"] = true
		}
	}
	if count4+count6 < 2 {
		return nil // rules 6 and 9 report too few nameservers
	}

	single4 := count4 > 1 && len(v4) == 1
	single6 := count6 > 1 && len(v6) == 1
	var single []string
	if single4 {
		single = append(single, "all IPv4 addresses are in "+keys(v4)[0])
	}
	if single6 {
		single = append(single, "all IPv6 addresses are in "+keys(v6)[0])
	}
	switch {
	case len(single) > 0 && (single4 && len(v6) > 1 || single6 && len(v4) > 1):
		// One address family is spread out; common for anycast providers that number IPv6 from one block
		return inform("One address family in one network",
			strings.Join(single, "; ")+", while the other address family is spread over several networks.")
	case len(single) > 0:
		return warn("Nameservers in one network",
			strings.Join(single, "; ")+". A single network failure takes all nameservers down; RFC 2182 recommends topologically separate networks (anycast setups are an exception).")
	}
	return pass("Nameservers in different networks",
		fmt.Sprintf("The nameservers are spread over %s and %s.", plural(len(v4), "IPv4 /24"), plural(len(v6), "IPv6 /48")))
}

// checkNSASN reports whether the nameservers are spread over more than one autonomous system
func checkNSASN(d *collector.DomainInfo) *Outcome {
	asns := map[string][]string{}
	for _, a := range d.Addresses() {
		if a.ASN != nil {
			first := strings.Fields(a.ASN.ASN)[0]
			asns[first] = append(asns[first], a.IP)
		}
	}
	if len(asns) == 0 {
		return nil
	}

	var names []string
	for asn, ips := range asns {
		name := ""
		for _, a := range d.Addresses() {
			if a.ASN != nil && strings.Fields(a.ASN.ASN)[0] == asn && a.ASN.Name != "" {
				name = " (" + a.ASN.Name + ")"
				break
			}
		}
		names = append(names, fmt.Sprintf("AS%s%s: %s", asn, name, plural(len(ips), "address")))
	}
	sort.Strings(names)

	if len(asns) == 1 {
		return inform("All nameservers in one AS",
			"All nameserver addresses are announced by one network operator ("+names[0]+"). An outage or attack on that network affects all nameservers; large anycast providers mitigate this, but a secondary DNS provider adds independence.")
	}
	return pass(fmt.Sprintf("%d autonomous systems", len(asns)), "The nameservers are spread over: "+strings.Join(names, "; ")+".")
}

// checkNSTLDs reports whether the nameserver names depend on a single TLD
func checkNSTLDs(d *collector.DomainInfo) *Outcome {
	if d.Delegation == nil || len(d.Delegation.NS) < 2 {
		return nil
	}
	tlds := map[string]bool{}
	for _, ns := range d.Delegation.NS {
		labels := strings.Split(ns, ".")
		tlds[labels[len(labels)-1]] = true
	}
	if len(tlds) == 1 {
		return inform("All nameserver names under ."+keys(tlds)[0],
			"All nameserver names are under one TLD, so a problem with that TLD also makes the nameservers unreachable. Some operators use names under two TLDs for extra resilience.")
	}
	return pass(fmt.Sprintf("Nameserver names under %d TLDs", len(tlds)), "Nameserver names use the TLDs ."+strings.Join(keys(tlds), ", .")+".")
}

// checkNSIPv6 verifies that the nameservers can be reached over IPv6
func checkNSIPv6(d *collector.DomainInfo) *Outcome {
	if len(d.Nameservers) == 0 {
		return nil
	}
	var without []string
	for _, s := range d.Nameservers {
		has := false
		for _, a := range s.Addresses {
			if net.ParseIP(a.IP).To4() == nil {
				has = true
			}
		}
		if !has && s.Resolves {
			without = append(without, s.Name)
		}
	}
	switch {
	case len(without) == len(d.Nameservers):
		return warn("No IPv6", "None of the nameservers has an IPv6 address, so IPv6-only resolvers can't reach them.")
	case len(without) > 0:
		return inform("Partly IPv6", "These nameservers have no IPv6 address: "+strings.Join(without, ", ")+".")
	default:
		return pass("All reachable over IPv6", "Every nameserver has an IPv6 address.")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func unique(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
