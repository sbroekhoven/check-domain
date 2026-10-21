package rules

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/sbroekhoven/check-domain/internal/collector"
	"github.com/sbroekhoven/check-domain/internal/nameservers"
)

// serverAddress is a probed address together with its nameserver name
type serverAddress struct {
	host string
	nameservers.Address
}

func (s serverAddress) String() string {
	return fmt.Sprintf("%s (%s)", s.host, s.IP)
}

// addresses returns all probed addresses with their nameserver names
func addresses(d *collector.DomainInfo) []serverAddress {
	var all []serverAddress
	for _, s := range d.Nameservers {
		for _, a := range s.Addresses {
			all = append(all, serverAddress{s.Name, a})
		}
	}
	return all
}

// responding returns the addresses that answered
func responding(d *collector.DomainInfo) []serverAddress {
	var out []serverAddress
	for _, a := range addresses(d) {
		if a.Responds {
			out = append(out, a)
		}
	}
	return out
}

func list(addrs []serverAddress) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// checkNSRespond verifies that every nameserver address answers
func checkNSRespond(d *collector.DomainInfo) *Outcome {
	all := addresses(d)
	if len(all) == 0 {
		return nil
	}
	var silent []string
	for _, a := range all {
		if !a.Responds {
			silent = append(silent, fmt.Sprintf("%s: %s", a, a.Error))
		}
	}
	switch {
	case len(silent) == len(all):
		return fail("No nameserver responds", "None of the nameserver addresses answered: "+strings.Join(silent, "; ")+".")
	case len(silent) > 0:
		return fail("Nameservers not responding",
			"These addresses did not answer, so resolvers waste time on timeouts: "+strings.Join(silent, "; ")+".")
	default:
		return pass("All respond", fmt.Sprintf("All %s answered.", plural(len(all), "nameserver address")))
	}
}

// checkNSAuthoritative verifies every answering server is authoritative for the zone (no lame delegation)
func checkNSAuthoritative(d *collector.DomainInfo) *Outcome {
	resp := responding(d)
	if len(resp) == 0 {
		return nil
	}
	var lame []string
	for _, a := range resp {
		if !a.Authoritative || a.Rcode != "NOERROR" || a.SOA == nil {
			lame = append(lame, fmt.Sprintf("%s: %s, authoritative=%v", a, a.Rcode, a.Authoritative))
		}
	}
	if len(lame) > 0 {
		return fail("Lame delegation",
			"These nameservers don't answer authoritatively for the zone, so resolvers ignore them: "+strings.Join(lame, "; ")+".")
	}
	return pass("All authoritative", "Every responding nameserver answers authoritatively for the zone.")
}

// checkNSRecursion verifies that the nameservers don't act as open resolvers
func checkNSRecursion(d *collector.DomainInfo) *Outcome {
	resp := responding(d)
	if len(resp) == 0 {
		return nil
	}
	var open []serverAddress
	for _, a := range resp {
		if a.Recursive {
			open = append(open, a)
		}
	}
	if len(open) > 0 {
		return fail("Open recursion",
			"These nameservers resolve names for anyone, which makes them usable for DNS amplification attacks and cache poisoning: "+list(open)+". Disable recursion on authoritative servers.")
	}
	return pass("No recursion", "The nameservers do not answer recursive queries for other domains.")
}

// versionNumber matches a dotted version such as "9.18.24" or "Knot DNS 3.6.2"
var versionNumber = regexp.MustCompile(`\d+\.\d+`)

// checkNSVersion warns when nameservers disclose their software version
func checkNSVersion(d *collector.DomainInfo) *Outcome {
	resp := responding(d)
	if len(resp) == 0 {
		return nil
	}
	// One entry per nameserver and version string, not per address
	var versions, names []string
	seen := map[string]bool{}
	for _, a := range resp {
		key := a.host + "\x00" + a.Version
		if a.Version == "" || seen[key] {
			continue
		}
		seen[key] = true
		entry := fmt.Sprintf("%s: %q", a.host, a.Version)
		if versionNumber.MatchString(a.Version) {
			versions = append(versions, entry)
		} else {
			names = append(names, entry)
		}
	}
	switch {
	case len(versions) > 0:
		return warn("Software version disclosed",
			"These nameservers report their software version via version.bind/version.server, which helps attackers find known vulnerabilities: "+strings.Join(versions, "; ")+". Hide or replace the version string.")
	case len(names) > 0:
		return inform("Identifying string disclosed", "These nameservers answer version queries with a string that is not a version number: "+strings.Join(names, "; ")+".")
	default:
		return pass("No version disclosed", "The nameservers don't reveal their software version.")
	}
}

// checkNSAXFR fails when a nameserver hands out the complete zone to anyone
func checkNSAXFR(d *collector.DomainInfo) *Outcome {
	tested := false
	var open []string
	for _, a := range responding(d) {
		tested = tested || a.AXFRTested
		if a.AXFR {
			open = append(open, fmt.Sprintf("%s: %s", a, plural(a.AXFRRecords, "record")))
		}
	}
	if !tested {
		return nil
	}
	if len(open) > 0 {
		return fail("Zone transfer allowed",
			"These nameservers send the complete zone to anyone who asks (AXFR), exposing all host names: "+strings.Join(open, "; ")+". Restrict zone transfers to your secondary servers.")
	}
	return pass("Zone transfers refused", "No nameserver allows a zone transfer to the public.")
}

// checkNSTCP verifies DNS over TCP, which is required for large answers (RFC 7766)
func checkNSTCP(d *collector.DomainInfo) *Outcome {
	resp := responding(d)
	if len(resp) == 0 {
		return nil
	}
	var noTCP []string
	for _, a := range resp {
		if !a.TCP {
			noTCP = append(noTCP, fmt.Sprintf("%s: %s", a, a.TCPError))
		}
	}
	if len(noTCP) > 0 {
		return fail("No DNS over TCP",
			"DNS over TCP is required (RFC 7766); without it, large answers such as DNSSEC responses fail. Not answering over TCP: "+strings.Join(noTCP, "; ")+".")
	}
	return pass("TCP supported", "All nameservers answer over TCP.")
}

// checkNSEDNS verifies EDNS(0) support, needed for DNSSEC and larger UDP answers
func checkNSEDNS(d *collector.DomainInfo) *Outcome {
	resp := responding(d)
	if len(resp) == 0 {
		return nil
	}
	var noEDNS []serverAddress
	for _, a := range resp {
		if !a.EDNS {
			noEDNS = append(noEDNS, a)
		}
	}
	if len(noEDNS) > 0 {
		return warn("No EDNS", "These nameservers don't support EDNS(0), needed for DNSSEC and answers larger than 512 bytes: "+list(noEDNS)+".")
	}
	return pass("EDNS supported", "All nameservers support EDNS(0).")
}

// checkNSPublic fails when nameserver addresses are private, loopback or otherwise not routable
func checkNSPublic(d *collector.DomainInfo) *Outcome {
	all := addresses(d)
	if len(all) == 0 {
		return nil
	}
	var private []serverAddress
	for _, a := range all {
		ip := net.ParseIP(a.IP)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
			private = append(private, a)
		}
	}
	if len(private) > 0 {
		return fail("Private nameserver addresses", "These nameserver addresses can't be reached from the internet: "+list(private)+".")
	}
	return pass("Public addresses", "All nameserver addresses are publicly routable.")
}
