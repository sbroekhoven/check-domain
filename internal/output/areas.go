// Package output renders check results as grouped terminal output or as a self-contained HTML report.
package output

import (
	"fmt"
	"net"
	"strings"

	"github.com/sbroekhoven/check-domain/internal/rules"
)

// areaResults returns the results of one area and the worst status among them
func areaResults(results []rules.RuleResult, area rules.Area) ([]rules.RuleResult, rules.Status) {
	var matching []rules.RuleResult
	worst := rules.StatusPass
	for _, r := range results {
		if r.Area == area {
			matching = append(matching, r)
			worst = rules.Worst(worst, r.Status)
		}
	}
	return matching, worst
}

// areaFailure returns the first failed lookup error among the lookups of an area
func areaFailure(e *rules.Report, area rules.Area) (string, bool) {
	for _, check := range area.Checks() {
		if err, failed := e.LookupFailure(check); failed {
			return err, true
		}
	}
	return "", false
}

// displayServer drops the default port from a host:port nameserver address
func displayServer(server string) string {
	if host, port, err := net.SplitHostPort(server); err == nil && port == "53" {
		return host
	}
	return server
}

// areaSummary is the one-line description of what was found for an area
func areaSummary(e *rules.Report, area rules.Area) string {
	lookupError := func(fallback string) string {
		if err, failed := areaFailure(e, area); failed {
			return err
		}
		return fallback
	}

	switch area {
	case rules.AreaRegistration:
		var parts []string
		if e.TLD != nil {
			parts = append(parts, "."+e.TLD.TLD+" "+string(e.TLD.Type))
		}
		if r := e.Registration; r != nil {
			if r.Registrar != "" {
				parts = append(parts, r.Registrar)
			}
			if !r.Expires.IsZero() {
				parts = append(parts, "expires "+r.Expires.UTC().Format("2006-01-02"))
			}
		}
		if len(parts) == 0 {
			return lookupError("Registration data not available")
		}
		return strings.Join(parts, " · ")

	case rules.AreaDelegation:
		if e.Delegation == nil {
			return lookupError("No delegation found")
		}
		return strings.Join(e.Delegation.NS, ", ")

	case rules.AreaNameservers:
		total, ok := 0, 0
		for _, s := range e.Nameservers {
			for _, a := range s.Addresses {
				total++
				if a.Responds && a.Authoritative {
					ok++
				}
			}
		}
		return fmt.Sprintf("%d of %d addresses answer authoritatively", ok, total)

	case rules.AreaSOA:
		if soa := e.SOA(); soa != nil {
			return fmt.Sprintf("serial %d · primary %s", soa.Serial, soa.MName)
		}
		return lookupError("No SOA record")

	case rules.AreaDNSSEC:
		switch s := e.DNSSEC; {
		case s == nil:
			return lookupError("DNSSEC status unknown")
		case s.Bogus:
			return "Validation fails"
		case len(s.DNSKEY) > 0 && len(s.DS) > 0:
			return "Signed, DS published at parent"
		case len(s.DNSKEY) > 0:
			return "Signed, but no DS at parent"
		case len(s.DS) > 0:
			return "DS at parent, but zone is not signed"
		default:
			return "Not signed"
		}

	case rules.AreaRecords:
		if r := e.Records; r != nil {
			return plural(len(r.Records), "record") + " at the apex"
		}
		return lookupError("Apex records not available")
	}
	return ""
}

// plural returns "1 thing" or "n things"
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
