package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-domain/internal/collector"
	"github.com/sbroekhoven/check-domain/internal/tld"
)

// checkTLDType reports what kind of TLD the domain is under and whether ICANN policies apply
func checkTLDType(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckTLD, "TLD"); o != nil {
		return o
	}
	t := d.TLD
	if t == nil {
		return nil
	}

	kind := map[tld.Type]string{
		tld.Generic:           "generic TLD (gTLD)",
		tld.GenericRestricted: "generic-restricted TLD",
		tld.Sponsored:         "sponsored TLD (sTLD)",
		tld.CountryCode:       "country-code TLD (ccTLD)",
		tld.IDN:               "internationalized TLD",
		tld.Infrastructure:    "infrastructure TLD",
	}[t.Type]

	message := t.Description
	if t.PublicSuffix != "" && t.PublicSuffix != t.TLD {
		message += fmt.Sprintf(" Domains are registered under the public suffix .%s.", t.PublicSuffix)
	}
	return inform(fmt.Sprintf(".%s is a %s", t.TLD, kind), message)
}

// checkTLDRoot verifies that the TLD is delegated in the root zone and DNSSEC-signed there
func checkTLDRoot(d *collector.DomainInfo) *Outcome {
	t := d.TLD
	if t == nil {
		return nil
	}
	switch {
	case !t.InRoot:
		return fail("TLD not in the root zone", fmt.Sprintf(".%s is not delegated in the root zone, so names under it can't be resolved on the public internet.", t.TLD))
	case !t.Signed:
		return warn("TLD not DNSSEC-signed", fmt.Sprintf("The root has no DS record for .%s, so DNSSEC for domains under it can't be validated.", t.TLD))
	default:
		return pass("TLD delegated and signed", fmt.Sprintf(".%s is delegated in the root zone and DNSSEC-signed.", t.TLD))
	}
}

// rdapUnavailable explains why there is no registration data; nil when RDAP was not used
func rdapUnavailable(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckRDAP, "RDAP"); o != nil {
		return o
	}
	if err, ok := d.Errors[collector.CheckRDAP]; ok {
		return inform("Registration data not available", "No registration data via RDAP: "+err+". Many ccTLD registries don't offer RDAP; check the registry's WHOIS instead.")
	}
	return nil
}

// checkExpiry warns when the domain registration expires soon
func checkExpiry(d *collector.DomainInfo) *Outcome {
	r := d.Registration
	if r == nil {
		return rdapUnavailable(d)
	}
	if r.Expires.IsZero() {
		return inform("Expiry date not published", "The registry does not publish the expiry date in RDAP. Check it with your registrar.")
	}

	days := int(r.Expires.Sub(d.QueryTime).Hours() / 24)
	date := r.Expires.UTC().Format("2006-01-02")
	switch {
	case days < 0:
		return fail("Registration expired", fmt.Sprintf("The domain expired on %s. Renew it immediately, before it is released.", date))
	case days < 14:
		return fail(fmt.Sprintf("Expires in %s", plural(days, "day")), fmt.Sprintf("The registration expires on %s. Renew it now or enable auto-renewal.", date))
	case days < 30:
		return warn(fmt.Sprintf("Expires in %d days", days), fmt.Sprintf("The registration expires on %s. Make sure it is renewed.", date))
	default:
		return pass("Expires on "+date, fmt.Sprintf("The registration is valid until %s (%d days).", date, days))
	}
}

// problemStatuses are EPP statuses that mean the domain is (about to be) out of service
var problemStatuses = []string{"server hold", "client hold", "redemption period", "pending delete", "pending restore", "inactive"}

// checkDomainStatus reports registry statuses that take the domain offline, and a missing transfer lock
func checkDomainStatus(d *collector.DomainInfo) *Outcome {
	r := d.Registration
	if r == nil {
		return nil // rule 3 explains why there is no registration data
	}

	var problems []string
	for _, s := range problemStatuses {
		if r.HasStatus(s) {
			problems = append(problems, s)
		}
	}
	if len(problems) > 0 {
		return fail("Domain on hold or being deleted",
			"The registry status is "+strings.Join(problems, ", ")+". The domain is or will soon be removed from DNS; contact your registrar.")
	}

	locked := r.HasStatus("client transfer prohibited") || r.HasStatus("server transfer prohibited")
	for _, s := range r.Status {
		locked = locked || strings.Contains(s, "lock")
	}
	statuses := "none"
	if len(r.Status) > 0 {
		statuses = strings.Join(r.Status, ", ")
	}
	if !locked {
		return inform("No transfer lock", "The domain has no transfer lock (status: "+statuses+"). A registrar lock protects against unauthorized transfers.")
	}
	return pass("Transfer locked", "Registry status: "+statuses+".")
}

// checkRegistryNS compares the nameservers in the registry database with the published delegation
func checkRegistryNS(d *collector.DomainInfo) *Outcome {
	r := d.Registration
	if r == nil || len(r.Nameservers) == 0 || d.Delegation == nil {
		return nil
	}
	onlyRegistry, onlyDNS := diff(r.Nameservers, d.Delegation.NS)
	if len(onlyRegistry)+len(onlyDNS) == 0 {
		return pass("Registry and delegation match", "The nameservers registered at the registry are the ones published in DNS.")
	}
	return warn("Registry and delegation differ", describeDiff("registry", onlyRegistry, "parent zone", onlyDNS)+
		" The registry database and the published delegation should be identical; a pending change may not have been published yet.")
}

// diff returns the names only in a and only in b
func diff(a, b []string) (onlyA, onlyB []string) {
	inA, inB := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		inA[strings.ToLower(x)] = true
	}
	for _, x := range b {
		inB[strings.ToLower(x)] = true
	}
	for _, x := range a {
		if !inB[strings.ToLower(x)] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !inA[strings.ToLower(x)] {
			onlyB = append(onlyB, x)
		}
	}
	return onlyA, onlyB
}

func describeDiff(nameA string, onlyA []string, nameB string, onlyB []string) string {
	var parts []string
	if len(onlyA) > 0 {
		parts = append(parts, fmt.Sprintf("only at the %s: %s", nameA, strings.Join(onlyA, ", ")))
	}
	if len(onlyB) > 0 {
		parts = append(parts, fmt.Sprintf("only in the %s: %s", nameB, strings.Join(onlyB, ", ")))
	}
	s := strings.Join(parts, "; ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}
