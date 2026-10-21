package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sbroekhoven/check-domain/internal/collector"
)

// ttlTypes are the apex record types whose TTL is checked. TXT and CAA often have short TTLs on
// purpose (verification tokens); the SOA TTL only affects negative caching, which rule 23 covers.
var ttlTypes = map[string]bool{"NS": true, "A": true, "AAAA": true, "MX": true}

// TTL limits for apex records
const (
	minTTL = 300    // 5 minutes: lower causes needless query load and slower resolution
	maxTTL = 604800 // 1 week: higher makes changes and emergency moves very slow
)

// checkTTLs reports TTLs that are very low or very high, and differences between parent and child NS TTLs
func checkTTLs(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckRecords, "apex records"); o != nil {
		return o
	}
	r := d.Records
	if r == nil || len(r.Records) == 0 {
		return nil
	}

	var low, high []string
	ttls := map[string]uint32{}
	for _, rec := range r.Records {
		if _, seen := ttls[rec.Type]; !seen && ttlTypes[rec.Type] {
			ttls[rec.Type] = rec.TTL
		}
	}
	types := make([]string, 0, len(ttls))
	for t := range ttls {
		types = append(types, t)
	}
	sort.Strings(types)

	var summary []string
	for _, t := range types {
		ttl := ttls[t]
		summary = append(summary, fmt.Sprintf("%s %s", t, seconds(ttl)))
		switch {
		case ttl < minTTL:
			low = append(low, fmt.Sprintf("%s (%s)", t, seconds(ttl)))
		case ttl > maxTTL:
			high = append(high, fmt.Sprintf("%s (%s)", t, seconds(ttl)))
		}
	}

	var note string
	if d.Delegation != nil {
		if ns, ok := ttls["NS"]; ok && ns != d.Delegation.NSTTL {
			note = fmt.Sprintf(" The NS TTL at the parent is %s and in the zone %s; resolvers may use either.", seconds(d.Delegation.NSTTL), seconds(ns))
		}
	}

	switch {
	case len(low) > 0:
		return warn("Very low TTLs",
			"These records have a TTL below "+seconds(minTTL)+", causing extra queries and slower lookups: "+strings.Join(low, ", ")+". Low TTLs are useful just before a planned change."+note)
	case len(high) > 0:
		return warn("Very high TTLs", "These records have a TTL above "+seconds(maxTTL)+", so changes take very long to reach everyone: "+strings.Join(high, ", ")+"."+note)
	default:
		return pass("TTLs within range", "TTLs: "+strings.Join(summary, ", ")+"."+note)
	}
}

// checkApexCNAME fails when the zone apex is a CNAME, which conflicts with the SOA and NS records
func checkApexCNAME(d *collector.DomainInfo) *Outcome {
	r := d.Records
	if r == nil {
		return nil
	}
	if r.ApexCNAME != "" {
		return fail("CNAME at the apex",
			fmt.Sprintf("The zone apex is a CNAME to %s. A CNAME can't coexist with the SOA and NS records (RFC 1034); use your provider's ALIAS/flattening feature instead.", r.ApexCNAME))
	}
	return pass("No CNAME at the apex", "The zone apex has no CNAME record.")
}

// checkWildcard reports wildcard records, which make every name under the zone resolve
func checkWildcard(d *collector.DomainInfo) *Outcome {
	r := d.Records
	if r == nil {
		return nil
	}
	if r.Wildcard {
		return inform("Wildcard record",
			"A random name under the zone resolves, so there is a wildcard (*) record. Typos and non-existent hosts resolve too, which can confuse mail and certificate checks.")
	}
	return pass("No wildcard", "Names that don't exist return NXDOMAIN.")
}

// knownCAATags are the property tags of RFC 8659 and its extensions
var knownCAATags = map[string]bool{
	"issue": true, "issuewild": true, "iodef": true, "issuemail": true, "issuevmc": true,
	"contactemail": true, "contactphone": true,
}

// checkCAA reports which certificate authorities may issue certificates (RFC 8659)
func checkCAA(d *collector.DomainInfo) *Outcome {
	r := d.Records
	if r == nil {
		return nil
	}
	if len(r.CAA) == 0 {
		return inform("No CAA records",
			"Without CAA records any certificate authority may issue certificates for this domain. A CAA record limits issuance to the CAs you use.")
	}

	var cas, unknown []string
	for _, c := range r.CAA {
		switch {
		case !knownCAATags[c.Tag]:
			entry := c.Tag
			if c.Flag&128 != 0 {
				entry += " (critical)"
			}
			unknown = append(unknown, entry)
		case c.Tag == "issue" || c.Tag == "issuewild":
			ca, _, _ := strings.Cut(c.Value, ";")
			if ca = strings.TrimSpace(ca); ca == "" {
				ca = "none (issuance forbidden)"
			}
			cas = append(cas, ca)
		}
	}
	if len(unknown) > 0 {
		return warn("Unknown CAA tags",
			"These CAA tags are not defined: "+strings.Join(unknown, ", ")+". CAs must refuse to issue when an unknown tag is marked critical.")
	}
	return pass("CAA restricts issuance", "Certificates may be issued by: "+strings.Join(unique(cas), ", ")+".")
}
