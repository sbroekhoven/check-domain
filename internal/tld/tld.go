// Package tld classifies a top-level domain and checks its delegation in the root zone
package tld

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// Type is the IANA category of a TLD
type Type string

const (
	Generic           Type = "generic"            // gTLD: .com, .net, .org, .info and the new gTLDs
	GenericRestricted Type = "generic-restricted" // .biz, .name, .pro
	Sponsored         Type = "sponsored"          // sTLD with a sponsoring community: .edu, .gov, .museum, ...
	CountryCode       Type = "country-code"       // ccTLD: two letters, ISO 3166-1
	IDN               Type = "idn"                // internationalized TLD (xn--); ccTLD or gTLD cannot be told offline
	Infrastructure    Type = "infrastructure"     // .arpa
)

var sponsored = map[string]bool{
	"aero": true, "asia": true, "cat": true, "coop": true, "edu": true, "gov": true, "int": true,
	"jobs": true, "mil": true, "mobi": true, "museum": true, "post": true, "tel": true, "travel": true, "xxx": true,
}

var restricted = map[string]bool{"biz": true, "name": true, "pro": true}

// Info describes a TLD
type Info struct {
	TLD          string `json:"tld"`
	Type         Type   `json:"type"`
	ICANNPolicy  string `json:"icann_policy"`  // "yes", "no", "partly" or "unknown": do ICANN contracts and policies apply
	Description  string `json:"description"`   // human readable explanation
	InRoot       bool   `json:"in_root"`       // the TLD is delegated in the root zone
	Signed       bool   `json:"signed"`        // the root has a DS record for the TLD
	PublicSuffix string `json:"public_suffix"` // the suffix under which the domain is registered, e.g. "co.uk"
}

// Classify returns the type of a TLD and whether ICANN policies apply, without network access
func Classify(tld string) Info {
	tld = strings.ToLower(strings.Trim(tld, "."))
	info := Info{TLD: tld}
	switch {
	case tld == "arpa":
		info.Type, info.ICANNPolicy = Infrastructure, "no"
		info.Description = "Infrastructure TLD, managed by IANA for the IETF; not open for registrations."
	case sponsored[tld]:
		info.Type, info.ICANNPolicy = Sponsored, "partly"
		info.Description = "Sponsored TLD: operated under an ICANN agreement for a specific community, with its own registration rules."
	case restricted[tld]:
		info.Type, info.ICANNPolicy = GenericRestricted, "yes"
		info.Description = "Generic-restricted TLD under an ICANN registry agreement: ICANN-accredited registrars, UDRP and RDAP apply."
	case strings.HasPrefix(tld, "xn--"):
		info.Type, info.ICANNPolicy = IDN, "unknown"
		info.Description = "Internationalized TLD. It is either an IDN ccTLD (not under ICANN contract) or an IDN gTLD (under ICANN contract)."
	case len(tld) == 2:
		info.Type, info.ICANNPolicy = CountryCode, "no"
		info.Description = "Country-code TLD: governed by its local registry under national policy, not by an ICANN contract. Registrar accreditation, dispute resolution and RDAP/WHOIS rules are set by the registry."
	default:
		info.Type, info.ICANNPolicy = Generic, "yes"
		info.Description = "Generic TLD under an ICANN registry agreement: ICANN-accredited registrars, UDRP and RDAP apply."
	}
	return info
}

// Lookup classifies the TLD of zone and checks that it is delegated and signed in the root
func Lookup(zone, publicSuffix string, res *resolver.Resolver) (*Info, error) {
	labels := dns.SplitDomainName(zone)
	if len(labels) == 0 {
		return nil, &resolver.NotFoundError{What: "TLD", Name: zone}
	}
	info := Classify(labels[len(labels)-1])
	info.PublicSuffix = publicSuffix

	r, err := res.Query(info.TLD, dns.TypeNS, false)
	if err != nil && !resolver.IsNotFound(err) {
		return &info, err
	}
	if r != nil {
		for _, rr := range r.Answer {
			if _, ok := rr.(*dns.NS); ok {
				info.InRoot = true
			}
		}
	}

	r, err = res.Query(info.TLD, dns.TypeDS, true)
	if err != nil && !resolver.IsNotFound(err) {
		return &info, err
	}
	if r != nil {
		for _, rr := range r.Answer {
			if _, ok := rr.(*dns.DS); ok {
				info.Signed = true
			}
		}
	}
	return &info, nil
}
