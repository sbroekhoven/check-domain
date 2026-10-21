package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/sbroekhoven/check-domain/internal/collector"
	"github.com/sbroekhoven/check-domain/internal/dnssec"
)

// signatureExpiryWarning is how long before expiry a signature triggers a warning
const signatureExpiryWarning = 7 * 24 * time.Hour

// checkDNSSECEnabled verifies the zone is signed, delegated securely and validates
func checkDNSSECEnabled(d *collector.DomainInfo) *Outcome {
	if o := unchecked(d, collector.CheckDNSSEC, "DNSSEC"); o != nil {
		return o
	}
	s := d.DNSSEC
	if s == nil {
		return nil
	}
	hasDS, hasKeys := len(s.DS) > 0, len(s.DNSKEY) > 0
	switch {
	case s.Bogus:
		return fail("DNSSEC validation fails",
			"Validating resolvers return SERVFAIL for this zone, so the domain is unreachable for a large part of the internet. Check the DS record at the registrar against the zone's keys and the signatures.")
	case hasDS && !hasKeys:
		return fail("DS without signed zone",
			"The parent publishes a DS record but the zone has no DNSKEY records, so validating resolvers will reject it. Remove the DS record or sign the zone.")
	case hasKeys && !hasDS:
		return warn("Signed but not delegated securely",
			"The zone is signed but the parent has no DS record, so the signatures are not used. Publish the DS record at your registrar.")
	case hasKeys && hasDS && s.Validated:
		return pass("Signed and validated", "The zone is signed, the parent publishes a DS record, and the resolver validates the answers.")
	case hasKeys && hasDS:
		return warn("Signed, not validated by the resolver",
			"The zone is signed and has a DS record, but the resolver did not mark the answer as validated. The resolver may not validate, or the TLD is not signed.")
	default:
		return warn("Not signed", "The zone is not signed with DNSSEC, so answers can be spoofed. Enable DNSSEC at your DNS provider and publish the DS record at your registrar.")
	}
}

// checkDNSSECChain verifies that the DS at the parent matches a key in the zone
func checkDNSSECChain(d *collector.DomainInfo) *Outcome {
	s := d.DNSSEC
	if s == nil || len(s.DS) == 0 || len(s.DNSKEY) == 0 {
		return nil
	}
	var matched, unmatched []string
	for _, ds := range s.DS {
		label := fmt.Sprintf("key tag %d (%s)", ds.KeyTag, dnssec.DigestName(ds.DigestType))
		if ds.Matches {
			matched = append(matched, label)
		} else {
			unmatched = append(unmatched, label)
		}
	}
	switch {
	case len(matched) == 0:
		return fail("Broken chain of trust",
			"No DS record at the parent matches a DNSKEY in the zone ("+strings.Join(unmatched, ", ")+"). Validating resolvers will reject the zone; update the DS record at your registrar.")
	case len(unmatched) > 0:
		return inform("Unused DS records",
			"These DS records match no key in the zone: "+strings.Join(unmatched, ", ")+". That is normal during a key rollover; otherwise remove them.")
	default:
		return pass("DS matches a key", "The DS record at the parent matches a key in the zone: "+strings.Join(matched, ", ")+".")
	}
}

// Algorithm and digest assessments after RFC 8624
var (
	forbiddenAlgorithms  = map[uint8]bool{1: true, 3: true, 6: true, 12: true} // RSAMD5, DSA, DSA-NSEC3-SHA1, ECC-GOST
	deprecatedAlgorithms = map[uint8]bool{5: true, 7: true}                    // RSASHA1, RSASHA1-NSEC3-SHA1
)

// checkDNSSECAlgorithms verifies that keys and DS digests use current algorithms
func checkDNSSECAlgorithms(d *collector.DomainInfo) *Outcome {
	s := d.DNSSEC
	if s == nil || len(s.DNSKEY) == 0 {
		return nil
	}
	used := map[string]bool{}
	var forbidden, deprecated []string
	for _, k := range s.DNSKEY {
		name := fmt.Sprintf("%s (%d)", dnssec.AlgorithmName(k.Algorithm), k.Algorithm)
		used[name] = true
		switch {
		case forbiddenAlgorithms[k.Algorithm]:
			forbidden = append(forbidden, name)
		case deprecatedAlgorithms[k.Algorithm]:
			deprecated = append(deprecated, name)
		}
	}

	sha1Only := len(s.DS) > 0
	for _, ds := range s.DS {
		if ds.DigestType != 1 {
			sha1Only = false
		}
	}

	algorithms := strings.Join(keys(used), ", ")
	switch {
	case len(forbidden) > 0:
		return fail("Insecure algorithm", "These algorithms must not be used (RFC 8624): "+strings.Join(unique(forbidden), ", ")+". Roll over to ECDSAP256SHA256 (13).")
	case len(deprecated) > 0:
		return warn("Deprecated algorithm", "SHA-1 based algorithms are deprecated and rejected by some validators: "+strings.Join(unique(deprecated), ", ")+". Roll over to ECDSAP256SHA256 (13).")
	case sha1Only:
		return warn("SHA-1 DS digest only", "The DS records only use SHA-1 digests. Publish a SHA-256 (type 2) DS record at your registrar.")
	default:
		return pass("Modern algorithms", "Key algorithms: "+algorithms+".")
	}
}

// checkDNSSECExpiry verifies that the signatures are not (nearly) expired
func checkDNSSECExpiry(d *collector.DomainInfo) *Outcome {
	s := d.DNSSEC
	if s == nil || len(s.DNSKEY) == 0 || s.SignatureExpiry.IsZero() {
		return nil
	}
	remaining := s.SignatureExpiry.Sub(d.QueryTime)
	date := s.SignatureExpiry.Format("2006-01-02 15:04 MST")

	// Online signers (e.g. Cloudflare) sign every answer with signatures valid for a few days;
	// a short remaining time is normal there as long as the signature is fresh
	validity := s.SignatureExpiry.Sub(s.SignatureInception)
	age := d.QueryTime.Sub(s.SignatureInception)
	online := !s.SignatureInception.IsZero() && validity < signatureExpiryWarning && age < 2*24*time.Hour

	switch {
	case remaining > 0 && online:
		return pass("Short-lived signatures (online signing)",
			fmt.Sprintf("Signatures are valid for %s and created on demand; the current one was made at %s and expires at %s.",
				validity.Round(time.Hour), s.SignatureInception.Format("2006-01-02 15:04 MST"), date))
	case remaining <= 0:
		return fail("Signatures expired", "The DNSSEC signatures expired at "+date+"; validating resolvers reject the zone.")
	case remaining < signatureExpiryWarning:
		return warn("Signatures expire soon", fmt.Sprintf("The earliest signature expires at %s (in %s). Check that automatic re-signing works.", date, remaining.Round(time.Hour)))
	default:
		return pass("Signatures valid until "+s.SignatureExpiry.Format("2006-01-02"), "The earliest DNSKEY/SOA signature expires at "+date+".")
	}
}

// checkDNSSECDenial reports the authenticated denial method and NSEC3 parameters (RFC 9276)
func checkDNSSECDenial(d *collector.DomainInfo) *Outcome {
	s := d.DNSSEC
	if s == nil || len(s.DNSKEY) == 0 || s.Denial == "" {
		return nil
	}
	switch {
	case s.Denial == "NSEC":
		return inform("NSEC", "The zone uses NSEC, so its full contents can be listed by walking the NSEC chain. That is fine unless the names are sensitive.")
	case s.NSEC3 != nil && (s.NSEC3.Iterations > 0 || s.NSEC3.SaltLength > 0):
		return warn("NSEC3 with extra iterations or salt",
			fmt.Sprintf("NSEC3 uses %s and a %d-byte salt. RFC 9276 recommends 0 iterations and no salt: extra iterations cost resolvers CPU and add no real protection, and some validators treat high counts as insecure.", plural(int(s.NSEC3.Iterations), "iteration"), s.NSEC3.SaltLength))
	default:
		return pass("NSEC3 as recommended", "The zone uses NSEC3 with 0 iterations and no salt (RFC 9276).")
	}
}
