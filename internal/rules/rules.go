package rules

import (
	"fmt"
	"strings"

	"github.com/sbroekhoven/check-domain/internal/collector"
)

// Status is the outcome of a rule check
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

// Severity orders statuses from harmless (0) to worst
func (s Status) Severity() int {
	switch s {
	case StatusPass:
		return 0
	case StatusInfo:
		return 1
	case StatusWarn:
		return 2
	default:
		return 3
	}
}

// Worst returns the more severe of two statuses
func Worst(a, b Status) Status {
	if b.Severity() > a.Severity() {
		return b
	}
	return a
}

// Area is the part of the domain setup a rule checks
type Area string

const (
	AreaRegistration Area = "Registration"
	AreaDelegation   Area = "Delegation"
	AreaNameservers  Area = "Nameservers"
	AreaSOA          Area = "SOA"
	AreaDNSSEC       Area = "DNSSEC"
	AreaRecords      Area = "Records"
)

// Areas lists all areas in display order
var Areas = []Area{AreaRegistration, AreaDelegation, AreaNameservers, AreaSOA, AreaDNSSEC, AreaRecords}

// Checks returns the collector lookups that provide the data for this area
func (a Area) Checks() []collector.Check {
	switch a {
	case AreaRegistration:
		return []collector.Check{collector.CheckTLD, collector.CheckRDAP}
	case AreaDelegation:
		return []collector.Check{collector.CheckZone, collector.CheckDelegation, collector.CheckZoneNS}
	case AreaNameservers, AreaSOA:
		return []collector.Check{collector.CheckNameservers}
	case AreaDNSSEC:
		return []collector.Check{collector.CheckDNSSEC}
	case AreaRecords:
		return []collector.Check{collector.CheckRecords}
	}
	return nil
}

// Rule is a single check on the collected DNS data
type Rule struct {
	ID    int                                    // stable, public identifier
	Area  Area                                   // part of the mail setup it checks
	Name  string                                 // what it checks, e.g. "SPF DNS lookup limit"
	Check func(d *collector.DomainInfo) *Outcome // nil when the rule does not apply
}

// Outcome is what a rule found
type Outcome struct {
	Status      Status
	Description string // short outcome, e.g. "Ends with ~all"
	Message     string // explanation and advice
}

func pass(description, message string) *Outcome {
	return &Outcome{StatusPass, description, message}
}

func warn(description, message string) *Outcome {
	return &Outcome{StatusWarn, description, message}
}

func fail(description, message string) *Outcome {
	return &Outcome{StatusFail, description, message}
}

func inform(description, message string) *Outcome {
	return &Outcome{StatusInfo, description, message}
}

// unchecked returns an info outcome when the lookup for check failed, so a rule can't tell
// whether the record is missing; nil otherwise. what names the lookup in the message, e.g. "SPF".
func unchecked(d *collector.DomainInfo, check collector.Check, what string) *Outcome {
	err, failed := d.LookupFailure(check)
	if !failed {
		return nil
	}
	return inform("Could not be checked", fmt.Sprintf("The %s lookup failed, so this could not be checked: %s", what, err))
}

// registry holds all rules, ordered by ID. IDs are public (JSON, README) and must never be reused.
var registry = []Rule{
	{1, AreaRegistration, "TLD type and ICANN policies", checkTLDType},
	{2, AreaRegistration, "TLD delegated and signed in the root", checkTLDRoot},
	{3, AreaRegistration, "Domain expiry", checkExpiry},
	{4, AreaRegistration, "Domain status", checkDomainStatus},
	{5, AreaRegistration, "Registry nameservers match the delegation", checkRegistryNS},
	{6, AreaDelegation, "Number of nameservers", checkNSCount},
	{7, AreaDelegation, "Parent and zone NS sets match", checkNSMatch},
	{8, AreaDelegation, "Glue records", checkGlue},
	{9, AreaDelegation, "Nameserver names resolve", checkNSResolve},
	{10, AreaDelegation, "Nameservers in different networks", checkNSNetworks},
	{11, AreaDelegation, "Nameservers in different autonomous systems", checkNSASN},
	{12, AreaDelegation, "Nameserver names under more than one TLD", checkNSTLDs},
	{13, AreaDelegation, "Nameservers reachable over IPv6", checkNSIPv6},
	{14, AreaNameservers, "All nameservers respond", checkNSRespond},
	{15, AreaNameservers, "Authoritative answers", checkNSAuthoritative},
	{16, AreaNameservers, "No open recursion", checkNSRecursion},
	{17, AreaNameservers, "No software version disclosed", checkNSVersion},
	{18, AreaNameservers, "No public zone transfer (AXFR)", checkNSAXFR},
	{19, AreaNameservers, "TCP supported", checkNSTCP},
	{20, AreaNameservers, "EDNS supported", checkNSEDNS},
	{21, AreaNameservers, "Public nameserver addresses", checkNSPublic},
	{22, AreaSOA, "Serial identical on all nameservers", checkSOASerial},
	{23, AreaSOA, "SOA timers", checkSOATimers},
	{24, AreaSOA, "Primary nameserver (MNAME)", checkSOAMName},
	{25, AreaSOA, "Contact address (RNAME)", checkSOARName},
	{26, AreaSOA, "Serial format", checkSOASerialFormat},
	{27, AreaDNSSEC, "DNSSEC signed and validated", checkDNSSECEnabled},
	{28, AreaDNSSEC, "DS matches a DNSKEY", checkDNSSECChain},
	{29, AreaDNSSEC, "DNSSEC algorithms", checkDNSSECAlgorithms},
	{30, AreaDNSSEC, "DNSSEC signature expiry", checkDNSSECExpiry},
	{31, AreaDNSSEC, "Authenticated denial (NSEC/NSEC3)", checkDNSSECDenial},
	{32, AreaRecords, "TTLs", checkTTLs},
	{33, AreaRecords, "No CNAME at the apex", checkApexCNAME},
	{34, AreaRecords, "Wildcard records", checkWildcard},
	{35, AreaRecords, "CAA records", checkCAA},
}

// Rules returns all rules, ordered by ID
func Rules() []Rule {
	return append([]Rule(nil), registry...)
}

// RuleResult represents the outcome of a rule check
type RuleResult struct {
	RuleID      int    `json:"rule_id"`
	Area        Area   `json:"area"`
	Description string `json:"description"`
	Status      Status `json:"status"`
	Message     string `json:"message"`
}

// Report is the collected DNS data together with the rule results
type Report struct {
	*collector.DomainInfo
	RuleResults []RuleResult `json:"rule_results,omitempty"`
}

// Evaluate runs all rules against the collected data; results are ordered by rule ID
func Evaluate(d *collector.DomainInfo) *Report {
	report := &Report{DomainInfo: d, RuleResults: []RuleResult{}}
	for _, rule := range registry {
		if o := rule.Check(d); o != nil {
			report.RuleResults = append(report.RuleResults, RuleResult{
				RuleID:      rule.ID,
				Area:        rule.Area,
				Description: o.Description,
				Status:      o.Status,
				Message:     o.Message,
			})
		}
	}
	return report
}

// HasStatus reports whether any rule ended with the given status
func (r *Report) HasStatus(status Status) bool {
	for _, res := range r.RuleResults {
		if res.Status == status {
			return true
		}
	}
	return false
}

// Worst returns the most severe status of all results
func (r *Report) Worst() Status {
	worst := StatusPass
	for _, res := range r.RuleResults {
		worst = Worst(worst, res.Status)
	}
	return worst
}

// plural returns "1 thing" or "n things" ("addresses" for words ending in s, x, ch or sh)
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	for _, suffix := range []string{"s", "x", "ch", "sh"} {
		if strings.HasSuffix(word, suffix) {
			return fmt.Sprintf("%d %ses", n, word)
		}
	}
	return fmt.Sprintf("%d %ss", n, word)
}
