package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sbroekhoven/check-domain/internal/collector"
)

// SOA timer limits, after RFC 1912 2.2 and RFC 2308 5
const (
	minRefresh  = 1200   // 20 minutes
	maxRefresh  = 86400  // 1 day
	minExpire   = 604800 // 1 week
	minNegative = 300    // 5 minutes
	maxNegative = 86400  // 1 day
)

// checkSOASerial verifies that all nameservers serve the same version of the zone
func checkSOASerial(d *collector.DomainInfo) *Outcome {
	serials := map[uint32][]string{}
	for _, a := range responding(d) {
		if a.SOA != nil {
			serials[a.SOA.Serial] = append(serials[a.SOA.Serial], a.String())
		}
	}
	if len(serials) == 0 {
		return nil
	}
	if len(serials) == 1 {
		for serial := range serials {
			return pass(fmt.Sprintf("Serial %d everywhere", serial), "All nameservers serve the same version of the zone.")
		}
	}

	var parts []string
	for serial, servers := range serials {
		parts = append(parts, fmt.Sprintf("%d on %s", serial, strings.Join(servers, ", ")))
	}
	sort.Strings(parts)
	return warn("Serials differ",
		"The nameservers serve different versions of the zone: "+strings.Join(parts, "; ")+". This is normal for a few minutes after a change; if it lasts, zone transfers to the secondaries are failing.")
}

// checkSOATimers verifies that the SOA refresh, retry, expire and negative TTL values are sensible
func checkSOATimers(d *collector.DomainInfo) *Outcome {
	soa := d.SOA()
	if soa == nil {
		return nil
	}

	var problems []string
	if soa.Refresh < minRefresh || soa.Refresh > maxRefresh {
		problems = append(problems, fmt.Sprintf("refresh %s is outside %s–%s", seconds(soa.Refresh), seconds(minRefresh), seconds(maxRefresh)))
	}
	if soa.Retry >= soa.Refresh {
		problems = append(problems, fmt.Sprintf("retry %s should be shorter than refresh %s", seconds(soa.Retry), seconds(soa.Refresh)))
	}
	if soa.Expire < minExpire {
		problems = append(problems, fmt.Sprintf("expire %s is shorter than %s; secondaries stop answering too soon when the primary is down", seconds(soa.Expire), seconds(minExpire)))
	}
	if soa.Expire <= soa.Refresh+soa.Retry {
		problems = append(problems, fmt.Sprintf("expire %s must be longer than refresh + retry", seconds(soa.Expire)))
	}
	if soa.Minimum < minNegative || soa.Minimum > maxNegative {
		problems = append(problems, fmt.Sprintf("negative caching TTL (minimum) %s is outside %s–%s (RFC 2308 recommends 1–3 hours)", seconds(soa.Minimum), seconds(minNegative), seconds(maxNegative)))
	}

	values := fmt.Sprintf("refresh %s, retry %s, expire %s, negative TTL %s", seconds(soa.Refresh), seconds(soa.Retry), seconds(soa.Expire), seconds(soa.Minimum))
	if len(problems) > 0 {
		return warn("Unusual SOA timers", strings.Join(problems, "; ")+". Current values: "+values+".")
	}
	return pass("Timers within recommendations", "SOA "+values+".")
}

// checkSOAMName verifies the primary nameserver in the SOA and detects a hidden master
func checkSOAMName(d *collector.DomainInfo) *Outcome {
	soa := d.SOA()
	if soa == nil {
		return nil
	}
	mname := soa.MName
	if mname == "" || mname == "." {
		return warn("No primary nameserver", "The SOA MNAME field is empty. It should name the primary nameserver.")
	}

	listed := false
	for _, s := range d.Nameservers {
		if s.Name == mname {
			listed = true
		}
	}
	resolves := d.MName != nil && len(d.MName.Addresses) > 0

	switch {
	case listed:
		return pass("Primary is a public nameserver", fmt.Sprintf("The primary nameserver %s is one of the listed nameservers.", mname))
	case resolves:
		return inform("Hidden master",
			fmt.Sprintf("The primary nameserver %s is not listed as a nameserver: a hidden master that only feeds the public secondaries. That is a common setup; make sure it is not reachable for zone transfers from outside.", mname))
	default:
		return inform("Hidden master (not resolvable)",
			fmt.Sprintf("The primary nameserver %s is not listed as a nameserver and does not resolve publicly: a hidden master, or a placeholder name. Some tools (e.g. dynamic updates) use MNAME to find the primary.", mname))
	}
}

// checkSOARName verifies the contact mailbox in the SOA (RFC 1035 3.3.13)
func checkSOARName(d *collector.DomainInfo) *Outcome {
	soa := d.SOA()
	if soa == nil {
		return nil
	}
	email, ok := RNameToEmail(soa.RName)
	switch {
	case strings.Contains(soa.RName, "@"):
		return fail("Invalid contact address", fmt.Sprintf("The SOA RNAME %q contains an @; it must be written with a dot instead (hostmaster.example.com).", soa.RName))
	case !ok:
		return warn("Invalid contact address", fmt.Sprintf("The SOA RNAME %q is not a valid mailbox (expected e.g. hostmaster.example.com).", soa.RName))
	default:
		return pass("Contact "+email, fmt.Sprintf("The SOA RNAME %s means %s.", soa.RName, email))
	}
}

// RNameToEmail converts an SOA RNAME to an email address: the first unescaped dot is the @
func RNameToEmail(rname string) (string, bool) {
	rname = strings.TrimSuffix(rname, ".")
	for i := 0; i < len(rname); i++ {
		switch rname[i] {
		case '\\':
			i++ // skip the escaped character
		case '.':
			local := strings.ReplaceAll(rname[:i], `\.`, ".")
			domain := rname[i+1:]
			if local == "" || !strings.Contains(domain, ".") {
				return "", false
			}
			return local + "@" + domain, true
		}
	}
	return "", false
}

// checkSOASerialFormat checks that a date-based serial does not lie in the future
func checkSOASerialFormat(d *collector.DomainInfo) *Outcome {
	soa := d.SOA()
	if soa == nil {
		return nil
	}
	kind, date := SerialFormat(soa.Serial)
	switch {
	case kind == "date" && date.After(d.QueryTime.Add(24*time.Hour)):
		return warn("Serial date in the future",
			fmt.Sprintf("The serial %d looks like a date (YYYYMMDDnn) in the future (%s). It can only grow, so a wrong date can't be undone without a serial wrap-around.", soa.Serial, date.Format("2006-01-02")))
	case kind == "date":
		return pass("Date-based serial", fmt.Sprintf("The serial %d follows the YYYYMMDDnn convention (%s).", soa.Serial, date.Format("2006-01-02")))
	case kind == "unixtime":
		return pass("Timestamp serial", fmt.Sprintf("The serial %d is a Unix timestamp (%s).", soa.Serial, date.Format("2006-01-02 15:04 MST")))
	default:
		return pass("Counter serial", fmt.Sprintf("The serial %d is a plain counter.", soa.Serial))
	}
}

// SerialFormat recognizes YYYYMMDDnn and Unix timestamp serials
func SerialFormat(serial uint32) (string, time.Time) {
	s := strconv.FormatUint(uint64(serial), 10)
	if len(s) == 10 {
		if t, err := time.Parse("20060102", s[:8]); err == nil && t.Year() >= 1990 && t.Year() <= 2100 {
			return "date", t
		}
	}
	if serial >= 1000000000 { // September 2001
		return "unixtime", time.Unix(int64(serial), 0).UTC()
	}
	return "counter", time.Time{}
}

// seconds formats a duration in seconds with a readable unit
func seconds(s uint32) string {
	d := time.Duration(s) * time.Second
	switch {
	case s%86400 == 0 && s >= 86400:
		return fmt.Sprintf("%dd", s/86400)
	case s%3600 == 0 && s >= 3600:
		return fmt.Sprintf("%dh", s/3600)
	case s%60 == 0 && s >= 60:
		return fmt.Sprintf("%dm", s/60)
	default:
		return d.String()
	}
}
