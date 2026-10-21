package output

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sbroekhoven/check-domain/internal/dnssec"
	"github.com/sbroekhoven/check-domain/internal/rules"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

var reportTemplate = template.Must(template.New("report.html.tmpl").
	Funcs(template.FuncMap{"icon": statusIcon}).
	ParseFS(templateFS, "templates/report.html.tmpl"))

// reportData is the view model of the HTML report
type reportData struct {
	Domain     string
	Zone       string // shown when it differs from the domain that was asked for
	Checked    string
	Nameserver string
	Version    string
	Worst      rules.Status
	Verdict    string
	Counts     []countChip
	Areas      []reportArea
}

type countChip struct {
	Status rules.Status
	Label  string
}

// reportArea is one card of the report
type reportArea struct {
	Area    rules.Area
	ID      string
	Worst   rules.Status
	Summary string
	Facts   []fact
	Tables  []dataTable
	Error   string
	Results []rules.RuleResult
}

// fact is one label/value pair under "Found"
type fact struct {
	Label string
	Value string
	Mono  bool
}

type dataTable struct {
	Title string
	Wide  bool // many short columns: keep words whole and scroll horizontally on small screens
	Head  []string
	Rows  [][]string
}

// WriteHTML renders the results as a self-contained HTML page. version is shown in the footer.
func WriteHTML(w io.Writer, e *rules.Report, nameserver, version string) error {
	return reportTemplate.Execute(w, buildReport(e, nameserver, version))
}

func buildReport(e *rules.Report, nameserver, version string) reportData {
	data := reportData{
		Domain:     e.Domain,
		Checked:    e.QueryTime.Format("2 January 2006, 15:04 MST"),
		Nameserver: displayServer(nameserver),
		Version:    version,
	}
	if e.Zone != "" && e.Zone != e.Domain {
		data.Zone = e.Zone
	}

	data.Worst = e.Worst()
	counts := map[rules.Status]int{}
	for _, r := range e.RuleResults {
		counts[r.Status]++
	}
	data.Counts = []countChip{
		{rules.StatusPass, fmt.Sprintf("%d passed", counts[rules.StatusPass])},
		{rules.StatusWarn, plural(counts[rules.StatusWarn], "warning")},
		{rules.StatusFail, fmt.Sprintf("%d failed", counts[rules.StatusFail])},
	}
	if n := counts[rules.StatusInfo]; n > 0 {
		data.Counts = append(data.Counts, countChip{rules.StatusInfo, fmt.Sprintf("%d info", n)})
	}

	switch data.Worst {
	case rules.StatusFail:
		data.Verdict = "Problems found"
	case rules.StatusWarn:
		data.Verdict = "Passed with warnings"
	default:
		data.Verdict = "All checks passed"
	}

	for _, area := range rules.Areas {
		results, worst := areaResults(e.RuleResults, area)
		if len(results) == 0 {
			continue // no check applies, e.g. DNSSEC details for an unsigned zone
		}
		ra := reportArea{
			Area:    area,
			ID:      strings.ToLower(string(area)),
			Worst:   worst,
			Summary: areaSummary(e, area),
			Results: results,
		}
		addFound(&ra, e)

		// Show failed lookups as a note, unless the summary already shows the error
		if err, failed := areaFailure(e, area); failed && err != ra.Summary {
			ra.Error = err
		}
		data.Areas = append(data.Areas, ra)
	}

	return data
}

// addFound fills in the "Found" section of an area with the collected data
func addFound(ra *reportArea, e *rules.Report) {
	add := func(label, value string, mono bool) {
		if value != "" {
			ra.Facts = append(ra.Facts, fact{label, value, mono})
		}
	}
	date := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2 January 2006")
	}

	switch ra.Area {
	case rules.AreaRegistration:
		if t := e.TLD; t != nil {
			add("TLD", "."+t.TLD+" ("+string(t.Type)+")", false)
			if t.PublicSuffix != "" && t.PublicSuffix != t.TLD {
				add("Public suffix", "."+t.PublicSuffix, true)
			}
			add("ICANN policies apply", t.ICANNPolicy, false)
		}
		if r := e.Registration; r != nil {
			add("Registrar", r.Registrar, false)
			add("Registered", date(r.Created), false)
			add("Last changed", date(r.Updated), false)
			add("Expires", date(r.Expires), false)
			add("Status", strings.Join(r.Status, ", "), false)
			add("Registry nameservers", strings.Join(r.Nameservers, ", "), true)
			add("RDAP server", r.Server, true)
		}

	case rules.AreaDelegation:
		if dl := e.Delegation; dl != nil {
			add("Parent zone", dl.Parent, true)
			add("Delegation from", dl.AnsweredBy, true)
			add("NS at the parent", strings.Join(dl.NS, ", "), true)
		}
		add("NS in the zone", strings.Join(e.ZoneNS, ", "), true)
		if len(e.Nameservers) > 0 {
			t := dataTable{Wide: true, Head: []string{"Nameserver", "Addresses", "Network (AS)", "Glue"}}
			for _, s := range e.Nameservers {
				var ips, nets []string
				for _, a := range s.Addresses {
					ips = append(ips, a.IP)
					if a.ASN != nil {
						nets = append(nets, "AS"+strings.Fields(a.ASN.ASN)[0]+" "+a.ASN.Name)
					} else {
						nets = append(nets, "-")
					}
				}
				if len(ips) == 0 {
					ips = []string{"(does not resolve)"}
				}
				glue := "-"
				if e.Delegation != nil && len(e.Delegation.Glue[s.Name]) > 0 {
					glue = strings.Join(e.Delegation.Glue[s.Name], "\n")
				}
				name := s.Name
				switch {
				case s.InParent && !s.InZone:
					name += " (parent only)"
				case !s.InParent && s.InZone:
					name += " (zone only)"
				}
				t.Rows = append(t.Rows, []string{name, strings.Join(ips, "\n"), strings.Join(nets, "\n"), glue})
			}
			ra.Tables = append(ra.Tables, t)
		}

	case rules.AreaNameservers:
		t := dataTable{Wide: true, Head: []string{"Nameserver", "Answer", "Recursion", "TCP / EDNS", "AXFR", "Version"}}
		for _, s := range e.Nameservers {
			for _, a := range s.Addresses {
				answer := "no response"
				if a.Responds {
					answer = fmt.Sprintf("%s, %d ms", a.Rcode, a.RTTMillis)
					if a.Authoritative {
						answer += ", authoritative"
					} else {
						answer += ", NOT authoritative"
					}
				}
				axfr := "-"
				if a.AXFRTested {
					axfr = "refused"
					if a.AXFR {
						axfr = fmt.Sprintf("ALLOWED (%d records)", a.AXFRRecords)
					}
				}
				version := a.Version
				if version == "" {
					version = "-"
				}
				t.Rows = append(t.Rows, []string{
					s.Name + "\n" + a.IP, answer, yesNo(a.Recursive, "OPEN", "no"),
					yesNo(a.TCP, "yes", "no") + " / " + yesNo(a.EDNS, "yes", "no"), axfr, version,
				})
			}
		}
		if len(t.Rows) > 0 {
			ra.Tables = append(ra.Tables, t)
		}

	case rules.AreaSOA:
		if soa := e.SOA(); soa != nil {
			add("Primary (MNAME)", soa.MName, true)
			add("Contact (RNAME)", soa.RName, true)
			add("Serial", strconv.FormatUint(uint64(soa.Serial), 10), true)
			add("Refresh / retry", fmt.Sprintf("%d s / %d s", soa.Refresh, soa.Retry), false)
			add("Expire", fmt.Sprintf("%d s", soa.Expire), false)
			add("Negative TTL", fmt.Sprintf("%d s", soa.Minimum), false)
		}
		serials := dataTable{Title: "Serial per nameserver", Head: []string{"Nameserver", "Serial"}}
		for _, s := range e.Nameservers {
			for _, a := range s.Addresses {
				if a.SOA != nil {
					serials.Rows = append(serials.Rows, []string{s.Name + " (" + a.IP + ")", strconv.FormatUint(uint64(a.SOA.Serial), 10)})
				}
			}
		}
		if len(serials.Rows) > 1 {
			ra.Tables = append(ra.Tables, serials)
		}

	case rules.AreaDNSSEC:
		s := e.DNSSEC
		if s == nil {
			return
		}
		add("Validated by resolver", yesNo(s.Validated, "yes", "no"), false)
		add("Denial of existence", s.Denial, false)
		if s.NSEC3 != nil {
			add("NSEC3", fmt.Sprintf("%d iterations, %d-byte salt", s.NSEC3.Iterations, s.NSEC3.SaltLength), false)
		}
		add("Signatures valid until", date(s.SignatureExpiry), false)
		if len(s.DS) > 0 {
			t := dataTable{Title: "DS at the parent", Head: []string{"Key tag", "Algorithm", "Digest", "Matches a key"}}
			for _, ds := range s.DS {
				t.Rows = append(t.Rows, []string{
					strconv.Itoa(int(ds.KeyTag)), algorithm(ds.Algorithm),
					dnssec.DigestName(ds.DigestType) + " " + shorten(ds.Digest, 16), yesNo(ds.Matches, "yes", "NO"),
				})
			}
			ra.Tables = append(ra.Tables, t)
		}
		if len(s.DNSKEY) > 0 {
			t := dataTable{Title: "DNSKEY in the zone", Head: []string{"Key tag", "Role", "Algorithm"}}
			for _, k := range s.DNSKEY {
				t.Rows = append(t.Rows, []string{strconv.Itoa(int(k.KeyTag)), yesNo(k.KSK, "KSK (257)", "ZSK (256)"), algorithm(k.Algorithm)})
			}
			ra.Tables = append(ra.Tables, t)
		}

	case rules.AreaRecords:
		r := e.Records
		if r == nil {
			return
		}
		add("Read from", r.Server, true)
		t := dataTable{Head: []string{"Type", "Value", "TTL"}}
		for _, rec := range r.Records {
			t.Rows = append(t.Rows, []string{rec.Type, rec.Value, strconv.FormatUint(uint64(rec.TTL), 10)})
		}
		if len(t.Rows) > 0 {
			ra.Tables = append(ra.Tables, t)
		}
	}
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func algorithm(alg uint8) string {
	return fmt.Sprintf("%s (%d)", dnssec.AlgorithmName(alg), alg)
}

// shorten cuts long hex data for display
func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// statusIcon returns the symbol shown in a status badge
func statusIcon(status rules.Status) string {
	switch status {
	case rules.StatusPass:
		return "✓"
	case rules.StatusWarn:
		return "!"
	case rules.StatusFail:
		return "✗"
	default:
		return "i"
	}
}
