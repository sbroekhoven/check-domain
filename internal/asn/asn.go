// Package asn looks up the autonomous system of IP addresses via Team Cymru's DNS service
package asn

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// Info is the origin AS of an address
type Info struct {
	ASN     string `json:"asn"`     // e.g. "15169"; several origins are joined with spaces
	Prefix  string `json:"prefix"`  // announced prefix
	Country string `json:"country"` // registry country code
	Name    string `json:"name"`    // AS name, e.g. "GOOGLE, US"
}

// Lookup returns the AS information for each address. Addresses that could not be looked up are
// left out of the result.
func Lookup(ips []string, res *resolver.Resolver) map[string]Info {
	result := map[string]Info{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, ok := lookup(ip, res)
			if ok {
				mu.Lock()
				result[ip] = info
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return result
}

func lookup(ip string, res *resolver.Resolver) (Info, bool) {
	name, ok := originName(ip)
	if !ok {
		return Info{}, false
	}
	txts, err := res.TXT(name)
	if err != nil || len(txts) == 0 {
		return Info{}, false
	}
	info, ok := ParseOrigin(txts[0])
	if !ok {
		return Info{}, false
	}

	// The AS name is a separate lookup; use the first origin AS
	first := strings.Fields(info.ASN)[0]
	if txts, err := res.TXT("AS" + first + ".asn.cymru.com"); err == nil && len(txts) > 0 {
		info.Name = ParseASName(txts[0])
	}
	return info, true
}

// originName returns the Team Cymru query name for an address:
// 4.3.2.1.origin.asn.cymru.com for 1.2.3.4, nibbles under origin6.asn.cymru.com for IPv6
func originName(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), true
	}
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(arpa, "ip6.arpa.") + "origin6.asn.cymru.com", true
}

// ParseOrigin parses "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
func ParseOrigin(txt string) (Info, bool) {
	fields := strings.Split(txt, "|")
	if len(fields) < 3 {
		return Info{}, false
	}
	asn := strings.TrimSpace(fields[0])
	if asn == "" {
		return Info{}, false
	}
	return Info{
		ASN:     asn,
		Prefix:  strings.TrimSpace(fields[1]),
		Country: strings.TrimSpace(fields[2]),
	}, true
}

// ParseASName parses "15169 | US | arin | 2000-03-30 | GOOGLE, US" and returns the name
func ParseASName(txt string) string {
	fields := strings.Split(txt, "|")
	if len(fields) < 5 {
		return ""
	}
	return strings.TrimSpace(fields[4])
}
