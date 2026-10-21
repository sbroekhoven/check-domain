// Package records reads the records at the zone apex from an authoritative server, with their
// original TTLs, and checks for an apex CNAME and wildcards
package records

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// Types are the record types read at the apex
var Types = []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeCAA}

// Info holds the apex records of a zone
type Info struct {
	Server    string   `json:"server"` // authoritative address the records were read from
	Records   []Record `json:"records"`
	ApexCNAME string   `json:"apex_cname,omitempty"` // a CNAME at the apex, which is not allowed
	Wildcard  bool     `json:"wildcard"`             // a random name below the apex resolves
	CAA       []CAA    `json:"caa"`
}

// Record is one apex record
type Record struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// CAA is a certification authority authorization record (RFC 8659)
type CAA struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// Lookup reads the apex records of zone from an authoritative server (host:port)
func Lookup(zone, server string, res *resolver.Resolver) (*Info, error) {
	info := &Info{Server: server, Records: []Record{}, CAA: []CAA{}}
	var firstErr error

	for _, qtype := range Types {
		resp, _, err := res.QueryServer(server, zone, qtype, resolver.ServerOptions{})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range resp.Answer {
			if !strings.EqualFold(rr.Header().Name, dns.Fqdn(zone)) {
				continue
			}
			switch r := rr.(type) {
			case *dns.CNAME:
				info.ApexCNAME = strings.TrimSuffix(r.Target, ".")
				continue
			case *dns.CAA:
				info.CAA = append(info.CAA, CAA{Flag: r.Flag, Tag: strings.ToLower(r.Tag), Value: r.Value})
			}
			if rr.Header().Rrtype != qtype {
				continue
			}
			info.Records = append(info.Records, Record{
				Type:  dns.TypeToString[rr.Header().Rrtype],
				Value: value(rr),
				TTL:   rr.Header().Ttl,
			})
		}
	}
	if len(info.Records) == 0 && firstErr != nil {
		return nil, firstErr
	}

	info.Wildcard = hasWildcard(zone, server, res)
	sortRecords(info.Records)
	return info, nil
}

// value returns the record data without the owner, TTL, class and type
func value(rr dns.RR) string {
	full := rr.String()
	header := rr.Header().String()
	return strings.TrimSpace(strings.TrimPrefix(full, header))
}

// hasWildcard asks for a random name below the apex; an answer means a wildcard record
func hasWildcard(zone, server string, res *resolver.Resolver) bool {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	name := "wildcard-test-" + hex.EncodeToString(buf) + "." + zone
	for _, qtype := range []uint16{dns.TypeA, dns.TypeTXT} {
		resp, _, err := res.QueryServer(server, name, qtype, resolver.ServerOptions{})
		if err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return true
		}
	}
	return false
}

func sortRecords(records []Record) {
	order := map[string]int{}
	for i, t := range Types {
		order[dns.TypeToString[t]] = i
	}
	sort.SliceStable(records, func(i, j int) bool {
		return order[records[i].Type] < order[records[j].Type]
	})
}

// ByType returns the records of one type
func (i *Info) ByType(t string) []Record {
	var out []Record
	for _, r := range i.Records {
		if r.Type == t {
			out = append(out, r)
		}
	}
	return out
}
