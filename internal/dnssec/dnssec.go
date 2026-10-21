// Package dnssec inspects the DNSSEC setup of a zone: DS at the parent, DNSKEYs, signatures,
// authenticated denial (NSEC/NSEC3) and validation by the resolver
package dnssec

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// Info is the DNSSEC state of a zone
type Info struct {
	DS                 []DS        `json:"ds"`
	DNSKEY             []Key       `json:"dnskey"`
	Validated          bool        `json:"validated"`           // the resolver set the AD bit on the SOA answer
	Bogus              bool        `json:"bogus"`               // the validating resolver returned SERVFAIL
	SignatureExpiry    time.Time   `json:"signature_expiry"`    // earliest expiration of the DNSKEY and SOA signatures
	SignatureInception time.Time   `json:"signature_inception"` // inception of that same signature
	Denial             string      `json:"denial"`              // "NSEC", "NSEC3" or "" (unsigned or unknown)
	NSEC3              *NSEC3Param `json:"nsec3,omitempty"`
	Server             string      `json:"server"` // authoritative address the zone data was read from
}

// DS is a delegation signer record at the parent
type DS struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"` // 1 = SHA-1, 2 = SHA-256, 4 = SHA-384
	Digest     string `json:"digest"`
	Matches    bool   `json:"matches"` // a DNSKEY in the zone produces this digest
}

// Key is a DNSKEY record
type Key struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	KSK       bool   `json:"ksk"` // SEP flag set (257)
}

// NSEC3Param are the NSEC3 hashing parameters (RFC 5155, RFC 9276)
type NSEC3Param struct {
	Iterations uint16 `json:"iterations"`
	SaltLength int    `json:"salt_length"`
}

// Signed reports whether the zone publishes DNSKEYs
func (i *Info) Signed() bool {
	return len(i.DNSKEY) > 0
}

// AlgorithmName returns the mnemonic of a DNSSEC algorithm number
func AlgorithmName(alg uint8) string {
	if name, ok := dns.AlgorithmToString[alg]; ok {
		return name
	}
	return "unknown"
}

// DigestName returns the name of a DS digest type
func DigestName(t uint8) string {
	if name, ok := dns.HashToString[t]; ok {
		return name
	}
	return "unknown"
}

// Lookup reads the zone's DNSSEC data from an authoritative server (server is host:port) and
// checks validation through the recursive resolver
func Lookup(zone, server string, res *resolver.Resolver) (*Info, error) {
	info := &Info{DS: []DS{}, DNSKEY: []Key{}, Server: server}

	// DS records come from the parent, through the resolver
	r, err := res.Query(zone, dns.TypeDS, true)
	if err != nil && !resolver.IsNotFound(err) {
		if !isServfail(err) {
			return nil, err
		}
	}
	if r != nil {
		for _, rr := range r.Answer {
			if ds, ok := rr.(*dns.DS); ok {
				info.DS = append(info.DS, DS{KeyTag: ds.KeyTag, Algorithm: ds.Algorithm, DigestType: ds.DigestType, Digest: strings.ToUpper(ds.Digest)})
			}
		}
	}

	// Validation: a validating resolver sets AD, or returns SERVFAIL for bogus data
	r, err = res.Query(zone, dns.TypeSOA, true)
	switch {
	case isServfail(err):
		info.Bogus = true
	case err == nil:
		info.Validated = r.AuthenticatedData
	}

	// DNSKEYs and signatures straight from the authoritative server
	if server == "" {
		return info, nil
	}
	resp, _, err := res.QueryServer(server, zone, dns.TypeDNSKEY, resolver.ServerOptions{DNSSEC: true})
	if err != nil {
		return info, err
	}
	var keys []*dns.DNSKEY
	for _, rr := range resp.Answer {
		switch k := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, k)
			info.DNSKEY = append(info.DNSKEY, Key{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, Flags: k.Flags, KSK: k.Flags&dns.SEP != 0})
		case *dns.RRSIG:
			info.noteSignature(k)
		}
	}
	for i := range info.DS {
		info.DS[i].Matches = matchesKey(info.DS[i], keys)
	}
	if len(keys) == 0 {
		return info, nil
	}

	if resp, _, err := res.QueryServer(server, zone, dns.TypeSOA, resolver.ServerOptions{DNSSEC: true}); err == nil {
		for _, rr := range resp.Answer {
			if sig, ok := rr.(*dns.RRSIG); ok {
				info.noteSignature(sig)
			}
		}
	}

	if resp, _, err := res.QueryServer(server, zone, dns.TypeNSEC3PARAM, resolver.ServerOptions{DNSSEC: true}); err == nil {
		for _, rr := range resp.Answer {
			if p, ok := rr.(*dns.NSEC3PARAM); ok {
				info.NSEC3 = &NSEC3Param{Iterations: p.Iterations, SaltLength: int(p.SaltLength)}
			}
		}
	}
	info.Denial = denialType(zone, server, res)
	return info, nil
}

// noteSignature keeps the earliest signature expiration
func (i *Info) noteSignature(sig *dns.RRSIG) {
	exp := time.Unix(int64(sig.Expiration), 0).UTC()
	if i.SignatureExpiry.IsZero() || exp.Before(i.SignatureExpiry) {
		i.SignatureExpiry = exp
		i.SignatureInception = time.Unix(int64(sig.Inception), 0).UTC()
	}
}

// matchesKey reports whether one of the keys hashes to the DS digest
func matchesKey(ds DS, keys []*dns.DNSKEY) bool {
	for _, k := range keys {
		if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
			continue
		}
		if computed := k.ToDS(ds.DigestType); computed != nil && strings.EqualFold(computed.Digest, ds.Digest) {
			return true
		}
	}
	return false
}

// denialType asks for a name that doesn't exist and looks at the proof of non-existence
func denialType(zone, server string, res *resolver.Resolver) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	name := "check-domain-" + hex.EncodeToString(buf) + "." + zone
	resp, _, err := res.QueryServer(server, name, dns.TypeA, resolver.ServerOptions{DNSSEC: true})
	if err != nil {
		return ""
	}
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NSEC3:
			return "NSEC3"
		case *dns.NSEC:
			return "NSEC"
		}
	}
	return ""
}

func isServfail(err error) bool {
	rerr, ok := err.(*resolver.RcodeError)
	return ok && rerr.Rcode == dns.RcodeServerFailure
}
