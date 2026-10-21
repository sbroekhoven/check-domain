package resolver

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RcodeError is returned when a DNS query completes but the server answers with a non-success code
type RcodeError struct {
	Name  string
	Rcode int
}

func (e *RcodeError) Error() string {
	return fmt.Sprintf("DNS query for %s returned %s", e.Name, dns.RcodeToString[e.Rcode])
}

// IsNXDomain reports whether err is an NXDOMAIN answer
func IsNXDomain(err error) bool {
	var rerr *RcodeError
	return errors.As(err, &rerr) && rerr.Rcode == dns.RcodeNameError
}

// NotFoundError is returned when a lookup succeeded but the record does not exist
type NotFoundError struct {
	What string // kind of record, e.g. "SPF"
	Name string // name that was queried
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no %s record found for domain: %s", e.What, e.Name)
}

// notFound is implemented by errors of other packages that mean "does not exist"
type notFound interface {
	NotFound() bool
}

// IsNotFound reports whether err means the record does not exist (as opposed to the lookup failing)
func IsNotFound(err error) bool {
	var nf *NotFoundError
	var other notFound
	return errors.As(err, &nf) || IsNXDomain(err) || errors.As(err, &other) && other.NotFound()
}

// Resolver sends DNS queries to a single nameserver, with an optional fallback nameserver
type Resolver struct {
	Server   string // host:port of the primary nameserver
	Fallback string // host:port of the fallback nameserver, empty to disable
	Timeout  time.Duration
}

// New creates a Resolver. Nameservers may be given as "1.1.1.1", "1.1.1.1:5353",
// "2001:4860:4860::8888" or "[2001:4860:4860::8888]:53". An empty fallback disables fallback.
func New(nameserver, fallback string, timeout time.Duration) *Resolver {
	r := &Resolver{
		Server:  NormalizeNameserver(nameserver),
		Timeout: timeout,
	}
	if fallback != "" {
		r.Fallback = NormalizeNameserver(fallback)
	}
	return r
}

// NormalizeNameserver turns a nameserver address into host:port form, defaulting to port 53
func NormalizeNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	if host, port, err := net.SplitHostPort(ns); err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(strings.Trim(ns, "[]"), "53")
}

// Query sends a recursive query for name/qtype. Truncated UDP answers are retried over TCP.
// Network failures on the primary nameserver are retried on the fallback nameserver, if configured.
// A non-success response code is returned as *RcodeError together with the response.
func (r *Resolver) Query(name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	if dnssec {
		// DO asks for signatures; AD asks a validating resolver to report whether it validated them
		m.SetEdns0(4096, true)
		m.AuthenticatedData = true
	}

	resp, err := r.exchange(m, r.Server)
	if err != nil && r.Fallback != "" {
		resp, err = r.exchange(m, r.Fallback)
	}
	if err != nil {
		return nil, fmt.Errorf("DNS query for %s failed: %w", name, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return resp, &RcodeError{Name: name, Rcode: resp.Rcode}
	}
	return resp, nil
}

func (r *Resolver) exchange(m *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: r.Timeout}
	resp, _, err := c.Exchange(m, server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.Exchange(m, server)
	}
	return resp, err
}

// TXT returns the TXT strings for name, with the chunks of each record joined together
func (r *Resolver) TXT(name string) ([]string, error) {
	resp, err := r.Query(name, dns.TypeTXT, false)
	if err != nil {
		return nil, err
	}

	var txts []string
	for _, a := range resp.Answer {
		if txt, ok := a.(*dns.TXT); ok {
			txts = append(txts, strings.Join(txt.Txt, ""))
		}
	}
	return txts, nil
}

// ServerOptions controls a direct query to one nameserver
type ServerOptions struct {
	Recursion bool          // set RD; authoritative checks leave it off
	TCP       bool          // use TCP instead of UDP (no automatic retry)
	NoEDNS    bool          // send the query without an OPT record
	DNSSEC    bool          // set the DO bit (implies EDNS)
	Class     uint16        // query class; 0 means IN
	Timeout   time.Duration // 0 means the resolver's timeout
}

// QueryServer sends one query directly to server (host:port) and returns the response as is,
// without fallback and without turning a non-success rcode into an error. Over UDP, a truncated
// answer is retried over TCP unless opts.TCP is set. It also returns the round-trip time.
func (r *Resolver) QueryServer(server, name string, qtype uint16, opts ServerOptions) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = opts.Recursion
	if opts.Class != 0 {
		m.Question[0].Qclass = opts.Class
	}
	if !opts.NoEDNS || opts.DNSSEC {
		m.SetEdns0(1232, opts.DNSSEC)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = r.Timeout
	}
	c := &dns.Client{Net: "udp", Timeout: timeout}
	if opts.TCP {
		c.Net = "tcp"
	}
	resp, rtt, err := c.Exchange(m, server)
	if err == nil && resp.Truncated && !opts.TCP {
		c.Net = "tcp"
		resp, rtt, err = c.Exchange(m, server)
	}
	return resp, rtt, err
}

// AXFR asks server for a full zone transfer and returns the number of records received.
// A refused or failed transfer returns an error.
func (r *Resolver) AXFR(server, zone string) (int, error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	t := &dns.Transfer{DialTimeout: r.Timeout, ReadTimeout: r.Timeout}
	envelopes, err := t.In(m, server)
	if err != nil {
		return 0, err
	}
	count := 0
	for env := range envelopes {
		if env.Error != nil {
			return count, env.Error
		}
		count += len(env.RR)
	}
	return count, nil
}

// DNSPort is the port nameservers are queried on; tests point it at a local fake server
var DNSPort = "53"

// ServerAddr returns host:port for a nameserver IP address
func ServerAddr(ip string) string {
	return net.JoinHostPort(ip, DNSPort)
}
