// Package rdap looks up a domain's registration at its registry through RDAP (RFC 9082/9083)
package rdap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sbroekhoven/check-domain/internal/resolver"
)

// BootstrapURL is IANA's list of RDAP servers per TLD (RFC 9224)
const BootstrapURL = "https://data.iana.org/rdap/dns.json"

// maxResponseSize limits how much of an RDAP response is read
const maxResponseSize = 1 << 20

// Domain is the registration data of a domain
type Domain struct {
	Server      string    `json:"server"`    // RDAP base URL of the registry
	Name        string    `json:"name"`      // ldhName as the registry knows it
	Registrar   string    `json:"registrar"` // name of the sponsoring registrar
	Created     time.Time `json:"created,omitzero"`
	Updated     time.Time `json:"updated,omitzero"`
	Expires     time.Time `json:"expires,omitzero"`
	Status      []string  `json:"status"`      // EPP status values, e.g. "client transfer prohibited"
	Nameservers []string  `json:"nameservers"` // as registered at the registry, lowercase without trailing dot
	Signed      bool      `json:"signed"`      // secureDNS.delegationSigned
}

// Client looks up domains via RDAP
type Client struct {
	HTTP         *http.Client
	BootstrapURL string
}

// NewClient returns a client with the given timeout
func NewClient(timeout time.Duration) *Client {
	return &Client{HTTP: &http.Client{Timeout: timeout}, BootstrapURL: BootstrapURL}
}

// Lookup finds the RDAP server for the TLD and fetches the domain. A TLD without an RDAP service
// returns a *resolver.NotFoundError, which is not a failed lookup.
func (c *Client) Lookup(domain string) (*Domain, error) {
	labels := strings.Split(strings.Trim(domain, "."), ".")
	tld := strings.ToLower(labels[len(labels)-1])

	base, err := c.serverFor(tld)
	if err != nil {
		return nil, err
	}

	var raw response
	status, err := c.getJSON(strings.TrimSuffix(base, "/")+"/domain/"+domain, &raw)
	if status == http.StatusNotFound {
		return nil, &resolver.NotFoundError{What: "RDAP", Name: domain}
	}
	if err != nil {
		return nil, err
	}
	d := raw.domain()
	d.Server = base
	return d, nil
}

// serverFor returns the RDAP base URL for a TLD from the IANA bootstrap file
func (c *Client) serverFor(tld string) (string, error) {
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if _, err := c.getJSON(c.BootstrapURL, &bootstrap); err != nil {
		return "", fmt.Errorf("RDAP bootstrap: %w", err)
	}
	for _, service := range bootstrap.Services {
		if len(service) < 2 || len(service[1]) == 0 {
			continue
		}
		for _, t := range service[0] {
			if strings.EqualFold(t, tld) {
				// Prefer an https URL
				for _, u := range service[1] {
					if strings.HasPrefix(u, "https://") {
						return u, nil
					}
				}
				return service[1][0], nil
			}
		}
	}
	return "", &NoServiceError{TLD: tld}
}

// NoServiceError means the registry of a TLD offers no RDAP service; it counts as "not found"
type NoServiceError struct {
	TLD string
}

func (e *NoServiceError) Error() string {
	return "the registry of ." + e.TLD + " offers no RDAP service"
}

// NotFound marks the error as "does not exist" rather than a failed lookup
func (e *NoServiceError) NotFound() bool { return true }

func (c *Client) getJSON(url string, v any) (int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return resp.StatusCode, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return resp.StatusCode, fmt.Errorf("%s: invalid JSON: %w", url, err)
	}
	return resp.StatusCode, nil
}

// response is the part of an RDAP domain object we use
type response struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
}

// Parse parses an RDAP domain response
func Parse(body []byte) (*Domain, error) {
	var raw response
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return raw.domain(), nil
}

func (r response) domain() *Domain {
	d := &Domain{
		Name:        strings.ToLower(r.LDHName),
		Status:      []string{},
		Nameservers: []string{},
		Signed:      r.SecureDNS.DelegationSigned,
	}
	for _, s := range r.Status {
		d.Status = append(d.Status, strings.ToLower(s))
	}
	for _, e := range r.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		switch e.Action {
		case "registration":
			d.Created = t
		case "last changed":
			d.Updated = t
		case "expiration":
			d.Expires = t
		}
	}
	for _, e := range r.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				d.Registrar = vcardName(e.VCardArray)
			}
		}
	}
	for _, ns := range r.Nameservers {
		if name := strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")); name != "" {
			d.Nameservers = append(d.Nameservers, name)
		}
	}
	sort.Strings(d.Nameservers)
	return d
}

// vcardName returns the "fn" (formatted name) of a jCard (RFC 7095): ["vcard", [["fn", {}, "text", "Name"], ...]]
func vcardName(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		if name, _ := prop[0].(string); name == "fn" {
			value, _ := prop[3].(string)
			return value
		}
	}
	return ""
}

// HasStatus reports whether the domain has a status, ignoring case and spaces vs camelCase
// ("client transfer prohibited" and "clientTransferProhibited" are the same)
func (d *Domain) HasStatus(status string) bool {
	want := normalizeStatus(status)
	for _, s := range d.Status {
		if normalizeStatus(s) == want {
			return true
		}
	}
	return false
}

func normalizeStatus(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}
