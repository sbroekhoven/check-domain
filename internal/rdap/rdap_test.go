package rdap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/sbroekhoven/check-domain/internal/resolver"
)

func TestParse(t *testing.T) {
	body, err := os.ReadFile("testdata/domain.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	want := &Domain{
		Name:        "example.com",
		Registrar:   "Example Registrar, Inc.",
		Created:     time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC),
		Updated:     time.Date(2026, 8, 14, 7, 1, 34, 0, time.UTC),
		Expires:     time.Date(2027, 8, 13, 4, 0, 0, 0, time.UTC),
		Status:      []string{"client delete prohibited", "client transfer prohibited", "client update prohibited"},
		Nameservers: []string{"a.iana-servers.net", "b.iana-servers.net"},
		Signed:      true,
	}
	if !reflect.DeepEqual(d, want) {
		t.Errorf("Parse() =\n%+v\nwant\n%+v", d, want)
	}
	if !d.HasStatus("clientTransferProhibited") || d.HasStatus("serverHold") {
		t.Error("HasStatus does not match camelCase and spaced status names")
	}
}

func TestServerForPrefersHTTPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"services": [[["com", "net"], ["http://plain.example/", "https://secure.example/"]], [["org"], ["http://only-http.example/"]]]}`))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BootstrapURL: srv.URL}

	for tld, want := range map[string]string{"com": "https://secure.example/", "NET": "https://secure.example/", "org": "http://only-http.example/"} {
		if got, err := c.serverFor(tld); err != nil || got != want {
			t.Errorf("serverFor(%q) = %q, %v; want %q", tld, got, err, want)
		}
	}
	if _, err := c.serverFor("nl"); !resolver.IsNotFound(err) {
		t.Errorf("serverFor(nl) error = %v, want not found", err)
	}
}

func TestLookup(t *testing.T) {
	fixture, _ := os.ReadFile("testdata/domain.json")
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"services": [[["com"], ["` + srv.URL + `/rdap/"]]]}`))
	})
	mux.HandleFunc("/rdap/domain/example.com", func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) })
	mux.HandleFunc("/rdap/domain/missing.com", http.NotFound)
	mux.HandleFunc("/rdap/domain/broken.com", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "oops", 500) })
	c := &Client{HTTP: srv.Client(), BootstrapURL: srv.URL + "/bootstrap"}

	d, err := c.Lookup("example.com")
	if err != nil || d.Registrar != "Example Registrar, Inc." || d.Server != srv.URL+"/rdap/" {
		t.Fatalf("Lookup(example.com) = %+v, %v", d, err)
	}
	if _, err := c.Lookup("missing.com"); !resolver.IsNotFound(err) {
		t.Errorf("unregistered domain: err = %v, want not found", err)
	}
	if _, err := c.Lookup("broken.com"); err == nil || resolver.IsNotFound(err) {
		t.Errorf("server error: err = %v, want a failure", err)
	}
	if _, err := c.Lookup("example.nl"); !resolver.IsNotFound(err) || err.Error() != "the registry of .nl offers no RDAP service" {
		t.Errorf("TLD without RDAP: err = %v", err)
	}
}
