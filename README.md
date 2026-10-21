# Domain & DNS Checker

A command-line tool that checks a domain's DNS setup: the registration, the delegation from the parent zone, every nameserver, the SOA record, DNSSEC and the records at the zone apex. It is the sibling of [check-maildomain](https://github.com/sbroekhoven/check-maildomain), which checks a domain's mail setup.

## Features

- **Registration:** TLD type (gTLD, ccTLD, sponsored, …) and whether ICANN policies apply; registrar, expiry date, status and nameservers at the registry via RDAP
- **Delegation:** the NS set and glue as the parent zone publishes them, compared with the zone itself; number of nameservers and their spread over networks, autonomous systems and TLDs
- **Nameservers:** every address is queried directly: does it respond, answer authoritatively, refuse recursion, hide its version, refuse zone transfers (AXFR), support TCP and EDNS
- **SOA:** identical serials on all nameservers, sane timers, primary nameserver (hidden master detection) and contact address
- **DNSSEC:** signed and validated, DS matches a key, current algorithms, signature expiry (online signing aware), NSEC/NSEC3 parameters
- **Records:** TTLs, no CNAME at the apex, wildcards, CAA
- Console output always; optional JSON and self-contained HTML report; the exit code reflects failures, so it can run in CI

## Installation

```bash
go install github.com/sbroekhoven/check-domain/cmd/check-domain@latest
```

Or download a binary from the [releases page](https://github.com/sbroekhoven/check-domain/releases), or build from source:

```bash
git clone https://github.com/sbroekhoven/check-domain.git
cd check-domain
go build -o check-domain ./cmd/check-domain
```

## Usage

```bash
# Check a domain (a host name such as www.example.com checks the zone it is in)
check-domain example.com

# Use a specific resolver (IPv4, IPv6, optional port)
check-domain -nameserver 1.1.1.1 example.com

# Also save the results as JSON and as an HTML report (missing folders are created)
check-domain -json reports/example.json -html reports/example.html example.com

# A folder (trailing /) gets a timestamped file name, e.g. results/20261021001500-example.com.json
check-domain -json results/ example.com

# Only DNS: no RDAP lookup, no zone transfer test
check-domain -no-rdap -no-axfr example.com
```

## Command-line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-domain` | | Domain to check (alternatively the first argument) |
| `-nameserver` | `8.8.8.8` | Recursive resolver for lookups, optionally with port |
| `-fallback` | | Resolver to use when the primary does not respond |
| `-timeout` | `3s` | Timeout per DNS query |
| `-json` | | Also write the results as JSON to this file, or into this folder (`dir/`) |
| `-html` | | Also write an HTML report to this file, or into this folder (`dir/`) |
| `-no-rdap` | `false` | Don't look up the registration via RDAP |
| `-no-axfr` | `false` | Don't test whether the nameservers allow zone transfers |
| `-v` | `false` | Also show the details of passing checks |
| `-rules` | | List all checks (ID, area, name) and exit |
| `-version` | | Print version and exit |

The console output is always printed to stdout. `-json` and `-html` write files in addition to it and can be used together; the paths they were saved to are printed on stderr. Colours are used when writing to a terminal and are turned off when the output is piped or `NO_COLOR` is set.

## HTML Report

`-html` writes a single, self-contained HTML file (inline CSS, no external assets) that you can email, attach to a ticket or archive. It shows an overall verdict and one card per area, with the data that was found: registration details, a table of nameservers with their addresses, networks and glue, the per-server probe results, serials, DS and DNSKEY records and the apex records with their TTLs. Problems are expanded; passing checks can be clicked open. The report follows the system light/dark theme, works on phones and prints cleanly.

## Checks

| ID | Area | Check |
|----|------|-------|
| 1 | Registration | TLD type and whether ICANN contracts and policies apply |
| 2 | Registration | TLD delegated in the root zone and DNSSEC-signed |
| 3 | Registration | Registration not expiring within 30 days (RDAP) |
| 4 | Registration | No hold/delete status; transfer lock present (RDAP) |
| 5 | Registration | Nameservers at the registry match the delegation (RDAP) |
| 6 | Delegation | Domain exists and has at least 2 nameservers (3 recommended) |
| 7 | Delegation | Parent delegation and zone NS records list the same nameservers |
| 8 | Delegation | Glue present for in-zone nameservers and matching the zone |
| 9 | Delegation | Nameserver names resolve and are not CNAMEs |
| 10 | Delegation | Nameservers in different IPv4 /24 and IPv6 /48 networks |
| 11 | Delegation | Nameservers in more than one autonomous system |
| 12 | Delegation | Nameserver names under more than one TLD |
| 13 | Delegation | Nameservers reachable over IPv6 |
| 14 | Nameservers | All nameserver addresses respond |
| 15 | Nameservers | All answer authoritatively (no lame delegation) |
| 16 | Nameservers | No open recursion |
| 17 | Nameservers | No software version disclosed (version.bind / version.server) |
| 18 | Nameservers | No zone transfer (AXFR) to the public |
| 19 | Nameservers | DNS over TCP supported |
| 20 | Nameservers | EDNS(0) supported |
| 21 | Nameservers | Nameserver addresses publicly routable |
| 22 | SOA | Serial identical on all nameservers |
| 23 | SOA | Refresh, retry, expire and negative TTL within recommendations |
| 24 | SOA | Primary nameserver (MNAME); hidden master detection |
| 25 | SOA | Contact address (RNAME) is a valid mailbox |
| 26 | SOA | Date-based serial not in the future |
| 27 | DNSSEC | Zone signed, DS at the parent, validated by the resolver |
| 28 | DNSSEC | DS record matches a DNSKEY |
| 29 | DNSSEC | No deprecated or insecure algorithms (RFC 8624) |
| 30 | DNSSEC | Signatures not (nearly) expired |
| 31 | DNSSEC | NSEC3 with 0 iterations and no salt (RFC 9276); NSEC zone walking noted |
| 32 | Records | NS, A, AAAA and MX TTLs between 5 minutes and 1 week |
| 33 | Records | No CNAME at the zone apex |
| 34 | Records | Wildcard records detected |
| 35 | Records | CAA records restrict certificate issuance |

## Network Access

Besides DNS queries to the chosen resolver, the tool makes these connections:

- **The domain's nameservers** are queried directly (UDP and TCP port 53): SOA, NS, a recursion test for an unrelated name, `version.bind`/`version.server` in the CHAOS class, and a zone transfer (AXFR) attempt. The transferred data is only counted, not stored. Use `-no-axfr` to skip the transfer test.
- **The parent zone's nameservers** are asked for the delegation, so the NS set and glue are exactly what the registry publishes.
- **Team Cymru** (`origin.asn.cymru.com`, via DNS) is asked for the autonomous system of each nameserver address.
- **RDAP:** IANA's bootstrap file (`https://data.iana.org/rdap/dns.json`) and the registry's RDAP server are queried over HTTPS. Use `-no-rdap` to skip this. Many ccTLD registries don't offer RDAP; those checks then report that the data is not available.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No check failed |
| 1 | Usage or runtime error, an output file could not be written, or a lookup failed so the results are incomplete |
| 2 | At least one check failed |

## Project Layout

```
cmd/check-domain/      command-line entry point: flags, output selection, exit codes
internal/resolver/     DNS queries: recursive (with TCP retry and fallback) and direct to one server
internal/delegation/   zone apex, parent zone and the delegation (NS + glue) it publishes
internal/nameservers/  resolves the nameservers and probes every address
internal/dnssec/       DS, DNSKEY, signatures, NSEC/NSEC3 and validation
internal/records/      apex records with their TTLs, apex CNAME, wildcards, CAA
internal/tld/          TLD classification and root zone checks
internal/rdap/         registration data via RDAP
internal/asn/          autonomous systems via Team Cymru
internal/collector/    runs all lookups concurrently into one DomainInfo
internal/rules/        the checks, producing pass/warn/fail/info results
internal/output/       terminal output and the HTML report (template in templates/)
```

## Development

```bash
go vet ./...
go test ./...
```

## License

Apache License 2.0, see [LICENSE](LICENSE).
