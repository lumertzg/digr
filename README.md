# digr

DNS lookups and traces, for terminals and scripts.

```sh
cargo install --git https://github.com/lumertzg/digr
digr example.com
digr example.com --type MX --server 1.1.1.1
digr example.com --server fe80::1%en0
digr --reverse 192.0.2.1
digr example.com --trace
digr example.com --subnet-from OC --location --asn
digr --help
```

## JSON

```sh
digr example.com --json
digr example.com --trace --json > trace.json
digr example.com --json | jq '.responses[].answers'
```

One document per invocation, including the entire trace. All DNS sections are
included. Progress and diagnostics go to stderr.

[Schema v1](schema.json). Common records have typed data. Other types retain
text and re-encoded RDATA hex. Names are in ASCII, so internationalized names
appear as `xn--` labels. Lookup failures, including NXDOMAIN and SERVFAIL,
retain partial responses with `complete: false`, an `error`, and a nonzero exit
status. A NOERROR response without records of the requested type succeeds,
but a referral fails.
Invalid CLI arguments produce no JSON.

## DNSSEC diagnostics

```sh
digr example.com --dnssec
digr example.com --dnssec --checking-disabled --server 1.1.1.1
digr example.com --trace --dnssec
```

`--dnssec` requests DNSSEC records (DO). `--checking-disabled` independently
asks the server to skip validation (CD). Both show flags and all record sections.
Work with `--trace` and `--json`.
RRSIG shows signing metadata. Full signatures require `--verbose` or `--json`.

No local validation. AD and Extended DNS Errors (EDE) are server-reported.
EDE appears whenever returned and does not change exit status.
Malformed DNSSEC records may be rejected before diagnostics.

## IP information

`--location` and `--asn` use [DB-IP Lite](https://db-ip.com),
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Downloads on first use. Fetches each new monthly release in the background.
Locations are approximate.

`--subnet CIDR` sends an ECS hint. `--subnet-from` offers NA, SA, EU, AS, AF,
and OC presets. Servers may ignore hints. Query origin does not change.
