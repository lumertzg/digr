# digr

DNS lookups and traces, for terminals and scripts.

```sh
cargo install --git https://github.com/lumertzg/digr
digr example.com
digr example.com --type MX --server 1.1.1.1
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
text and re-encoded RDATA hex. Lookup failures retain partial responses with
`complete: false`, an `error`, and a nonzero exit status. Invalid CLI arguments
produce no JSON.

## IP information

`--location` and `--asn` use [DB-IP Lite](https://db-ip.com),
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Downloads on first use. Refreshes data older than 30 days in the background.
Locations are approximate.

`--subnet CIDR` sends an ECS hint. `--subnet-from` offers NA, SA, EU, AS, AF,
and OC presets. Servers may ignore hints. Query origin does not change.
