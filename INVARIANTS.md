# Application invariants

These are the contracts at the application's boundaries. Private fields, types,
validation, and bounded loops enforce them where practical. Assertions describe
programmer errors, not invalid CLI arguments or untrusted DNS responses.

## CLI and query construction (`src/cli.rs`, `src/dns.rs`)

- A `Question` has an absolute name and a queryable record type. Its constructor
  normalizes the name and rejects OPT and reserved type zero. Fields are private.
  The CLI rejects these types with a diagnostic before construction.
- Reverse lookup means PTR and excludes a positional query name. The CLI parser
  enforces argument conflicts and conversion checks an explicit record type.
- CLI parsing requires positive port, timeout, and attempt count. Port and attempts
  retain nonzero types internally. Attempts include the initial request. Timeout
  applies to an exchange, not to the whole lookup.
- Transport family is one of Any, IPv4, or IPv6, never two competing flags.
  CLI validation rejects a conflicting source or explicit server address.
  Transport filtering also requires addresses to match the source family.
- Nameserver addresses retain their IPv6 scope with their IP. Private fields
  prevent changing the address independently of its scope. Hostname resolution
  uses system nameservers, not the unresolved server, and excludes scoped servers
  because Hickory's resolver configuration cannot represent their scopes.
- Explicit and regional subnet hints are mutually exclusive. The CLI truncates
  host bits before creating the EDNS Client Subnet option.
- Trace requests disable recursion. `Trace::new` asserts this precondition.
  DNSSEC record requests (DO) and checking-disabled (CD) remain independent.

## DNS exchange and lookup (`src/dns.rs`)

- Only transport code constructs `Response`. It checks the query opcode and an
  exact, single matching question. The validated message is immutable to consumers,
  so `Response::question` can safely return that question.
- Truncated UDP responses trigger TCP fallback. Truncated TCP responses are errors,
  not complete responses. Timing covers only the successful exchange.
- SERVFAIL and REFUSED permit server failover. If no server succeeds, a received
  server-failure response takes precedence over transport errors.
- Lookup starts with an empty response vector, asserted at entry. Received
  responses survive later answer-validation, CNAME, or transport errors.
- Only matching IN-class answers satisfy a query. Referrals are not NODATA.
  CNAME traversal is bounded within each message and across at most 16 queries,
  with repeated queried names rejected.
- DNS data is untrusted. AD is a server assertion, not local validation.
  EDE text and DNSSEC signatures are displayed without being trusted or verified.

## Delegation trace (`src/trace.rs`)

- `State` owns either the next query, a deferred error, or terminal completion.
  Each yielded hop owns its response. Error-status responses are yielded before
  reporting their error. Completion, errors, and cancellation are terminal.
- A referral must progress to a strict descendant of the current zone that is
  still an ancestor of the query. The deepest valid referral is selected.
- Glue must match an IN-class nameserver record and lie within the referring
  parent zone. Other nameservers are resolved separately. Addresses are filtered
  by transport family. Each referral retains at most 64 distinct targets (glue
  addresses or unresolved nameserver names). Resolved addresses may repeat across
  targets, with resolution and attempts bounded by the global work budget.
- A walk allows at most 32 hops and 64 units of work. Hostname resolutions and
  server attempts each spend work before starting. Authoritative completion is
  checked before the hop limit. Positive authoritative answers must match the query.

## Enrichment and cache (`src/location.rs`, `src/enrichment.rs`)

- A `Database` keeps its validated database kind paired with its reader. Its kind
  is private and read-only. Enrichment labels results by kind, and output matches
  those labels rather than relying on parallel-vector positions.
- Empty enrichment means no lookup was applicable or requested. An entry with
  no information means a lookup was attempted without a result. Failures warn
  rather than invalidate DNS results.
- Installation and cooldown updates require an `InstallLock` acquired with
  an exclusive OS lock. The persistent state file is never replaced, so all
  processes lock the same inode. The guard stays alive through installation.
- First use waits, then rechecks the cache under the lock. Background refresh
  skips contention and rechecks freshness and cooldown under the lock. The
  foreground's unlocked cooldown read is only a hint to avoid spawning an updater.
- Refresh attempts, including failed ones, are recorded before downloading and
  throttled for 24 hours. Reading rewinds the locked handle before checking state.
  Explicit first-use installation is not throttled.
- DB-IP build months identify releases. Refresh only tries newer current/previous
  month releases, and falls back to the older release only after HTTP 404.
- Downloads use HTTPS, timeouts, and compressed/expanded size limits. Installation
  validates database kind and verifies the database in a same-directory temporary
  file before atomic replacement. Failed installs leave the previous cache intact.

## Output and finalization (`src/main.rs`, `src/output.rs`, `src/output/json.rs`)

- JSON mode emits one finalized document. Consuming `finish` prevents duplicate
  finalization. `complete` is derived from the final error, retaining partial results.
- Lookup responses have no hop number. Trace hops start at one and are consecutive.
  `Document::push` asserts these mode-specific contracts.
- Verbose mode is the single source of truth for full terminal RRSIG signatures.
  JSON retains all DNS sections independently of terminal verbosity.
- Terminal formatting escapes untrusted control characters. Progress belongs on
  stderr and its owner clears it on drop. JSON stdout remains machine-readable.
- Finalization is attempted even after DNS failure. DNS errors take precedence
  over output errors. Unavailable enrichment does not change DNS success.
