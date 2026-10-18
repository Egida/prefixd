# Speaker backends

prefixd owns mitigation policy, guardrails, and desired state. The selected BGP
daemon owns peer sessions and protocol distribution. rustbgpd is the preferred
integration target; GoBGP remains supported. The default deployment continues
to use GoBGP while the rustbgpd path is qualified.

## Current boundary

`FlowSpecAnnouncer` remains the selected `Arc<dyn FlowSpecAnnouncer>` facade.
Its required `FlowSpecWriter` contract provides announce/upsert and idempotent
withdraw: repeating a request after an ambiguous response must be safe.
`reader()` optionally exposes `FlowSpecReader`; `peer_observer()` optionally
exposes `PeerObserver`. Availability is derived from these accessors. All three
current adapters provide both observers; no deployment default changes.

Without a reader, reconciliation still loads the strict complete desired
inventory and updates status gauges, but performs no announcement repairs.
Independent TTL and pending-withdrawal cleanup continue. A supported reader
failure fails the pass and increments the run error counter; it never becomes
an empty inventory. Unsupported peer observation skips peer metric updates;
a failed observation also retains the last successful metric values.

Health detail adds `speaker.backend` and two availability booleans under
`speaker.capabilities`: `rule_reader` and `peer_observer`. The legacy `gobgp`
component reports `unsupported` without an error when peer observation is absent,
`error` when it fails, and `connected` when it succeeds (even with zero peers).
`bgp_sessions` remains the same peer-name/state map. Missing optional observation
alone does not make overall health degraded. Health does not probe the RIB.
These fields describe API availability and peer observation, not announcement,
export, or enforcement confirmation.

`prefixdctl peers` fails explicitly on unsupported or failed peer observation;
successful JSON remains the peer map. Status and dashboard clients tolerate older
health responses without `speaker` metadata. The dashboard distinguishes
unsupported observation, observation errors, and a successful empty peer list.

| Backend | Runtime selection | Read-back / peers | Status |
|---------|-------------------|-------------------|--------|
| GoBGP | `gobgp` or existing `sidecar` | Implemented / implemented | Existing backend; existing lab receipts apply to this path |
| rustbgpd | `rustbgpd`, built with `bgp-rustbgpd` | Local injected view / neighbor states | Experimental adapter; deployment and router parity gates remain open |
| Mock | `mock` | In-memory / synthetic | Automated testing only |
| Generic HTTP shim | Planned | Capability-dependent | Requires durable announcement ledger |
| ExaBGP or another daemon | Planned adapter or shim | Must be verified | No support or interoperability claim yet |

FRR, BIRD, and OpenBGPD are not selectable backends today. A router accepting a
FlowSpec route is distinct from a daemon exposing the origination/control API
prefixd needs. Each proposed adapter needs that evidence before implementation.

## Persistent target ownership

Before constructing a speaker client, startup registers or validates one
credential-free target identity for the configured POP. Each target may belong to
only one POP in that database. Lifecycle entrypoints require this verified binding;
new withdrawal requests retain its immutable target UUID, and retry execution
checks both the caller and the freshly loaded pending row before any speaker RPC.
Only explicitly selected mock fixtures can run without a binding.

Existing speaker history needs a one-time, original-target adoption. See the
[upgrade procedure](../how-to/upgrading.md#speaker-ownership-upgrade) before
restarting an existing deployment. Reload does not change the running POP, speaker
configuration or controller mode. Credential rotation preserves identity; target
changes need an explicit drained transfer. These bindings assume one controller
per POP and exclusive physical-target use, not process leases or DNS-alias fencing.
HTTP(S) addresses may have only a root path: gRPC discards endpoint path prefixes,
so they cannot distinguish targets and are rejected before registration.

External repository implementations can read the normalized identity through
`SpeakerTarget::{backend, endpoint, namespace}` and issue a binding with the
public `VerifiedSpeakerBinding::new` constructor; its fields remain private.
Repositories are trusted issuers. They must serialize ownership registration,
persist or validate the exclusive POP/target assignment, finish any legacy
adoption atomically, and commit before constructing the binding. The constructor
performs no database checks. The result is startup consistency evidence, not an
authorization token or an interprocess lease. Keep endpoint coordinates out of
API responses and diagnostics.

`RepositoryTrait::register_speaker_target` defaults to an explicit unsupported
error so existing repository implementations remain source-compatible. They must
implement this contract before real-speaker startup can succeed; the default
never issues a binding or silently disables ownership checks.

## GoBGP read-back

GoBGP inventory reads both IPv4 and IPv6 FlowSpec GLOBAL tables, including
nonselected local paths. In GoBGP v4.10.0, an empty `neighbor_ip` identifies
GoBGP-local provenance; received paths are excluded before decoding. UUIDs are
not populated by ListPath and do not identify ownership. Local paths from other
controllers are not distinguished from prefixd's paths; unknown rules are never
deleted by reconciliation. These provenance fields follow the pinned
[GoBGP v4.10.0 serializer](https://github.com/osrg/gobgp/blob/da824d99912e02124b53741245ee4186c381adcc/pkg/server/grpc_server.go#L214).

This is the accepted local RIB, not retained pre-policy injection intent. Global
import policy can reject an injected route, so successful AddPath alone does not
prove it appears in this inventory; see the pinned
[AddPath policy processing](https://github.com/osrg/gobgp/blob/da824d99912e02124b53741245ee4186c381adcc/pkg/server/server.go#L1323).

Both family streams must finish successfully, including trailers. Any family
failure or malformed/unsupported local row fails the entire observation; no
partial inventory is returned. The complete dual-family read and each peer read
have a 30-second deadline, including response bodies. Destination prefixes,
optional protocol equality, destination-port equality lists, and one traffic-rate
action are supported. Byte rates convert to bits/sec before exact integer/range
validation; zero means discard. Missing or ambiguous actions and extra match or
action semantics are errors. Unsupported unrelated local rules can therefore
block reconciliation observation and require operator attention.

## rustbgpd configuration

Build with `cargo build --features bgp-rustbgpd`. A local authenticated TCP
configuration uses:

```yaml
bgp:
  mode: rustbgpd
  rustbgpd:
    endpoint: "http://127.0.0.1:50051"
    bearer_token_env: "PREFIXD_RUSTBGPD_TOKEN"
  local_asn: 65010
  router_id: "10.10.0.10"
```

Set the environment variable to the token stored in rustbgpd's `token_file`.
The daemon's listener principal needs an `operator` role for Add/DeleteFlowSpec;
the token authenticates that listener identity. The client sends the bearer
token, not a user-supplied principal header. Credential values are never YAML
configuration fields or settings API output.

For co-located processes use the owner-only Unix socket:

```yaml
bgp:
  mode: rustbgpd
  rustbgpd:
    endpoint: "unix:///var/lib/rustbgpd/grpc.sock"
  local_asn: 65010
  router_id: "10.10.0.10"
```

Mount the runtime directory at a stable absolute path and run both processes
with the same UID. The directory must be owner-only (normally `0700`), the
socket owner-only (normally `0600`), and neither path may traverse symlinks.
prefixd checks ownership, permissions and the Unix peer UID on every connection,
including reconnects after socket recreation. Every ancestor must be owned by
root or the controller UID and prevent untrusted directory replacement; writable
ancestors require the sticky bit. Root and the controller UID are trusted to
maintain these paths. An owner-only rustbgpd listener
without an explicit principal authorizes its owner as `local-operator`; no token
or role mapping is needed. If its UDS listener sets `token_file`, also configure
`bearer_token_env` in prefixd. Changing the socket path changes the persistent
speaker target; recreating it or rotating credentials does not.

For remote native mTLS use:

```yaml
bgp:
  mode: rustbgpd
  rustbgpd:
    endpoint: "https://speaker.example:50051"
    ca_cert_path: "/etc/prefixd/speaker-ca.pem"
    client_cert_path: "/etc/prefixd/client.pem"
    client_key_path: "/etc/prefixd/client-key.pem"
  local_asn: 65010
  router_id: "10.10.0.10"
```

The server certificate must match the endpoint hostname and chain to the
configured CA or system roots. Client certificate and key must be configured
together. On rustbgpd set all three `tls_cert_file`, `tls_key_file` and
`tls_client_ca_file`; partial server TLS configuration is invalid. Native mTLS
has no TLS-without-client-certificates mode. Map the verified client certificate
principal to `operator` under `[security.grpc.roles]`, rather than setting a TCP
listener principal. rustbgpd uses the full first `rustbgpd:` URI SAN, otherwise
an email SAN or Subject CN. No principal header is sent by prefixd.

Existing HTTPS bearer connections through a verified TLS endpoint remain valid;
client identity is optional for that case. Plain HTTP still requires a bearer
token and accepts only literal loopback IPs, including `127.0.0.1` and `[::1]`;
container DNS and other hostnames are not a loopback guarantee. TLS fields are
rejected on plaintext and Unix endpoints. Private key contents and token values
never belong in YAML or settings API output.

Initial network connection attempts and each TLS handshake have a ten-second
budget. A peer that accepts TCP but does not finish TLS cannot stall startup
indefinitely. Complete RPC attempts remain bounded separately.

The relevant vendored controller message fields were checked against rustbgpd
`v0.77.0`. This is a protocol baseline, not proof that an arbitrary binary
reporting that version has passed the deployment or router tests.

## Released controller qualification

The scoped controller promotion is released: v0.76.0 is the minimum controller
contract version, and v0.77.0 is the current qualification pin. CI runs the
lifecycle, TTL and restart suite against both immutable image references in
[releases.json](../../tests/fixtures/rustbgpd/releases.json). Image OCI source
revisions match the dereferenced release-tag commits. This qualifies the local
controller boundary on Linux amd64, independently of router interoperability.

Run the same isolated suite locally with Docker available:

```bash
scripts/test-rustbgpd.sh
PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 scripts/test-rustbgpd.sh
```

Fixtures bind ephemeral loopback ports, create an owner-only bearer token, and
remove their containers and token files afterward. They reuse the existing
client/channel and desired-state repository across a forced speaker-process
restart, prove local intent was lost, and verify exact dual-family actions are
restored by the running poller within its configured interval after readiness.
The next converged poll performs no repairs. Unknown local keys are preserved.

On a speaker restart, prefixd's active database rows remain desired state. The
next successful inventory poll repairs missing rules sequentially; there is no
additional restart detector or concurrent replay fan-out. Recovery time includes
speaker readiness, polling and RPC completion, so the configured interval alone
is not a wall-clock SLA under failures or a large backlog.

Monitor `prefixd_reconciliation_repairs_total{status="success"}` for repaired
local intent and `{status="error"}` for rejected repairs. Repair errors also make
`prefixd_reconciliation_runs_total{status="error"}` increase; other missing
rules are still attempted. For example, alert on
`increase(prefixd_reconciliation_repairs_total{status="error"}[5m]) > 0`, and
investigate unexpected repair spikes after restarts. These metrics report local
RPC outcomes, not downstream enforcement or a confirmed restart count.

## Rule and reconciliation semantics

Automatic detector intent uses IPv4 `/32` and IPv6 `/128` host destinations.
ICMP floods use protocol 1 for IPv4 and 58 for IPv6 before reaching either
speaker adapter. The manual mitigation API currently accepts `icmp` as protocol
1 only; it does not expose an ICMPv6 selector.

The rustbgpd adapter supports destination prefix, optional protocol, equality
lists of destination ports, and discard or traffic policing. Components are sent in RFC
type order. Policing uses bits/sec in prefixd and floating-point bytes/sec in
the daemon; rates that cannot be represented exactly are rejected. Unsupported matches or
actions must produce an error instead of being dropped during decoding.

Add is an upsert; reapplying unchanged intent succeeds. Delete requests opt into
`allow_missing`, so an already absent rule is success. Unknown mutation outcomes
and missing read-view acknowledgements are errors, including an empty response
from an older daemon that ignored the selector.

Both address families are read from retained local intent with
`received_peer_address = "0.0.0.0"`. A nonselected local rule still exists and
must not trigger repeated injection. No received peer's rule is withdrawn by
this API. Other controllers sharing local injection are not distinguished by an
ownership marker; unknown local rules are currently reported, not deleted.

New detector and manual mitigations are persisted as Active desired intent before
announcement. Speaker errors retain that row for readable recovery and return a
request-local unconfirmed outcome; they do not prove rejection or delete intent.
Active status and creation notifications describe desired state, while successful
announcement metrics describe local RPC acceptance. This is not the full durable
desired/acknowledged revision ledger or write-only recovery contract.

Reconciliation reads the complete desired owner inventory for its POP. Malformed
persisted rows fail the pass before repairs begin. Pending creation rows are
excluded from repairs and status-active counts; expired and pending-withdrawal
rows remain counted until their terminal transition but cannot be re-announced.
Expiry enumeration also filters POP before decoding and fails on malformed
eligible owned rows. Existing durable withdrawals are still attempted when expiry
enumeration fails; every withdrawal retains its independent ownership validation.

The scheduler currently compares NLRI identity. Repairing action-only drift
needs separate coverage and implementation. Successful injection does not
prove export-policy acceptance, router receipt, or traffic enforcement.

Mandatory TTLs are enforced by the running controller. Losing prefixd does not
drop a separate daemon's router sessions or automatically expire its rules.
Monitor controller availability and restore reconciliation after failure. A
controller lease or coupled lifecycle needs its own design and failure tests.

## Withdrawal recovery

Detector unban, operator single/bulk withdrawal and TTL expiry persist immutable
deletion intent before RPC. An error keeps that intent pending, suppresses repair
of its rule and retries cleanup on the same target. State, original-actor audit
and operation completion commit atomically after confirmed deletion. Conflicting
owners and foreign POPs cannot authorize deletion; stale local requests are
rejected before sending a new RPC.

Canonical ownership includes legacy prefix spellings. New manual duplicates
return 409 before speaker mutation; detector events reuse one existing owner.
Ambiguous multiple owners are rejected. An expired legacy sibling cannot delete
a live owner's rule; after the last owner expires, cleanup retires all rows.
Pending enforced-mode cleanup remains pending in dry-run and resumes when
enforcement returns; dry-run never supplies a deletion acknowledgement.

Independent housekeeping and peer observations continue after failed mutations.
Each scheduler mutation rechecks the current row and pending intent under the
shared lifecycle mutex; the mutex is released before the next rule. Both gRPC adapters
bound complete mutation responses, including body and trailers, to 30 seconds
per attempt, with at most three attempts.

Active mitigation gauges count local database status, including expired or
pending rows awaiting confirmed cleanup; they are not proof of enforcement.
rustbgpd session observations use peer addresses as unique names, so neighbors
sharing a description retain separate metric series.

This is a fixed-target, single-controller contract. Drain pending requests before
changing targets or downgrading; see [the upgrade guide](../how-to/upgrading.md#pending-withdrawals-and-rollback).
Application status and local speaker intent do not prove router enforcement.

## Delivery order

| Stage | Work and gate |
|-------|---------------|
| 1 | Keep GoBGP supported; selectable rustbgpd adapter, compatible config, authenticated RPC and codec tests |
| 2 | Retry failed expiry withdrawals; real daemon TTL/restart recovery and transport/deployment wiring |
| 3 | Router interop, migration and rollback evidence; only then change deployment defaults |
| 4 | Optional observation split implemented; durable confirmed announcement state remains required (pending withdrawal cleanup exists) |
| 5 | Health availability metadata and CLI/dashboard observation states implemented; retain legacy public fields |
| 6 | HTTP shim, a second transport proof, shared conformance and per-backend CI |

The capability/ledger work can proceed before the default switch, but a
write-only backend cannot ship before its reconciliation path is verified.
Generic exec transport, runtime plugin loading, and unrelated framework or UI
rewrites are outside this first slice.

## Contributor and certification gates

Custom `RepositoryTrait` implementations must provide the strict
`expired_mitigation_inventory` boundary. The legacy required expiry method remains
available, but the new boundary reports unsupported until explicitly implemented.

Add an adapter module, its config subsection, and a factory entry. Implement required writing and explicitly opt into supported observers. Test exact RPC
or transport payloads, authentication, transient and permanent failures, rule
identity, replacement, repeated delete, both families, and action read-back.
Run against a pinned real daemon before calling the adapter supported. Record
router evidence separately and include restart/TTL behavior in the release gate.

The existing `gobgp` health field and `apipb` export remain compatibility
surfaces. They do not select the active backend. Production write-only adapters
remain gated on the durable announcement ledger and verified recovery semantics.


## Readable backend qualification

`tests/common/speaker_contract.rs` contains the shared async lifecycle oracle used
by Mock, GoBGP and rustbgpd. It checks complete local inventory cardinality,
canonical IPv4/IPv6 destinations, optional protocols, eight destination ports,
exact discard/police actions, duplicate announcement/withdrawal, action replacement
and re-announcement. The ordinary Rust test suite includes a deliberately broken
Mock reader whose missing actions must fail that oracle with a useful diagnostic.
A readable third-party adapter can call `run_readable_contract(&adapter)` against
an isolated empty speaker; unsupported observation must not be faked as an empty
inventory. Peer transitions and process restart require backend-owned fixtures.

Run the real fixtures on Linux with Docker:

```sh
scripts/test-gobgp.sh
scripts/test-rustbgpd.sh
PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 scripts/test-rustbgpd.sh
```

The GoBGP fixture pins image digest
`sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2`
and verifies the binary reports 4.10.0. Raw and API end-to-end tests create their
own containers and reserve ephemeral loopback listeners; they ignore ambient
speaker endpoints. Readiness, raw streams and peer convergence are bounded.
Optional `PREFIXD_TEST_CPUSET` applies to the fixture containers.

The GoBGP peer case observes actual dual-family receipt and withdrawal, checks
session continuity, forces a received route to win over an existing local path,
and verifies the local reader still returns that nonselected local path. It also
checks peer loss and recovery after a real process restart using the original
clients. A separate restart case rebuilds GoBGP state through the real reconciler
without deleting unrelated local rules. Existing rustbgpd TTL and same-client
restart cases remain in its released-image matrix. CI retains logs on success
and failure; an unavailable image or daemon fails qualification.

These tests observe local acceptance and daemon-to-daemon BGP receipt. They do
not establish router enforcement, vendor forwarding, or rustbgpd-to-GoBGP peer
interoperability. The latter remains a separate required peering qualification;
ExaBGP and other write-only backends are not qualified by this readable suite.
