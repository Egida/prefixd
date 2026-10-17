# Speaker backends

prefixd owns mitigation policy, guardrails, and desired state. The selected BGP
daemon owns peer sessions and protocol distribution. rustbgpd is the preferred
integration target; GoBGP remains supported. The default deployment continues
to use GoBGP while the rustbgpd path is qualified.

## Current boundary

`FlowSpecAnnouncer` has four required operations: announce, withdraw, list active
local rules, and observe peer state. A factory selects the configured adapter;
the policy engine and scheduler use the same trait for every backend.

| Backend | Runtime selection | Read-back / peers | Status |
|---------|-------------------|-------------------|--------|
| GoBGP | `gobgp` or existing `sidecar` | Implemented / implemented | Existing backend; existing lab receipts apply to this path |
| rustbgpd | `rustbgpd`, built with `bgp-rustbgpd` | Local injected view / neighbor states | Experimental adapter; deployment and router parity gates remain open |
| Mock | `mock` | In-memory / synthetic | Automated testing only |
| Generic HTTP shim | Planned | Capability-dependent | Requires durable ledger and optional observation support |
| ExaBGP or another daemon | Planned adapter or shim | Must be verified | No support or interoperability claim yet |

FRR, BIRD, and OpenBGPD are not selectable backends today. A router accepting a
FlowSpec route is distinct from a daemon exposing the origination/control API
prefixd needs. Each proposed adapter needs that evidence before implementation.

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

For a remote endpoint use `https://speaker.example:50051` and set
`ca_cert_path` to the PEM CA certificate that authenticates the server. The
certificate must match the endpoint hostname. Plain HTTP accepts only literal
loopback IPs, including `127.0.0.1` and `[::1]`; a hostname is not a loopback
guarantee. UDS and client-certificate mTLS are follow-up work.

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

Reconciliation reads the complete desired owner inventory for its POP. Malformed
persisted rows fail the pass before repairs begin. Pending creation rows are
excluded from repairs and status-active counts; expired and pending-withdrawal
rows remain counted until their terminal transition but cannot be re-announced.

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
| 4 | Split required writing from optional reading/peer observation; persist confirmed announcement state and pending cleanup |
| 5 | Expose capabilities in health/CLI/dashboard/metrics; retain legacy public fields during migration |
| 6 | HTTP shim, a second transport proof, shared conformance and per-backend CI |

The capability/ledger work can proceed before the default switch, but a
write-only backend cannot ship before its reconciliation path is verified.
Generic exec transport, runtime plugin loading, and unrelated framework or UI
rewrites are outside this first slice.

## Contributor and certification gates

Add an adapter module, its config subsection, and a factory entry. Preserve the
shared trait until optional-capability handling is implemented. Test exact RPC
or transport payloads, authentication, transient and permanent failures, rule
identity, replacement, repeated delete, both families, and action read-back.
Run against a pinned real daemon before calling the adapter supported. Record
router evidence separately and include restart/TTL behavior in the release gate.

The existing `gobgp` health field and `apipb` export remain compatibility
surfaces. They do not select the active backend. Operator-facing generic naming
and capability badges belong to the later compatibility stage.
