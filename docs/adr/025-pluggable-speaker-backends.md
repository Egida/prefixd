# ADR 025: Pluggable Speakers with rustbgpd as the Preferred Backend

## Status

Accepted. Backend rollout remains gated on the validation below.

Extends [ADR 023](023-rustbgpd-over-grpc.md) and updates
[ADR 001](001-gobgp-sidecar.md) and [ADR 007](007-trait-based-bgp-abstraction.md).
The transport decision does not require deleting the GoBGP integration.

## Date

2026-10-17

## Context

prefixd should work with the operator's chosen BGP daemon. rustbgpd is the
preferred first-party integration, and existing GoBGP deployments must continue
to work. Embedding rustbgpd's private runtime crates would couple policy and
protocol lifecycles to an unsupported library boundary. Its controller gRPC API
already supplies the operations prefixd needs.

The current four-method `FlowSpecAnnouncer` trait requires rule read-back and
peer observation. Both GoBGP and rustbgpd can satisfy it. A generic write-only
adapter cannot honestly return an empty RIB: reconciliation would continually
reannounce every desired rule. A durable announcement ledger is a prerequisite
for that class of backend.

## Decision

- Keep the BGP daemon in a separate process, controlled through an adapter.
  Peer configuration and routing policy remain the daemon's responsibility.
- Develop rustbgpd as the preferred backend. Keep GoBGP as a maintained,
  supported alternative, with its existing configuration and public protobuf
  export preserved during migration. Mock remains the test backend.
- Add rustbgpd behind `bgp-rustbgpd` and explicit runtime selection first.
  Existing defaults stay on GoBGP until deployment, restart, migration, and
  router interoperability checks pass. Preference does not establish parity.
- Reconcile rustbgpd against its retained **locally injected** rules, using
  `received_peer_address = "0.0.0.0"` and checking `received_view`. The selected
  Loc-RIB can hide a local rule behind a received candidate.
- Require authenticated, bounded daemon calls. The first transport is bearer
  TCP with verified server TLS for remote endpoints; plaintext is restricted to
  literal loopback addresses. UDS and client-certificate mTLS follow separately.
- Preserve the distinction between local mutation acceptance, committed
  advertisement, and remote installation. A successful RPC proves only the
  documented local mutation stage.
- Add optional reader/peer capabilities and durable reconciliation before
  enabling generic adapters. Report unsupported capabilities explicitly.
  Neither ledger state nor missing observation proves the daemon's actual RIB.

prefixd maintainers own the bundled rustbgpd and GoBGP adapters, their tests,
and security fixes. A community adapter needs a named maintainer and passing
conformance coverage before being described as supported. Implementation and qualification are separate: GoBGP is the existing backend,
rustbgpd is the preferred integration target, and generic/community adapters
require their own evidence. Vendor receipts apply only to the backend tested.

## Validation and rollout

Each supported backend needs lifecycle, idempotency, IPv4/IPv6, action-preserving
read-back, and error-path tests. Real daemon checks must cover restart recovery
and TTL withdrawal. Router qualification must separately verify the received
rule and action and, where claimed, traffic enforcement. Fake RPC servers and
mock repositories do not establish those properties.

Pin a released daemon for deployment evidence and record its image digest or
build identity. Review the vendored controller messages and contract on upgrade.
The scoped rustbgpd controller contract does not promote all FlowSpec features
or receive-side feasibility validation.

## Consequences

Operators can keep their speaker while prefixd gains another implementation of
the same policy boundary. Maintaining GoBGP requires continued CI and dependency
updates; changing the preferred backend does not remove that obligation.

Controller failure and speaker failure are separate events. A speaker can keep
advertising after prefixd exits; FlowSpec injection has no controller TTL lease.
Application TTLs require reconciliation to be running. See the corrected
[ADR 003](003-fail-open-ttl.md); crash cleanup needs an explicit mechanism and
evidence before it becomes a product guarantee.
