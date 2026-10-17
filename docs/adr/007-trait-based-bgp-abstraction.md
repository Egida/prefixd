# ADR 007: Trait-Based BGP Abstraction for Testing

## Status

Accepted

## Date

2026-01-15

## Context

The policy engine and reconciliation loop need to announce and withdraw FlowSpec rules via BGP. Testing these components against a real GoBGP instance would make tests slow, flaky, and require a running GoBGP container.

## Decision

Keep `Arc<dyn FlowSpecAnnouncer>` as the selected-speaker facade, with required
writing and optional observation (updated October 2026):

```rust
#[async_trait]
pub trait FlowSpecWriter: Send + Sync {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()>;
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()>;
}

#[async_trait]
pub trait FlowSpecReader: Send + Sync {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>>;
}

#[async_trait]
pub trait PeerObserver: Send + Sync {
    async fn session_status(&self) -> Result<Vec<PeerStatus>>;
}

pub trait FlowSpecAnnouncer: FlowSpecWriter {
    fn backend(&self) -> &'static str;
    fn reader(&self) -> Option<&dyn FlowSpecReader> { None }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> { None }
}
```

The traits live in `src/bgp/announcer.rs`; `Result` is `crate::error::Result`.
Announcement is a retry-safe upsert, withdrawal is idempotent, and success only
acknowledges the backend's local mutation stage. Observer availability is derived
from accessors, never inferred from an empty response or a failed RPC. Implementing
an observer requires explicit opt-in; test wrappers expose themselves so faults
and barriers remain visible.

Without rule observation, the scheduler preserves desired inventory validation,
status gauges, TTL expiry and pending cleanup, but skips repairs. Supported read
errors fail reconciliation. Peer observation errors retain last successful metrics;
unsupported observation skips those updates. Existing adapters expose both observers.
A production write-only backend still requires a durable announcement ledger.

Implementations:
- `GoBgpAnnouncer` — GoBGP gRPC client (the shipped backend, ADR 001)
- `RustBgpdAnnouncer` — experimental gRPC adapter behind `bgp-rustbgpd` ([ADR 023](023-rustbgpd-over-grpc.md))
- `MockAnnouncer` — in-memory store for tests, records all calls

## Consequences

**Positive:**
- Unit tests run in milliseconds without any external dependencies
- Can verify exact announcement/withdrawal sequences
- Policy engine tests don't depend on BGP protocol details
- Integration tests can use the real `GoBgpAnnouncer` against GoBGP in Docker
- Easy to add future implementations (native speaker, BIRD adapter)

**Negative:**
- Mock may not capture all GoBGP quirks (e.g., NLRI encoding edge cases)
- Must keep trait interface in sync with what GoBGP actually supports
- Two code paths means bugs could exist in `GoBgpAnnouncer` that `MockAnnouncer` doesn't surface

**Mitigation:**
- Lab testing with real routers (FRR, cJunosEvolved) validates the full path
- Integration tests in CI use testcontainers for GoBGP
