# ADR 026: Defer Framework Migration During the Facelift

## Status

Accepted. Updates the scheduling decision in
[ADR 024](024-loco-staged-migration.md).

## Date

2026-10-17

## Context

The facelift must make rustbgpd the primary speaker, retain selectable GoBGP
and ExaBGP, and give operators a clear mitigation workflow. Existing adapters,
configuration, authentication, PostgreSQL repositories and reconciliation already
provide seams for this work.

The announcement ledger currently has a schema but no runtime implementation.
Some mutation paths call the speaker before persisting desired state. Recovery
therefore needs explicit durable intent, pending cleanup and acknowledgement
semantics before a write-only speaker can be supported safely.

Adding framework boot, configuration and ORM migrations at the same time would
change those boundaries without resolving a speaker requirement. Historical
framework estimates and dependency versions in ADR 024 are not a current
compatibility assessment.

## Decision

Defer Loco adoption throughout this facelift. Preserve the earlier eventual
adoption decision as recorded intent; this changes its scheduling rather than
silently cancelling it.

- Keep axum, sqlx, PostgreSQL, `RepositoryTrait`, current authentication,
  configuration loading and reconciliation as the runtime baseline.
- Add no Loco dependency, ORM migration or framework-driven MSRV change in
  this work. Establish the actual supported Rust baseline independently.
- Split oversized handlers only through behavior-preserving resource modules,
  separately from changes to persistence or speaker semantics.
- Implement required durable announcement recovery and, when justified,
  durable alert delivery through the existing storage boundary.
- Keep [ADR 009](009-postgresql-over-sqlite.md) operative, including its current
  storage abstraction decision; the deferred ORM migration has not superseded it.

Before resuming framework adoption, require a separate proposal identifying a
concrete unmet requirement, verified release/dependency/MSRV choices, bounded
scope, and parity checks for API routes, sessions/roles, WebSockets, metrics,
configuration reload, the CLI and recovery.

## Consequences

Speaker portability, engineering gates and the operator UI can be delivered
without a simultaneous runtime rewrite. The existing architecture still needs
smaller modules, explicit errors and reliable durable mutations; deferral does
not remove those obligations.

Framework conveniences remain unavailable until separately justified. This
decision establishes implementation scope, not a claim that the new speaker
defaults, ledger, deployment profiles or UI have already shipped.
