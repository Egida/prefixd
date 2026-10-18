# Roadmap

prefixd's priority is reliable mitigation through a separate BGP speaker and a
clear operator workflow. Main may contain unreleased work; see the
[changelog](CHANGELOG.md) for release history and [features](FEATURES.md) for the
current product surface.

## Current baseline

Normal builds and the example deployment prefer rustbgpd. GoBGP remains an
explicit choice in the same controller image. Both adapters use the shared
writer and optional rule/peer observation boundary, with released-daemon CI,
dual-family peer tests and secure Compose profiles. See
[speaker backends](docs/reference/speaker-backends.md) and the
[dated profile qualification](docs/reference/qualification/speaker-profiles-2026-10-18.md)
for exact versions, checks and limits.

Desired mitigation intent is persisted before announcement; failed withdrawals
retain their original rule, actor and reason for retry. PostgreSQL, axum/sqlx,
the existing authentication modes and the repository boundary remain the runtime
baseline. The operator overview puts active mitigations, signals, observation
limits and expiry ahead of historical activity.

These controller and peer results do not establish vendor forwarding. TTL expiry
requires the running controller; a separate speaker can continue advertising
after prefixd stops.

## Near-term work

- Repair action-only drift as well as missing NLRI, with explicit ownership and
  acknowledgement semantics. Current reconciliation compares NLRI identity.
- Qualify router receipt and traffic enforcement separately for each tested
  backend, vendor, software version and topology. Preserve historical GoBGP
  results; qualify rustbgpd against FRR/Juniper and Arista/Cisco independently.
- Finish complete-list pagination and tied-timestamp cursor correctness, then
  verify the operator workflow at the tested scale and accessibility settings.
- Keep input validation, authentication, dependency audits and native lint gates
  strict. Address concrete findings without adding speculative configuration.
- Keep documentation and release guidance aligned with source. Exercise the
  quickstart from a clean environment and record its actual prerequisites and
  timing; retain failed runs and scope performance claims to dated receipts.

## Later work

ExaBGP and other write-only adapters need durable desired/acknowledged state and
verified restart replay before support can be claimed. An empty observed RIB
cannot stand in for unavailable observation. Additional integrations, match or
action types, telemetry and distributed coordination need a concrete operator
requirement and their own qualification.

[ADR 026](docs/adr/026-facelift-framework-scope.md) defers framework adoption.
Loco or an ORM migration is not a prerequisite for these changes.

prefixd remains a control-plane policy controller: packet scrubbing, detection
algorithms and L7/WAF analysis belong to other systems. Default guardrails reject
broad match-everything rules.

See [contributing](CONTRIBUTING.md) and the
[public issues](https://github.com/lance0/prefixd/issues) for ways to help.
