# ADR 003: Fail-Open Design with Mandatory TTLs

## Status

Accepted

## Date

2026-01-15

## Context

A DDoS mitigation system that fails closed (leaves rules permanently installed) is more dangerous than one that fails open (rules expire). If prefixd crashes, loses its database, or has a bug in rule management, permanent FlowSpec rules could:

- Block legitimate traffic indefinitely
- Cause customer outages that outlast the original attack
- Require manual router intervention to clear

## Decision

All mitigations **must** have a TTL. The running reconciliation loop enforces
expiry by asking the speaker to withdraw the rule. The TTL is application
state; it is not a lease encoded in the FlowSpec rule.

Corrected 2026-10-17: prefixd and its BGP speaker are separate processes.
prefixd exiting does not close GoBGP's or rustbgpd's router sessions. Rules can
remain installed while the controller is down. Automatic cleanup after a
controller crash requires an explicit lease or coupled-lifecycle mechanism;
neither is provided by the current deployment.

The safety chain:
1. **Application TTL** - prefixd expires mitigations and sends withdrawals
2. **Speaker session loss** - A speaker failure can clear routes through BGP
   session teardown; configured Graceful Restart retention can delay removal.
   This does not cover an independent controller failure.
3. **Operator withdrawal** - `prefixdctl mitigations withdraw <id>` for manual override

## Consequences

**Positive:**
- Active reconciliation withdraws mitigations whose TTL has elapsed
- Speaker and controller failures have separate recovery requirements
- Running reconciliation attempts TTL withdrawals; failed cleanup needs explicit recovery and tests

**Negative:**
- Long-running mitigations need periodic extension (detectors must re-send events)
- Short TTLs increase event volume; long TTLs delay cleanup
- No "permanent safelist via FlowSpec" use case (use router static config instead)
- Controller downtime suspends application TTL enforcement; restore
  reconciliation or explicitly withdraw rules from the speaker.
