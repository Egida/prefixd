# ADR 018: Multi-Signal Correlation Engine

## Status

Accepted

Current implementation note: the unused policy `EventCorrelator` prototype and
ineffective `timers.correlation_window_seconds` setting were removed. Event
ingestion handles runtime deduplication and TTL extension; the active multi-signal
engine uses `correlation.window_seconds`. The decision below records the original
design context.

## Date

2026-03-19

## Context

prefixd currently treats each detector event independently: a single `POST /v1/events` creates a mitigation if it passes guardrails and matches a playbook. This works well for high-confidence detectors like FastNetMon in ban mode, but creates two problems:

1. **Low-confidence signals go to waste.** A telemetry-based alert at 0.5 confidence is too weak to act on alone, even though it carries useful information. If two independent sources both flag the same victim and vector, the combined evidence is much stronger than either signal alone.

2. **No corroboration path.** Operators who integrate multiple detection sources (NetFlow analyzers, Alertmanager rules, FastNetMon, manual reports) have no way to require agreement between sources before triggering a mitigation. They either set low thresholds (false positives) or high thresholds (missed attacks).

The correlation engine addresses this by grouping related signals within a configurable time window and computing a weighted confidence score across sources. Corroboration — requiring a minimum number of distinct sources — becomes an optional, per-playbook policy lever.

### Alternatives Considered

1. **Client-side aggregation.** Have detectors pre-aggregate before calling the API. Rejected because it pushes complexity to every integration and prevents cross-source corroboration.

2. **Event deduplication only.** Extend the existing `EventCorrelator` (scope-matching by ports) to track sources. Rejected because scope-matching serves a different purpose (extending TTL on same-scope mitigations) and conflating the two concepts makes both harder to reason about.

3. **External stream processor (Kafka/Flink).** Powerful but introduces significant operational complexity for what is fundamentally a small-cardinality grouping problem (unique victim_ip × vector × time window). The in-process approach keeps the deployment simple.

## Decision

### 1. Time-windowed grouping by (victim_ip, vector)

When an event arrives with correlation enabled, the engine looks for an existing **signal group** with matching `(victim_ip, vector)` whose window has not yet expired. If found, the event joins that group. If not, a new group is created with `window_expires_at = now + correlation.window_seconds`.

This is the simplest grouping key that captures "multiple sources agreeing about the same attack." Port-level granularity is deliberately omitted from grouping — different detectors may report different top ports for the same DDoS vector, and requiring port-exact matches would defeat corroboration.

### 2. Weighted confidence aggregation

Each signal source has a configurable weight (default 1.0). The derived confidence for a signal group is the weighted average:

```
derived_confidence = Σ(event_confidence_i × source_weight_i) / Σ(source_weight_i)
```

This allows operators to express trust levels: a FastNetMon ban (weight 2.0) contributes more to derived confidence than a Prometheus alert rule (weight 0.8).

### 3. Optional corroboration with backward compatibility

The `min_sources` parameter (default 1) controls how many distinct sources must contribute before a signal group can trigger a mitigation:

- **min_sources=1** (default): A single event from any source can trigger a mitigation if its confidence meets the threshold. This preserves current behavior — existing deployments see no change.
- **min_sources=2+**: Requires corroboration. A single source's event is recorded in the signal group but does not trigger a mitigation until additional sources confirm.

Per-playbook overrides allow operators to require corroboration for some vectors (e.g., UDP floods from noisy detectors) while keeping single-source triggering for others (e.g., SYN floods from a trusted detector).

### 4. Integration point: between event storage and policy evaluation

The correlation step is inserted after the event is persisted (ensuring no data loss) and before policy evaluation (ensuring corroboration is checked before any mitigation decision). When correlation is disabled (`enabled: false`), this step is skipped entirely — the code path is identical to v0.13.0.

### 5. Database-backed signal groups

Signal groups are stored in PostgreSQL (`signal_groups` and `signal_group_events` tables) rather than in-memory. This ensures:

- Groups survive prefixd restarts during the correlation window.
- The reconciliation loop can expire stale groups.
- Multiple prefixd instances (future) share the same group state.
- Full auditability of which events contributed to each mitigation decision.

A nullable `signal_group_id` column on the `mitigations` table links each mitigation to the signal group that triggered it, enabling end-to-end explainability.

### 6. Configuration in prefixd.yaml with hot-reload

Correlation configuration lives in the main `prefixd.yaml` under a `correlation:` section. Using `#[serde(default)]` ensures omitting the section entirely produces a disabled (backward-compatible) config. Configuration changes are picked up on `POST /v1/config/reload` without restarting the daemon.

## Consequences

### Positive

- Operators can combine weak signals from multiple detectors into high-confidence mitigation decisions.
- Backward compatible: existing single-detector deployments work unchanged (min_sources=1, correlation disabled by default).
- Per-playbook overrides give fine-grained control over which attack vectors require corroboration.
- Database-backed groups provide full auditability and survive restarts.
- Weighted confidence lets operators tune trust levels per detection source.

### Negative

- Adds latency to the ingestion path when correlation is enabled (database lookup for existing group + insert/update). Mitigated by indexes on `(victim_ip, vector, status)`.
- Increases database write volume (one signal_group_events row per event). Acceptable given the expected event rates (tens to low hundreds per minute).
- When min_sources > 1, there is a window where an attack is detected but not yet mitigated (waiting for corroboration). Operators must understand this trade-off.

### Neutral

- The existing `EventCorrelator` in `src/policy/correlation.rs` (scope-matching) remains unchanged. It serves a different purpose (TTL extension for same-scope mitigations) and operates independently of multi-signal correlation.
- Signal group expiry is handled by the existing reconciliation loop, adding minimal new complexity to the scheduler.
