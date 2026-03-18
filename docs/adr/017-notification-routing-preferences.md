# ADR 017: Per-Destination Event Routing and Notification Preferences

## Status

Accepted

## Date

2026-03-18

## Context

### Per-Destination Event Routing

The alerting system has a single global `events` list that controls which event types are sent to webhooks. All destinations receive the same events. Operators want to route different event types to different destinations — for example, only page PagerDuty on `mitigation.created`, but send all events to a Slack channel for visibility.

### Notification Preferences

WebSocket toast notifications in the dashboard fire for every event with no way to mute or filter them. During active attack waves, the toast storm obscures the screen. Operators on night shifts want quiet hours where non-critical events are suppressed.

## Decisions

### 1. Per-destination events with global fallback

Each destination in the alerting config gains an optional `events` list. If present, only those event types are sent to that destination. If absent or empty, the destination inherits the global `events` list.

This is backward-compatible: existing configs with only a global `events` list continue to work unchanged. Operators adopt per-destination routing incrementally.

**Rejected alternative:** Clean break (remove global `events`, require per-destination). This would break all existing configs on upgrade for marginal benefit.

### 2. DB-backed notification preferences

Per-operator preferences are stored in a `notification_preferences` table keyed by `operator_id`. This persists across browsers and devices, and ties naturally to the existing operators table.

**Rejected alternative:** localStorage-only. Simpler but doesn't survive browser changes, and operators who work from multiple machines (NOC desktop + laptop) would need to configure twice.

### 3. Quiet hours suppress non-critical only

During quiet hours, `mitigation.created` and `mitigation.escalated` toasts still fire. Only lower-severity events (`mitigation.withdrawn`, `mitigation.expired`, `config.reloaded`, `guardrail.rejected`) are suppressed.

Rationale: a new mitigation at 3am means an active attack. Suppressing that notification defeats the purpose of the dashboard.

### 4. UTC-only quiet hours

Quiet hours are specified as UTC hour integers (0-23). No timezone support.

Rationale: NOC operators already think in UTC. Adding timezone support requires a timezone database dependency (chrono-tz or similar) and complicates the schema for negligible benefit.

### 5. Client-side toast filtering

The WebSocket feed continues to send all events to all connected clients. Filtering happens in the frontend `WebSocketProvider` based on the operator's cached preferences.

**Rejected alternative:** Server-side WS filtering (track per-connection preferences, filter before sending). This adds session state to the WebSocket handler, complicates reconnection logic, and provides no benefit since SWR cache invalidation must still happen regardless of toast visibility.

## Consequences

- **Alerting config schema** gains optional `events` per destination. Existing YAML configs remain valid.
- **Dispatch logic** changes from "check global events once" to "check per-destination events, fall back to global."
- **New table** (`notification_preferences`) with foreign key to `operators`. Operators without preferences get all toasts (safe default).
- **Frontend** adds a preferences panel and modifies `WebSocketProvider` to consult preferences before toasting.
- **No impact** on backend webhook delivery — notification preferences control UI toasts only.
