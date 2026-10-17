# Architecture

This document describes prefixd's design decisions and data flow.

## Overview

prefixd is a **policy daemon** that sits between attack detectors and BGP routers. It doesn't detect attacks or filter packets—it makes policy decisions about when and how to announce FlowSpec rules.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              prefixd                                        │
│                                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌──────────────┐   │
│  │  HTTP    │───▶│   Policy     │───▶│ Guardrails │───▶│  FlowSpec    │   │
│  │  API     │    │   Engine     │    │            │    │  Manager     │   │
│  └──────────┘    └──────────────┘    └────────────┘    └──────┬───────┘   │
│       │                │                   │                   │           │
│       │                │                   │                   │           │
│       ▼                ▼                   ▼                   ▼           │
│  ┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌──────────────┐   │
│  │ Events   │    │  Playbooks   │    │  Safelist  │    │   GoBGP      │   │
│  │   DB     │    │   (YAML)     │    │    DB      │    │   gRPC       │   │
│  └──────────┘    └──────────────┘    └────────────┘    └──────────────┘   │
│                                                                             │
│                        ┌──────────────────┐                                │
│                        │  Reconciliation  │                                │
│                        │      Loop        │                                │
│                        └──────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────────┘
         │                                                        │
         │                                                        │
         ▼                                                        ▼
┌─────────────────┐                                    ┌─────────────────┐
│    Detectors    │                                    │     Routers     │
│   (FastNetMon,  │                                    │   (Juniper,     │
│    Prometheus)  │                                    │    Arista)      │
└─────────────────┘                                    └─────────────────┘
```

## Design Principles

### 1. Signal-Driven, Not Detection

prefixd doesn't detect attacks. Detectors (FastNetMon, Prometheus alerts, custom scripts) signal attack events, and prefixd applies policy.

**Why?** Detection is hard and domain-specific. Rate-based detection misses low-and-slow attacks; ML-based detection has false positives. By separating detection from policy, you can:

- Use the best detector for each attack type
- Tune detection thresholds independently
- Correlate multiple weak signals (future: v1.5)

### 2. TTL Enforcement

If prefixd crashes or becomes unavailable:

- **Existing rules can remain advertised** while the separate speaker stays up
- **No new mitigations** are created (attacks may go unblocked)
- **Application TTL enforcement pauses** until reconciliation resumes

FlowSpec injection carries no controller expiry lease. Controller-crash cleanup
needs an explicit lease or coupled lifecycle; see [ADR 003](../adr/003-fail-open-ttl.md).

### 3. /32 Only (IPv4)

prefixd enforces that mitigations target single IPs (/32 for IPv4, /128 for IPv6). Broader prefixes are rejected.

**Why?** A misconfigured detector sending a /24 could block 256 IPs. With /32-only, the blast radius of a false positive is one IP.

### 4. Mandatory TTL

Every mitigation must have a TTL. There are no permanent rules.

**Why?** Without TTL, a false positive requires manual intervention. With TTL, false positives auto-resolve when the mitigation expires.

### 5. Guardrails Everywhere

Every mitigation passes through guardrails:

- Safelist check (is this IP protected?)
- Prefix length check (/32 only)
- TTL bounds check (min/max)
- Port count check (max 8)
- Quota check (per-customer, per-POP, global)

Guardrails can't be bypassed. They're the last line of defense against bad data.

---

## Data Flow

### Event Ingestion

```
POST /v1/events
     │
     ▼
┌─────────────────┐
│ Parse & Validate│───▶ 400 Bad Request
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Rate Limit Check│───▶ 429 Too Many Requests
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Safelist Check  │───▶ 403 Forbidden (safelisted)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Inventory Lookup│───▶ Find customer/service context
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Playbook Match  │───▶ Find policy for this vector
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Guardrails      │───▶ 422 Validation Failed
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Create/Extend   │───▶ Duplicate? Extend TTL
│ Mitigation      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Announce via    │───▶ GoBGP gRPC AddPath
│ GoBGP           │
└────────┬────────┘
         │
         ▼
     201 Created
```

### Reconciliation Loop

Runs every 30 seconds:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Reconciliation Loop                         │
│                                                                 │
│  1. Load desired state (active mitigations from DB)             │
│                         │                                       │
│                         ▼                                       │
│  2. Load actual state (FlowSpec routes from GoBGP RIB)          │
│                         │                                       │
│                         ▼                                       │
│  3. Find expired mitigations (TTL passed)                       │
│     └──▶ Withdraw from GoBGP                                   │
│     └──▶ Mark as "expired" in DB                               │
│                         │                                       │
│                         ▼                                       │
│  4. Find missing rules (in DB, not in RIB)                      │
│     └──▶ Re-announce via GoBGP                                 │
│                         │                                       │
│                         ▼                                       │
│  5. Find orphan rules (in RIB, not in DB)                       │
│     └──▶ Withdraw from GoBGP                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Why reconciliation?**

- GoBGP might restart, losing RIB state
- prefixd might restart, missing the window to withdraw
- Network issues might cause announcement failures
- Manual GoBGP CLI operations might create inconsistency

Reconciliation ensures desired state eventually matches actual state.

---

## Component Details

### Policy Engine

The policy engine evaluates playbooks to determine mitigation actions.

```yaml
# Playbook example
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 120
      - action: discard
        ttl_seconds: 300
        require_confidence_at_least: 0.8
```

**Evaluation order:**

1. Find playbook matching event vector
2. Check escalation eligibility (is there an existing mitigation?)
3. Select step based on confidence threshold
4. Apply port exclusions from inventory

### Guardrails

Guardrails are non-negotiable safety checks:

| Check | Rejection Reason |
|-------|------------------|
| `require_ttl` | TTL is mandatory |
| `min_ttl_seconds` | TTL below minimum |
| `max_ttl_seconds` | TTL above maximum |
| `dst_prefix_maxlen` | Prefix broader than /32 |
| `max_ports` | Too many ports (router memory) |
| `max_active_per_customer` | Customer quota exceeded |
| `max_active_per_pop` | POP quota exceeded |
| `max_active_global` | Global quota exceeded |
| Safelist | IP is protected |

### FlowSpec Manager

Translates mitigations into FlowSpec NLRI:

```
Mitigation                    FlowSpec NLRI
─────────────────────────────────────────────────
dst_prefix: 203.0.113.10/32   Type 1: Destination Prefix
protocol: UDP                 Type 3: IP Protocol
dst_ports: [!53]              Type 5: Destination Port (negated)
action: police 10M            Extended Community: traffic-rate
```

### GoBGP Client

gRPC client for GoBGP v4.x:

- **AddPath** - Announce FlowSpec rule
- **DeletePath** - Withdraw FlowSpec rule
- **ListPath** - Query RIB for reconciliation
- **ListPeer** - Monitor BGP session status

Features:
- Connection pooling
- Automatic retry with exponential backoff
- Timeout handling (10s connect, 30s request)

---

## State Management

### PostgreSQL Schema

```sql
-- Events (001 + 003)
CREATE TABLE events (
    event_id UUID PRIMARY KEY,
    external_event_id TEXT,
    source TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    victim_ip TEXT NOT NULL,
    vector TEXT NOT NULL,
    protocol INTEGER,
    bps BIGINT,
    pps BIGINT,
    top_dst_ports_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    raw_details JSONB,                          -- 003
    action TEXT NOT NULL DEFAULT 'ban',          -- 003
    UNIQUE(source, external_event_id)
);

-- Mitigations (001 + 005)
CREATE TABLE mitigations (
    mitigation_id UUID PRIMARY KEY,
    scope_hash TEXT NOT NULL,
    pop TEXT NOT NULL,
    customer_id TEXT,
    service_id TEXT,
    victim_ip TEXT NOT NULL,
    vector TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    match_json TEXT NOT NULL,
    action_type TEXT NOT NULL,
    action_params_json TEXT,
    status TEXT NOT NULL,                        -- pending, active, escalated, expired, withdrawn
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ,
    triggering_event_id UUID NOT NULL,
    last_event_id UUID NOT NULL,
    escalated_from_id UUID,
    reason TEXT,
    rejection_reason TEXT,
    acknowledged_at TIMESTAMPTZ,                 -- 005
    acknowledged_by TEXT                          -- 005
);

-- FlowSpec announcements (001)
CREATE TABLE flowspec_announcements (
    announcement_id UUID PRIMARY KEY,
    mitigation_id UUID NOT NULL REFERENCES mitigations(mitigation_id),
    pop TEXT NOT NULL,
    peer_name TEXT NOT NULL,
    peer_address TEXT NOT NULL,
    nlri_hash TEXT NOT NULL,
    nlri_json TEXT NOT NULL,
    action_json TEXT NOT NULL,
    status TEXT NOT NULL,
    announced_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    last_error TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);

-- Audit log (001)
CREATE TABLE audit_log (
    audit_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details_json TEXT NOT NULL
);

-- Safelist (001)
CREATE TABLE safelist (
    prefix TEXT PRIMARY KEY,
    added_at TIMESTAMPTZ NOT NULL,
    added_by TEXT NOT NULL,
    reason TEXT,
    expires_at TIMESTAMPTZ
);

-- Config snapshots (001)
CREATE TABLE config_snapshots (
    snapshot_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    config_hash TEXT NOT NULL,
    config_json TEXT NOT NULL
);

-- Operators (002)
CREATE TABLE operators (
    operator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    last_login_at TIMESTAMPTZ
);

-- Sessions (002) — tower-sessions-sqlx-store
CREATE TABLE tower_sessions.session (
    id TEXT PRIMARY KEY NOT NULL,
    data BYTEA NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL
);

-- Schema migrations (004)
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Notification preferences (006)
CREATE TABLE notification_preferences (
    operator_id UUID PRIMARY KEY REFERENCES operators(operator_id) ON DELETE CASCADE,
    muted_events TEXT[] NOT NULL DEFAULT '{}',
    quiet_hours_start SMALLINT,
    quiet_hours_end SMALLINT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Multi-POP Model

Multiple prefixd instances share one PostgreSQL:

```
prefixd (iad1)  ──┐
prefixd (fra1)  ──┼──▶ PostgreSQL
prefixd (sin1)  ──┘
```

Each instance:
- Filters by its own `pop` field
- Announces to its local GoBGP
- Has cross-POP visibility via `?pop=all`

---

## Security Model

### Authentication Layers

1. **Network level** - API should be on private network or behind load balancer
2. **Bearer token** - For API/CLI access
3. **Session cookie** - For dashboard access
4. **mTLS** - Optional mutual TLS for zero-trust environments

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ Trusted Zone                                                    │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                 │
│  │ prefixd  │◀──▶│ PostgreSQL│    │  GoBGP   │                 │
│  └──────────┘    └──────────┘    └──────────┘                 │
│       ▲                               │                        │
│       │                               ▼                        │
│       │                         ┌──────────┐                   │
│       │                         │  Routers │                   │
│       │                         └──────────┘                   │
└───────┼─────────────────────────────────────────────────────────┘
        │
        │ HTTPS + Auth
        │
┌───────┼─────────────────────────────────────────────────────────┐
│ Untrusted Zone                                                  │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                 │
│  │Detectors │    │Dashboard │    │   CLI    │                 │
│  └──────────┘    └──────────┘    └──────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key principle:** Detectors are untrusted. They can suggest mitigations, but guardrails have final say.

---

## Performance Characteristics

### Latency

| Operation | Typical | P99 |
|-----------|---------|-----|
| Event ingestion | <5ms | <20ms |
| Inventory lookup | <1μs | <10μs |
| DB query | <2ms | <10ms |
| GoBGP announce | ~10ms | ~50ms |

### Throughput

| Operation | Sustained | Burst |
|-----------|-----------|-------|
| Event ingestion | ~4,700/s | 10,000/s |
| DB writes | 2,000/s | 5,000/s |
| GoBGP announces | 100/s | 200/s |

### Bottleneck: GoBGP

GoBGP gRPC is the bottleneck for high-volume events. Each announcement requires:
- gRPC round-trip (~10ms)
- BGP UPDATE construction
- RIB insertion

For 1000+ mitigations/second, consider batching (not yet implemented).

---

## Failure Modes

### prefixd Crash

- Existing rules can persist while the speaker stays up; application TTL expiry
  resumes with reconciliation
- No new mitigations until restart
- Reconciliation syncs state on restart

### PostgreSQL Unavailable

- Event ingestion fails (503)
- Reconciliation pauses
- GoBGP rules remain (no withdrawal)

### GoBGP Unavailable

- Event ingestion fails at announcement step
- Mitigation saved to DB as "pending"
- Reconciliation retries on GoBGP recovery

### Router Crash

- GoBGP session drops
- Router recovers, re-establishes BGP
- GoBGP re-advertises routes
- No prefixd intervention required

---

## Future Architecture

### v1.5: Multi-Signal Correlation

```
FastNetMon  ──┐
Prometheus  ──┼──▶ Correlation ──▶ Policy Engine
Router CPU  ──┘    Engine
```

Combine weak signals into high-confidence decisions.

### v2.0: Native BGP Speaker

Replace GoBGP sidecar with embedded BGP:

```
prefixd ──── BGP ────▶ Routers
  │
  └── No GoBGP dependency
```

Reduces operational complexity but increases code complexity.

---

## Why These Choices?

### Why GoBGP sidecar instead of native BGP?

- **Time to market** - GoBGP is battle-tested
- **Flexibility** - GoBGP supports features we might need later
- **Debugging** - gobgp CLI is useful for troubleshooting
- **Risk isolation** - BGP bugs don't crash prefixd

### Why PostgreSQL instead of embedded DB?

- **Multi-POP** - Shared state across instances
- **Operational familiarity** - Teams know Postgres
- **Tooling** - pgAdmin, backups, monitoring
- **HA** - Postgres replication is well-understood

### Why Rust?

- **Performance** - Minimal latency in hot path
- **Safety** - No null pointers, no data races
- **Ecosystem** - Great async runtime (tokio), gRPC (tonic)
- **Binary size** - Single ~15MB binary, no runtime deps
