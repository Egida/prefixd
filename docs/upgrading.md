# Upgrade Guide

## General Principles

- **Database migrations run automatically** on startup. No manual SQL required.
- **Config files are backward compatible.** New fields have sensible defaults; old configs continue to work.
- **Mitigations survive restarts.** Active mitigations are stored in PostgreSQL and re-announced by the reconciliation loop after startup.
- **Always back up the database** before upgrading.

---

## Docker Compose Upgrade

```bash
# 1. Back up the database
docker compose exec postgres pg_dump -U prefixd prefixd > backup-$(date +%F).sql

# 2. Pull latest code
git pull origin main

# 3. Rebuild containers
docker compose build

# 4. Restart (prefixd applies migrations on startup)
docker compose up -d

# 5. Verify
curl http://localhost/v1/health
docker compose logs prefixd | grep "database migrations applied"
```

### Zero-Downtime Upgrade

For environments where downtime is unacceptable:

1. Build the new image while the old one is running
2. Run `docker compose up -d --no-deps prefixd` to replace only the prefixd container
3. The reconciliation loop will re-announce any rules within 30 seconds
4. Active mitigations are not affected (fail-open: GoBGP retains routes until explicitly withdrawn)

---

## Bare Metal Upgrade

```bash
# 1. Back up the database
pg_dump -U prefixd prefixd > backup-$(date +%F).sql

# 2. Build new version
git pull origin main
cargo build --release

# 3. Stop the daemon
sudo systemctl stop prefixd

# 4. Install new binary
sudo cp target/release/prefixd /usr/local/bin/
sudo cp target/release/prefixdctl /usr/local/bin/

# 5. Start (migrations run automatically)
sudo systemctl start prefixd

# 6. Verify
prefixdctl status
prefixdctl migrations
```

---

## Rollback

If an upgrade causes issues:

### Docker Compose

```bash
# Check out the previous version
git checkout v0.8.5  # or whatever the previous tag was

# Restore database (if migration changed schema)
docker compose exec -T postgres psql -U prefixd prefixd < backup-2026-02-20.sql

# Rebuild and restart
docker compose build
docker compose up -d
```

### Bare Metal

```bash
# Stop
sudo systemctl stop prefixd

# Restore database backup
psql -U prefixd prefixd < backup-2026-02-20.sql

# Install previous binary
sudo cp /path/to/previous/prefixd /usr/local/bin/

# Start
sudo systemctl start prefixd
```

> **Important:** Database migrations are forward-only. If a migration altered the schema, you must restore from backup to roll back. Migrations that only add tables or columns (using `IF NOT EXISTS`) are safe to roll back without a restore.

---

## Checking Migration Status

After an upgrade, confirm all migrations applied:

```bash
# CLI
prefixdctl migrations

# Expected output:
# VERSION   NAME                            APPLIED AT
# -----------------------------------------------------------------
# 1         initial                         2026-01-15 10:00:00
# 2         operators_sessions              2026-01-15 10:00:00
# 3         raw_details                     2026-01-28 12:00:00
# 4         schema_migrations               2026-02-20 10:00:00
# 5         acknowledge                     2026-03-18 14:37:00
#
# 5 migration(s) applied
```

---

## Version-Specific Notes

### v0.11.0 -> Next (Unreleased)

- **Breaking: Offset pagination removed.** `GET /v1/mitigations`, `GET /v1/events`, and `GET /v1/audit` no longer accept the `offset` query parameter. Use cursor-based pagination instead (`?cursor=<value>&limit=N`). Responses now include `next_cursor` and `has_more` fields. See [ADR 016](adr/016-cursor-pagination.md).
- **Breaking: Audit response shape changed.** `GET /v1/audit` now returns `{"entries": [...], "count": N, "next_cursor": ..., "has_more": ...}` instead of a bare array.
- **New migration (005):** Adds `acknowledged_at` and `acknowledged_by` columns to mitigations table. Runs automatically on startup. Uses `IF NOT EXISTS` so safe to re-run.
- **New endpoint:** `POST /v1/mitigations/acknowledge` for bulk acknowledging mitigations.
- **New query params:** `?start=`, `?end=` (ISO 8601) for date range filtering on all list endpoints. `?acknowledged=true|false` on mitigations.
- **New dependency:** `base64` crate added for cursor encoding.
- **Frontend:** API hooks now return response objects (`{mitigations, count, next_cursor, has_more}`) instead of bare arrays. If you have custom frontend code consuming these hooks, update accordingly.
- **prefixdctl:** If you have scripts using `--offset`, they need to be updated to use `--cursor` or omit for the first page.
- **New migration (006):** Adds `notification_preferences` table for per-operator toast settings. Runs automatically. FK to `operators` table.
- **Per-destination event routing:** Alerting destinations now accept an optional `events` array to override the global event filter. Existing configs without per-destination events are unaffected (backward-compatible, see ADR 017).
- **New endpoint:** `GET/PUT /v1/preferences` for notification preferences (muted events, quiet hours).
- No config file changes required.

### v0.10.1 -> v0.11.0

- **CVE gate in CI:** `cargo audit` and `bun audit` now gate Docker publishing. CycloneDX SBOM generated on version tags.
- **Vendor capability matrix:** New `docs/vendors.md`.
- **Security fixes:** Next.js 16.1.7, undici 7.24.4, quinn-proto 0.11.14, rollup 4.59.0.
- **New features:** Bulk withdraw (`POST /v1/mitigations/withdraw`), FlowSpec rule preview on mitigation detail page.
- No database migrations required.
- No breaking API changes.

### v0.10.0 -> v0.10.1

- **FastNetMon integration fix:** Deterministic event IDs replaced with UUIDs. Unban now queries `GET /v1/mitigations?victim_ip=X` then withdraws, instead of constructing a deterministic ID.
- **New query param:** `victim_ip` on `GET /v1/mitigations`.
- No database migrations required.

### v0.9.1 -> v0.10.0

- **Playbook editor:** New `PUT /v1/config/playbooks` endpoint (admin-only). Config page now has form-based and raw YAML editors for playbooks. Playbooks are saved with atomic write + `.bak` backup.
- **Interactive alerting config:** New `PUT /v1/config/alerting` endpoint (admin-only). Alerting configuration moved from `prefixd.yaml` to standalone `alerting.yaml` (backward-compatible fallback). Config page alerting tab now supports add/edit/remove destinations with type-specific forms. Secrets preserved via `***` sentinel on update.
- **SSRF protection:** Webhook destination URLs now require HTTPS and reject localhost/private IPs.
- **Event cross-links:** Mitigation detail page shows clickable triggering and last event links.
- **GHCR publishing:** CI publishes Docker images to `ghcr.io` on push to main and version tags.
- No database migrations required
- No breaking API changes

### v0.9.0 -> v0.9.1

- **Security fixes:** Login brute-force throttle hardened (atomic check, bounded state), CIDR validation uses `ipnet::IpNet`, generic webhook headers redacted in API, alerting test endpoint admin-only, CSV formula regex strengthened
- **Webhook alerting:** New `src/alerting/` module with 7 destination types (Slack, Discord, Teams, Telegram, PagerDuty, OpsGenie, generic). Fire-and-forget dispatch with bounded concurrency (64 tasks). New endpoints: `GET /v1/config/alerting`, `POST /v1/config/alerting/test`
- **Dashboard:** Alerting config tab, audit log detail expansion, customer/POP filters, timeseries range selector (1h/6h/24h/7d), active count sidebar badge, severity badges
- **New config section:** Optional `alerting:` in prefixd.yaml (see example in config file)
- No database migrations required
- No breaking API changes

### v0.8.5 -> v0.9.0

- **New table:** `schema_migrations` (migration 004) -- tracks applied migrations
- **Reconciliation loop** now pages through all active mitigations (previously capped at 1000)
- **New metrics:** `prefixd_reconciliation_active_count`, `prefixd_db_pool_connections`
- **New endpoints:** `GET /v1/stats/timeseries`, `GET /v1/ip/{ip}/history`
- **prefixdctl default endpoint** changed from `http://127.0.0.1:8080` to `http://127.0.0.1` (nginx)
- **Timeseries bucketing fix** -- sub-hour buckets now align correctly
- No config file changes required
