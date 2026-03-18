# ADR 016: Cursor-Based Pagination (Replacing Offset)

## Status

Accepted

## Date

2026-03-18

## Context

All list endpoints (`GET /v1/mitigations`, `GET /v1/events`, `GET /v1/audit`) used offset-based pagination (`?limit=100&offset=200`). This has well-known problems at scale:

1. **Drifting windows** — When new rows are inserted between page fetches, offset-based queries skip or duplicate rows. During an active attack, mitigations are created continuously, making offset pagination unreliable for operators paging through results.

2. **O(n) cost** — PostgreSQL must scan and discard `offset` rows before returning results. Page 100 of 100-row pages requires scanning 10,000 rows. This becomes a performance problem as the mitigations table grows.

3. **No stable reference** — Offsets are positional, not stable. A client cannot bookmark "where I left off" across requests if the underlying data changes.

Cursor-based pagination solves all three: the cursor is a stable reference to a specific row's timestamp, the database seeks directly to that position via an indexed `WHERE` clause, and insertions don't affect the cursor's position.

## Decision

Replace offset-based pagination with cursor-based pagination on all three list endpoints. This is a **breaking change** — the `offset` query parameter is removed entirely rather than supported alongside cursors during a transition period.

### Cursor encoding

The cursor is a base64-encoded RFC 3339 timestamp of the ordering column:

| Endpoint | Ordering column | Example cursor (decoded) |
|---|---|---|
| `GET /v1/mitigations` | `created_at` | `2026-03-18T12:00:00Z` |
| `GET /v1/events` | `ingested_at` | `2026-03-18T12:00:00Z` |
| `GET /v1/audit` | `timestamp` | `2026-03-18T12:00:00Z` |

### Query mechanics

```sql
-- First page (no cursor)
SELECT ... FROM mitigations
WHERE (filters)
ORDER BY created_at DESC
LIMIT $limit + 1

-- Subsequent pages
SELECT ... FROM mitigations
WHERE (filters) AND created_at < $cursor
ORDER BY created_at DESC
LIMIT $limit + 1
```

Fetching `limit + 1` rows determines `has_more` without a separate COUNT query. The extra row is not returned to the client.

### Response shape

All three endpoints gain `next_cursor` and `has_more` fields:

```json
{
  "mitigations": [...],
  "count": 20,
  "next_cursor": "MjAyNi0wMy0xOFQxMjowMDowMFo=",
  "has_more": true
}
```

- `next_cursor` is `null` when there are no more pages.
- `has_more` is a convenience boolean so clients don't need to check for null.
- First request omits the `cursor` parameter to get the most recent page.

### Why not both?

Supporting both `offset` and `cursor` during a transition period was considered and rejected:

- No known external consumers depend on offset pagination today — the API is pre-v1.0.
- Dual support adds handler complexity (which mode? what if both are provided?).
- Offset encourages patterns we want to discourage (deep pagination in automation scripts).
- A clean break now avoids a deprecation cycle that delays the inevitable.

## Consequences

- **Breaking** — Clients sending `?offset=N` will receive an error or have the parameter ignored. Documented in CHANGELOG as a breaking change.
- **Frontend** — Page number navigation replaced with cursor stack (push on "Next", pop on "Previous"). Selecting a new filter or date range resets the cursor.
- **prefixdctl** — The `list` subcommands switch from `--offset` to `--cursor` (or omit for first page).
- **Performance** — Deep pagination cost drops from O(offset + limit) to O(limit). All ordering columns are already indexed.
- **Consistency** — All new list endpoints must follow this pattern. No future endpoint should use offset.
