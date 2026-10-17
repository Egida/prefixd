-- Preserve requested deletion across ambiguous speaker replies and controller restarts.
CREATE TABLE IF NOT EXISTS withdrawal_requests (
    operation_id UUID PRIMARY KEY,
    mitigation_id UUID NOT NULL UNIQUE REFERENCES mitigations(mitigation_id),
    pop TEXT NOT NULL,
    nlri_hash TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    mitigation_updated_at TIMESTAMPTZ NOT NULL,
    terminal_status TEXT NOT NULL CHECK (terminal_status IN ('withdrawn', 'expired')),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('operator', 'detector', 'system')),
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_pending
    ON withdrawal_requests(pop) WHERE completed_at IS NULL;

-- Earlier instances of this migration did not record the originating mode.
ALTER TABLE withdrawal_requests
    ADD COLUMN IF NOT EXISTS speaker_delete_required BOOLEAN NOT NULL DEFAULT TRUE;
