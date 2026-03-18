-- Add acknowledge tracking to mitigations
ALTER TABLE mitigations ADD COLUMN acknowledged_at TIMESTAMPTZ;
ALTER TABLE mitigations ADD COLUMN acknowledged_by TEXT;

CREATE INDEX IF NOT EXISTS idx_mitigations_ack
    ON mitigations(acknowledged_at)
    WHERE acknowledged_at IS NULL;
