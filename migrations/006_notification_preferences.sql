CREATE TABLE IF NOT EXISTS notification_preferences (
    operator_id UUID PRIMARY KEY REFERENCES operators(operator_id) ON DELETE CASCADE,
    muted_events TEXT[] NOT NULL DEFAULT '{}',
    quiet_hours_start SMALLINT,
    quiet_hours_end SMALLINT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
