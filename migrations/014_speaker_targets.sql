-- Stable, credential-free target identities. Assignment is separate so an
-- explicitly drained transfer can preserve old immutable operation references.
CREATE TABLE IF NOT EXISTS speaker_targets (
    target_id UUID PRIMARY KEY,
    backend TEXT NOT NULL CHECK (backend IN ('gobgp', 'rustbgpd', 'mock')),
    endpoint TEXT NOT NULL,
    routing_namespace TEXT NOT NULL CHECK (routing_namespace = 'GLOBAL'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (backend, endpoint, routing_namespace)
);

CREATE TABLE IF NOT EXISTS speaker_pop_bindings (
    pop TEXT PRIMARY KEY,
    target_id UUID NOT NULL UNIQUE REFERENCES speaker_targets(target_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Existing requests remain unbound until explicit original-target adoption.
-- Replaying migrations must never infer ownership or create acknowledgements.
ALTER TABLE withdrawal_requests
    ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES speaker_targets(target_id);

CREATE OR REPLACE FUNCTION preserve_speaker_target_identity() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'speaker target identities are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER speaker_target_identity_immutable
    BEFORE UPDATE ON speaker_targets
    FOR EACH ROW EXECUTE FUNCTION preserve_speaker_target_identity();

CREATE OR REPLACE FUNCTION preserve_withdrawal_target() RETURNS trigger AS $$
BEGIN
    IF OLD.target_id IS NOT NULL AND NEW.target_id IS DISTINCT FROM OLD.target_id THEN
        RAISE EXCEPTION 'withdrawal target is immutable once bound';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER withdrawal_target_immutable
    BEFORE UPDATE OF target_id ON withdrawal_requests
    FOR EACH ROW EXECUTE FUNCTION preserve_withdrawal_target();
