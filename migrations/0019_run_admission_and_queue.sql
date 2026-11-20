-- V1-10 migration 19 (ADR 0032): durable run admission and the fair PostgreSQL work queue.
-- Additive: no existing row changes. Runs written before this version, or by bare
-- `create_run`, keep NULL admission columns; they are never claimed and the first expiry
-- sweep fails them.

ALTER TABLE openmettle.runs
    ADD COLUMN actor_approval_id uuid REFERENCES openmettle.local_identity_approvals (id),
    ADD COLUMN round_limit integer CHECK (round_limit BETWEEN 1 AND 1000),
    ADD COLUMN queue_expires_at timestamptz,
    ADD COLUMN claim_token uuid,
    ADD COLUMN claimed_at timestamptz,
    ADD CONSTRAINT runs_admission_check CHECK (
        (actor_approval_id IS NULL) = (round_limit IS NULL)
        AND (round_limit IS NULL) = (queue_expires_at IS NULL)
        AND (queue_expires_at IS NULL OR queue_expires_at > created_at)),
    ADD CONSTRAINT runs_claim_check CHECK (
        (claim_token IS NULL) = (claimed_at IS NULL)
        AND (claim_token IS NULL OR queue_expires_at IS NOT NULL));

-- Each query repeats its index predicate verbatim so the planner can prove it.
CREATE INDEX runs_live_actor_idx ON openmettle.runs (actor_user_id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');
CREATE INDEX runs_live_scope_idx ON openmettle.runs (scope_id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');
CREATE INDEX runs_dispatch_idx ON openmettle.runs (state, created_at, id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');

-- One row serializes claims so the executing limits are exact. The inert guard column lets
-- the worker lock it without UPDATE on any meaningful column.
CREATE TABLE openmettle.run_dispatch_lock (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false)
);
INSERT INTO openmettle.run_dispatch_lock (id) VALUES (true);

-- The API writes the admission decision once with the run; the worker records its claim.
GRANT INSERT (actor_approval_id, round_limit, queue_expires_at) ON openmettle.runs
    TO openmettle_api;
GRANT UPDATE (claim_token, claimed_at) ON openmettle.runs TO openmettle_worker;
GRANT SELECT, UPDATE (lock_guard) ON openmettle.run_dispatch_lock TO openmettle_worker;
