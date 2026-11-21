-- V1-11 (ADR 0033). Existing claims have no deadlines and are due for settlement.
ALTER TABLE openmettle.runs
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN execution_expires_at timestamptz,
    ADD COLUMN cancel_reason text CHECK (cancel_reason IN ('requested', 'revoked')),
    ADD CONSTRAINT runs_lease_check CHECK (
        (execution_expires_at IS NULL OR claim_token IS NOT NULL)
        AND (lease_expires_at IS NULL
             OR (execution_expires_at IS NOT NULL AND lease_expires_at <= execution_expires_at))),
    ADD CONSTRAINT runs_cancelling_check CHECK (state <> 'cancelling' OR cancel_reason IS NOT NULL);

GRANT UPDATE (lease_expires_at, execution_expires_at, cancel_reason) ON openmettle.runs
    TO openmettle_worker;
GRANT UPDATE (cancel_reason) ON openmettle.runs TO openmettle_api;
