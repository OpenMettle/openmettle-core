-- Outstanding browser-login admission (ADR 0014). One operator-owned limit on unexpired login
-- rows that have no issued session. This is an outstanding-work cap: it is not a rate limit,
-- a request/concurrency control or a bound on retained nonce reservations or expired rows.
-- NULL refuses every login initiation until the owner configures a value. The ceiling is an
-- implementation bound, not a deployment default.
CREATE TABLE openmettle.login_admission (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    outstanding_limit integer CHECK (outstanding_limit BETWEEN 1 AND 65536),
    lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false),
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL CHECK (octet_length(changed_by) BETWEEN 1 AND 128),
    change_reason text NOT NULL CHECK (octet_length(change_reason) BETWEEN 1 AND 512)
);
INSERT INTO openmettle.login_admission (id, outstanding_limit, changed_at, changed_by, change_reason)
    VALUES (true, NULL, clock_timestamp(), 'migration-9', 'unconfigured; login initiation refused');
-- Bounded count of outstanding rows for each initiation, consumed rows included.
CREATE INDEX login_transactions_outstanding_idx
    ON openmettle.login_transactions (expires_ms) WHERE NOT session_issued;
-- The API reads the limit and may lock the row through the constrained guard column only.
GRANT SELECT ON openmettle.login_admission TO openmettle_api;
GRANT UPDATE (lock_guard) ON openmettle.login_admission TO openmettle_api;
