-- Local identity approval and opaque sessions only. No invitation delivery or provisioning.
-- All monotonic generation changes and retirement are owner/application protocols (ADR 0013).
ALTER TABLE openmettle.login_providers
    ADD COLUMN lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false),
    ADD COLUMN access_generation bigint NOT NULL DEFAULT 0 CHECK (access_generation >= 0),
    ADD COLUMN changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN changed_by text NOT NULL DEFAULT 'migration-8' CHECK (octet_length(changed_by) BETWEEN 1 AND 128),
    ADD COLUMN change_reason text NOT NULL DEFAULT 'initial session authority' CHECK (octet_length(change_reason) BETWEEN 1 AND 512);
-- Migration provenance applies only to rows that existed at upgrade. New providers must
-- supply their real operator provenance; no permanent migration author default.
ALTER TABLE openmettle.login_providers
    ALTER COLUMN changed_by DROP DEFAULT,
    ALTER COLUMN change_reason DROP DEFAULT;
ALTER TABLE openmettle.users
    ADD COLUMN session_generation bigint NOT NULL DEFAULT 0 CHECK (session_generation >= 0);
-- Table-wide INSERT on users remains for compatibility. Generation initialization and
-- monotonic UPDATE are trusted API protocols, not protection against arbitrary API SQL.
ALTER TABLE openmettle.login_transactions
    ADD COLUMN session_issued boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT login_session_consumed_check CHECK (NOT session_issued OR consumed);

CREATE TABLE openmettle.local_identity_approvals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id uuid NOT NULL REFERENCES openmettle.login_providers(id),
    identity_id uuid NOT NULL REFERENCES openmettle.user_identities(id),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    access_generation bigint NOT NULL DEFAULT 0 CHECK (access_generation >= 0),
    active boolean NOT NULL,
    expires_ms bigint NOT NULL CHECK (expires_ms > 0),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    changed_by text NOT NULL CHECK (octet_length(changed_by) BETWEEN 1 AND 128),
    change_reason text NOT NULL CHECK (octet_length(change_reason) BETWEEN 1 AND 512),
    lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false),
    UNIQUE (provider_id, identity_id),
    UNIQUE (id, provider_id, identity_id)
);
CREATE TABLE openmettle.local_sessions (
    id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    login_id text NOT NULL UNIQUE REFERENCES openmettle.login_transactions(id),
    provider_id uuid NOT NULL REFERENCES openmettle.login_providers(id),
    identity_id uuid NOT NULL REFERENCES openmettle.user_identities(id),
    approval_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES openmettle.users(id),
    issued_client text NOT NULL CHECK (octet_length(issued_client) BETWEEN 1 AND 255),
    issued_epoch bigint NOT NULL REFERENCES openmettle.login_provider_revisions(epoch),
    issued_revision bigint NOT NULL CHECK (issued_revision > 0),
    provider_generation bigint NOT NULL CHECK (provider_generation >= 0),
    approval_generation bigint NOT NULL CHECK (approval_generation >= 0),
    user_generation bigint NOT NULL CHECK (user_generation >= 0),
    created_ms bigint NOT NULL CHECK (created_ms > 0),
    expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
    revoked boolean NOT NULL DEFAULT false,
    FOREIGN KEY (approval_id, provider_id, identity_id)
        REFERENCES openmettle.local_identity_approvals(id, provider_id, identity_id)
);
CREATE INDEX local_sessions_user_idx ON openmettle.local_sessions(user_id, id);
CREATE INDEX local_sessions_expiry_idx ON openmettle.local_sessions(expires_ms, id);
GRANT UPDATE (lock_guard) ON openmettle.login_providers TO openmettle_api;
GRANT UPDATE (session_generation) ON openmettle.users TO openmettle_api;
GRANT UPDATE (session_issued) ON openmettle.login_transactions TO openmettle_api;
GRANT SELECT ON openmettle.local_identity_approvals, openmettle.local_sessions TO openmettle_api;
GRANT UPDATE (lock_guard) ON openmettle.local_identity_approvals TO openmettle_api;
GRANT UPDATE (revoked) ON openmettle.local_sessions TO openmettle_api;
GRANT INSERT (id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,
    issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms)
    ON openmettle.local_sessions TO openmettle_api;
