-- ADR 0035. Session locators survive session retention and carry no credential material.
ALTER TABLE openmettle.runs
    ADD COLUMN execution_mode text CHECK (execution_mode IN ('ordinary', 'yolo')),
    ADD COLUMN originating_session_id text CHECK (originating_session_id COLLATE "C" ~ '^[A-Za-z0-9_-]{43}$'),
    ADD COLUMN admission_evidence bytea CHECK (octet_length(admission_evidence) BETWEEN 1 AND 16384),
    ADD COLUMN approval_wait_id uuid,
    ADD CHECK ((execution_mode IS NULL) = (originating_session_id IS NULL)
           AND (execution_mode IS NULL) = (admission_evidence IS NULL)
           AND (execution_mode IS NULL OR actor_approval_id IS NOT NULL)),
    ADD UNIQUE (scope_id, id, actor_user_id);

CREATE TABLE openmettle.run_approvals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    run_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    logical_key text NOT NULL CHECK (octet_length(logical_key) BETWEEN 1 AND 128),
    tool_id text NOT NULL CHECK (octet_length(tool_id) BETWEEN 1 AND 128),
    tool_version text NOT NULL CHECK (octet_length(tool_version) BETWEEN 1 AND 128),
    canonical_arguments bytea NOT NULL CHECK (octet_length(canonical_arguments) BETWEEN 2 AND 65536),
    destination text NOT NULL CHECK (octet_length(destination) BETWEEN 1 AND 512),
    authority_evidence bytea NOT NULL CHECK (octet_length(authority_evidence) BETWEEN 1 AND 32768),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    approval_expires_at timestamptz NOT NULL CHECK (isfinite(approval_expires_at)),
    resume_execution_expires_at timestamptz NOT NULL CHECK (isfinite(resume_execution_expires_at)),
    CHECK (convert_from(canonical_arguments, 'UTF8') IS JSON OBJECT WITH UNIQUE KEYS),
    CHECK (octet_length(canonical_arguments) + octet_length(authority_evidence)
           + octet_length(destination) + octet_length(tool_id) + octet_length(tool_version) <= 65536),
    CHECK (approval_expires_at <= resume_execution_expires_at),
    UNIQUE (run_id, logical_key),
    UNIQUE (scope_id, run_id, id),
    UNIQUE (scope_id, run_id, id, logical_key),
    FOREIGN KEY (scope_id, run_id, actor_user_id) REFERENCES openmettle.runs (scope_id, id, actor_user_id),
    UNIQUE (scope_id, run_id, id, actor_user_id, binding_digest)
);
CREATE INDEX run_approvals_actor_run_idx ON openmettle.run_approvals (scope_id, run_id, actor_user_id);

CREATE TABLE openmettle.run_approval_decisions (
    approval_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    run_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    deciding_session_id text NOT NULL CHECK (deciding_session_id COLLATE "C" ~ '^[A-Za-z0-9_-]{43}$'),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest) = 32),
    decision text NOT NULL CHECK (decision IN ('approve', 'deny')),
    request_key text NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (scope_id, actor_user_id, request_key),
    UNIQUE (approval_id, decision),
    FOREIGN KEY (scope_id, run_id, approval_id, actor_user_id, binding_digest)
        REFERENCES openmettle.run_approvals (scope_id, run_id, id, actor_user_id, binding_digest)
);

-- Preserve state and event history. The bounded worker sweep settles these legacy waits.
UPDATE openmettle.runs SET wait_reason = NULL WHERE wait_reason = 'approval';
ALTER TABLE openmettle.runs
    ADD FOREIGN KEY (scope_id, id, approval_wait_id) REFERENCES openmettle.run_approvals (scope_id, run_id, id),
    ADD CHECK ((wait_reason IS NOT DISTINCT FROM 'approval') = (state = 'waiting' AND approval_wait_id IS NOT NULL)
           AND (wait_reason IS DISTINCT FROM 'approval' OR claim_token IS NULL));
CREATE INDEX runs_wait_sweep_idx ON openmettle.runs (id) WHERE state = 'waiting';

ALTER TABLE openmettle.operations
    ADD COLUMN approval_id uuid UNIQUE,
    ADD COLUMN approval_decision text GENERATED ALWAYS AS
        (CASE WHEN approval_id IS NOT NULL THEN 'approve' END) STORED,
    ADD FOREIGN KEY (scope_id, run_id, approval_id, logical_key)
        REFERENCES openmettle.run_approvals (scope_id, run_id, id, logical_key),
    ADD FOREIGN KEY (approval_id, approval_decision)
        REFERENCES openmettle.run_approval_decisions (approval_id, decision);

-- The unique run and approval identities also index reverse FK lookups.
GRANT SELECT ON openmettle.run_approvals, openmettle.run_approval_decisions TO openmettle_api, openmettle_worker;
GRANT INSERT (scope_id, run_id, actor_user_id, logical_key, tool_id, tool_version, canonical_arguments,
              destination, authority_evidence, binding_digest, approval_expires_at, resume_execution_expires_at)
    ON openmettle.run_approvals TO openmettle_worker;
GRANT INSERT (approval_id, scope_id, run_id, actor_user_id, deciding_session_id, binding_digest, decision, request_key)
    ON openmettle.run_approval_decisions TO openmettle_api;
GRANT INSERT (execution_mode, originating_session_id, admission_evidence) ON openmettle.runs TO openmettle_api;
GRANT UPDATE (approval_wait_id) ON openmettle.runs TO openmettle_worker;
GRANT INSERT (approval_id) ON openmettle.operations TO openmettle_worker;
GRANT SELECT (id, user_id, approval_id, provider_id, identity_id, issued_client, issued_epoch,
              provider_generation, approval_generation, user_generation, created_ms, expires_ms, revoked)
    ON openmettle.local_sessions TO openmettle_worker;
