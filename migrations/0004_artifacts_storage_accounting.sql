-- V1-02 migration 4: artifacts, immutable revisions, storage reservations and byte accounting.
-- Persistence only (ADR 0005). No filesystem, purge job, authorization or quota policy. The
-- helpers in src/storage.rs maintain the counters; direct SQL by an application role can bypass
-- them, so this schema does not claim database-enforced accounting.

-- Installation-wide accounting and the owner-configured limits. NULL limits are unconfigured
-- and refuse new reservations. Values are deployment inputs set by openmettle_owner; the
-- application roles may only adjust counters. The budget is the logical byte ceiling left
-- after operator headroom, not a measurement of physical disk capacity.
CREATE TABLE openmettle.storage_instance (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    instance_budget_bytes bigint CHECK (instance_budget_bytes >= 0),
    personal_limit_bytes bigint CHECK (personal_limit_bytes >= 0),
    project_limit_bytes bigint CHECK (project_limit_bytes >= 0),
    active_bytes bigint NOT NULL DEFAULT 0 CHECK (active_bytes >= 0),
    retained_bytes bigint NOT NULL DEFAULT 0 CHECK (retained_bytes >= 0),
    reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0)
);
INSERT INTO openmettle.storage_instance (id) VALUES (true);

-- One accounting row per owner scope, created lazily by the reservation helper so scopes
-- written by the previous release still work.
CREATE TABLE openmettle.storage_accounts (
    scope_id uuid PRIMARY KEY REFERENCES openmettle.scopes (id),
    active_bytes bigint NOT NULL DEFAULT 0 CHECK (active_bytes >= 0),
    retained_bytes bigint NOT NULL DEFAULT 0 CHECK (retained_bytes >= 0),
    reserved_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Logical file identity. The scope is the single accounting owner; owner_user_id is the
-- private creator, as for conversations. A project scope does not publish the artifact.
CREATE TABLE openmettle.artifacts (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    scope_kind text NOT NULL,
    owner_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    personal_owner_user_id uuid GENERATED ALWAYS AS (
        CASE WHEN scope_kind = 'personal' THEN owner_user_id END
    ) STORED,
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT artifacts_scope_fkey
        FOREIGN KEY (scope_id, scope_kind) REFERENCES openmettle.scopes (id, kind),
    CONSTRAINT artifacts_personal_owner_fkey
        FOREIGN KEY (scope_id, personal_owner_user_id)
        REFERENCES openmettle.scopes (id, personal_user_id),
    CONSTRAINT artifacts_scope_id_key UNIQUE (scope_id, id)
);
CREATE INDEX artifacts_scope_owner_idx ON openmettle.artifacts (scope_id, owner_user_id, created_at);
CREATE INDEX artifacts_owner_idx ON openmettle.artifacts (owner_user_id);

-- A bounded allowance reserved before a write. It settles into exactly one revision or is
-- released; either closes it once. An optional run/operation link records the external work
-- that must be reconciled before release.
CREATE TABLE openmettle.storage_reservations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES openmettle.storage_accounts (scope_id),
    actor_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    artifact_id uuid NOT NULL,
    max_bytes bigint NOT NULL CHECK (max_bytes > 0),
    run_id uuid,
    operation_id uuid,
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) <= 1024),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved', 'settled', 'released')),
    settled_bytes bigint,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT storage_reservations_key UNIQUE (scope_id, actor_user_id, idempotency_key),
    CONSTRAINT storage_reservations_scope_id_key UNIQUE (scope_id, id, artifact_id),
    CONSTRAINT storage_reservations_run_fkey
        FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id),
    CONSTRAINT storage_reservations_operation_fkey
        FOREIGN KEY (scope_id, run_id, operation_id)
        REFERENCES openmettle.operations (scope_id, run_id, id),
    CONSTRAINT storage_reservations_operation_run_check
        CHECK (operation_id IS NULL OR run_id IS NOT NULL),
    CONSTRAINT storage_reservations_lifecycle_check CHECK (
        (state = 'reserved' AND settled_bytes IS NULL AND closed_at IS NULL)
        OR (state = 'settled' AND settled_bytes IS NOT NULL AND settled_bytes BETWEEN 0 AND max_bytes
            AND closed_at IS NOT NULL AND closed_at >= created_at)
        OR (state = 'released' AND settled_bytes IS NULL
            AND closed_at IS NOT NULL AND closed_at >= created_at)
    )
);
CREATE INDEX storage_reservations_scope_state_idx
    ON openmettle.storage_reservations (scope_id, state, created_at);
CREATE INDEX storage_reservations_scope_run_idx
    ON openmettle.storage_reservations (scope_id, run_id) WHERE run_id IS NOT NULL;
CREATE INDEX storage_reservations_actor_idx ON openmettle.storage_reservations (actor_user_id);

-- Immutable stored payload metadata. Each revision is charged once, from its reservation;
-- further references or grants never add a charge. Lifecycle columns record retention:
-- retained and purging bytes stay charged until purge is confirmed.
CREATE TABLE openmettle.artifact_revisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    reservation_id uuid NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    media_type text NOT NULL CHECK (octet_length(media_type) BETWEEN 1 AND 255),
    created_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'retained', 'purging', 'purged')),
    retained_at timestamptz,
    purge_after timestamptz,
    purging_at timestamptz,
    purged_at timestamptz,
    CONSTRAINT artifact_revisions_artifact_revision_key UNIQUE (artifact_id, revision),
    CONSTRAINT artifact_revisions_reservation_key UNIQUE (reservation_id),
    CONSTRAINT artifact_revisions_scope_id_key UNIQUE (scope_id, id),
    CONSTRAINT artifact_revisions_artifact_fkey
        FOREIGN KEY (scope_id, artifact_id) REFERENCES openmettle.artifacts (scope_id, id),
    CONSTRAINT artifact_revisions_reservation_fkey
        FOREIGN KEY (scope_id, reservation_id, artifact_id)
        REFERENCES openmettle.storage_reservations (scope_id, id, artifact_id),
    CONSTRAINT artifact_revisions_lifecycle_check CHECK (
        (state = 'active' AND retained_at IS NULL AND purge_after IS NULL
            AND purging_at IS NULL AND purged_at IS NULL)
        OR (state = 'retained' AND retained_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after > retained_at
            AND purging_at IS NULL AND purged_at IS NULL)
        OR (state = 'purging' AND retained_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after > retained_at
            AND purging_at IS NOT NULL
            AND purging_at >= purge_after AND purged_at IS NULL)
        OR (state = 'purged' AND retained_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after > retained_at
            AND purging_at IS NOT NULL AND purged_at IS NOT NULL
            AND purging_at >= purge_after AND purged_at >= purging_at)
    )
);
CREATE INDEX artifact_revisions_scope_artifact_idx
    ON openmettle.artifact_revisions (scope_id, artifact_id, revision);
CREATE INDEX artifact_revisions_scope_state_idx
    ON openmettle.artifact_revisions (scope_id, state);
CREATE INDEX artifact_revisions_purge_idx
    ON openmettle.artifact_revisions (purge_after) WHERE state = 'retained';

-- No DELETE, TRUNCATE, limit, ownership or immutable-metadata UPDATE for application roles.
-- Retention columns are split: only the API can retain/restore and only the worker can purge.
GRANT SELECT ON openmettle.storage_instance, openmettle.storage_accounts, openmettle.artifacts,
    openmettle.storage_reservations, openmettle.artifact_revisions
    TO openmettle_api, openmettle_worker;
GRANT UPDATE (active_bytes, retained_bytes, reserved_bytes)
    ON openmettle.storage_instance, openmettle.storage_accounts
    TO openmettle_api, openmettle_worker;
GRANT INSERT (scope_id) ON openmettle.storage_accounts TO openmettle_api, openmettle_worker;
GRANT INSERT (id, scope_id, scope_kind, owner_user_id) ON openmettle.artifacts
    TO openmettle_api, openmettle_worker;
GRANT UPDATE (last_revision) ON openmettle.artifacts TO openmettle_api, openmettle_worker;
GRANT INSERT (id, scope_id, actor_user_id, idempotency_key, artifact_id, max_bytes, run_id,
    operation_id, request_identity, request_digest)
    ON openmettle.storage_reservations TO openmettle_api, openmettle_worker;
GRANT UPDATE (state, settled_bytes, closed_at) ON openmettle.storage_reservations
    TO openmettle_api, openmettle_worker;
GRANT INSERT (id, scope_id, artifact_id, revision, reservation_id, size_bytes, content_digest,
    media_type, created_by_user_id)
    ON openmettle.artifact_revisions TO openmettle_api, openmettle_worker;
GRANT UPDATE (state, retained_at, purge_after) ON openmettle.artifact_revisions TO openmettle_api;
GRANT UPDATE (state, purging_at, purged_at) ON openmettle.artifact_revisions TO openmettle_worker;
