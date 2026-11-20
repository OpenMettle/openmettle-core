-- V1-05 migration 15 (ADR 0027): project settings, non-nested local groups, account
-- administration, platform and user capability policy, the append-only authorization audit
-- and the worker's execution-time recheck grants. Persistence only: no route, writer or
-- policy decision is added here. The pure evaluator in src/authz.rs decides access.
-- Rows are never deleted by application roles. Lifecycle changes are current-state updates
-- with a revision, and every change is recorded in authorization_audit by its writer.

-- Project name, instructions and defaults keyed only by the stable project and scope IDs.
-- A project without a row (every project created before version 15 or by a version-14
-- process during a rolling upgrade) has no name, empty instructions and '{}' defaults.
-- Defaults must not carry legacy folder or collection identifiers at the top level.
CREATE TABLE openmettle.project_settings (
    project_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256 AND btrim(name) = name
        AND name COLLATE "C" !~ '[[:cntrl:]]'),
    instructions text NOT NULL DEFAULT '' CHECK (octet_length(instructions) <= 32768),
    defaults jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(defaults) = 'object'
        AND octet_length(defaults::text) <= 16384
        AND NOT (defaults ?| ARRAY['folder_id', 'folder_ids', 'collection_id', 'collection_ids'])),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    archived_at timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    CONSTRAINT project_settings_scope_key UNIQUE (scope_id),
    CONSTRAINT project_settings_project_fkey FOREIGN KEY (project_id, scope_id)
        REFERENCES openmettle.projects (id, scope_id),
    CHECK (archived_at IS NULL OR archived_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

-- Local groups are one flat namespace, separate from OIDC groups. There is deliberately no
-- parent or member-group column: a group never contains another group.
CREATE TABLE openmettle.local_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128 AND btrim(name) = name
        AND name COLLATE "C" !~ '[[:cntrl:]]'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    CONSTRAINT local_groups_name_key UNIQUE (name),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

-- One current-state row per (group, user). Removal sets active = false; re-adding sets it
-- back to true. Each change advances the revision, so a writer can compare and set.
CREATE TABLE openmettle.local_group_memberships (
    group_id uuid NOT NULL REFERENCES openmettle.local_groups (id),
    user_id uuid NOT NULL REFERENCES openmettle.users (id),
    active boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX local_group_memberships_user_idx
    ON openmettle.local_group_memberships (user_id, group_id);

-- Every account_admin change, from the API or an owner operator script, first locks this one
-- row FOR UPDATE, then counts enabled administrators and writes in the same transaction. User
-- disablement takes the same lock. The API can lock it only through the inert guard column.
CREATE TABLE openmettle.account_admin_lock (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false)
);
INSERT INTO openmettle.account_admin_lock (id) VALUES (true);

-- Current account_admin state. NULL updated_by_user_id records an owner operator script;
-- the operator UUID, request and reason are in authorization_audit.
CREATE TABLE openmettle.account_admins (
    user_id uuid PRIMARY KEY REFERENCES openmettle.users (id),
    active boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid REFERENCES openmettle.users (id)
);

-- Capability names follow src/authz.rs exactly: 1 to 128 bytes of lowercase ASCII letters,
-- digits, '.', '_' and '-'. The character set is spelled out so no locale range applies.
CREATE TABLE openmettle.platform_capability_denies (
    capability text PRIMARY KEY CHECK (octet_length(capability) BETWEEN 1 AND 128
        AND capability COLLATE "C" ~ '^[abcdefghijklmnopqrstuvwxyz0123456789._-]+$'),
    denied boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id)
);
CREATE TABLE openmettle.user_capability_denies (
    user_id uuid NOT NULL REFERENCES openmettle.users (id),
    capability text NOT NULL CHECK (octet_length(capability) BETWEEN 1 AND 128
        AND capability COLLATE "C" ~ '^[abcdefghijklmnopqrstuvwxyz0123456789._-]+$'),
    denied boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    PRIMARY KEY (user_id, capability)
);
-- Explicit assignments for opt-in capabilities such as runs.use_yolo. Administration never
-- implies one, and a platform or user deny still wins.
CREATE TABLE openmettle.user_capability_grants (
    user_id uuid NOT NULL REFERENCES openmettle.users (id),
    capability text NOT NULL CHECK (octet_length(capability) BETWEEN 1 AND 128
        AND capability COLLATE "C" ~ '^[abcdefghijklmnopqrstuvwxyz0123456789._-]+$'),
    granted boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    PRIMARY KEY (user_id, capability)
);

-- Append-only record of every authorization change. Application roles can insert and read,
-- never update or delete. The API cannot choose the row ID, the time or an operator actor:
-- those columns are outside its INSERT grant, so it records only user actors. A request key
-- is unique per actor, which makes a replayed change detectable. details is a bounded object
-- of identifiers and counters; it never holds secrets, tokens or content.
CREATE TABLE openmettle.authorization_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor_kind text NOT NULL DEFAULT 'user' CHECK (actor_kind IN ('user', 'operator')),
    actor_user_id uuid REFERENCES openmettle.users (id),
    operator_id uuid,
    action text NOT NULL CHECK (action IN (
        'account_admin.grant', 'account_admin.revoke',
        'user.disable', 'user.enable',
        'local_group.create', 'local_group.rename', 'local_group.disable', 'local_group.enable',
        'local_group.member_add', 'local_group.member_remove',
        'project.create', 'project.settings_update', 'project.archive', 'project.restore',
        'project.delete', 'project.member_grant', 'project.member_revoke',
        'resource.share', 'resource.unshare',
        'capability.platform_deny', 'capability.platform_allow',
        'capability.user_deny', 'capability.user_allow',
        'capability.user_grant', 'capability.user_revoke')),
    target_kind text NOT NULL CHECK (target_kind IN
        ('user', 'project', 'conversation', 'artifact', 'local_group', 'capability', 'scope')),
    target_id text NOT NULL CHECK (octet_length(target_id) BETWEEN 1 AND 256
        AND target_id COLLATE "C" !~ '[[:cntrl:]]'),
    request_key text NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 512),
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'
        AND octet_length(details::text) <= 4096),
    CHECK ((actor_kind = 'user' AND actor_user_id IS NOT NULL AND operator_id IS NULL)
        OR (actor_kind = 'operator' AND operator_id IS NOT NULL AND actor_user_id IS NULL)),
    -- NULLs are distinct, so each constraint applies only to its own actor kind.
    CONSTRAINT authorization_audit_user_request_key UNIQUE (actor_user_id, request_key),
    CONSTRAINT authorization_audit_operator_request_key UNIQUE (operator_id, request_key)
);
CREATE INDEX authorization_audit_target_idx
    ON openmettle.authorization_audit (target_kind, target_id, occurred_at);

-- API: reads, whole-row inserts without ownership-key updates, and current-state updates.
-- No DELETE, TRUNCATE, REFERENCES or TRIGGER for any application role.
GRANT SELECT ON openmettle.project_settings, openmettle.local_groups,
    openmettle.local_group_memberships, openmettle.account_admin_lock,
    openmettle.account_admins, openmettle.platform_capability_denies,
    openmettle.user_capability_denies, openmettle.user_capability_grants,
    openmettle.authorization_audit TO openmettle_api;
GRANT INSERT (project_id, scope_id, name, instructions, defaults, updated_by_user_id)
    ON openmettle.project_settings TO openmettle_api;
GRANT UPDATE (name, instructions, defaults, revision, archived_at, deleted_at, updated_at,
    updated_by_user_id) ON openmettle.project_settings TO openmettle_api;
GRANT INSERT (id, name, created_by_user_id, updated_by_user_id)
    ON openmettle.local_groups TO openmettle_api;
GRANT UPDATE (name, revision, disabled_at, updated_at, updated_by_user_id)
    ON openmettle.local_groups TO openmettle_api;
GRANT INSERT (group_id, user_id, active, updated_by_user_id)
    ON openmettle.local_group_memberships TO openmettle_api;
GRANT UPDATE (active, revision, updated_at, updated_by_user_id)
    ON openmettle.local_group_memberships TO openmettle_api;
GRANT UPDATE (lock_guard) ON openmettle.account_admin_lock TO openmettle_api;
GRANT INSERT (user_id, active, updated_by_user_id) ON openmettle.account_admins TO openmettle_api;
GRANT UPDATE (active, revision, updated_at, updated_by_user_id)
    ON openmettle.account_admins TO openmettle_api;
GRANT INSERT (capability, denied, updated_by_user_id)
    ON openmettle.platform_capability_denies TO openmettle_api;
GRANT UPDATE (denied, revision, updated_at, updated_by_user_id)
    ON openmettle.platform_capability_denies TO openmettle_api;
GRANT INSERT (user_id, capability, denied, updated_by_user_id)
    ON openmettle.user_capability_denies TO openmettle_api;
GRANT UPDATE (denied, revision, updated_at, updated_by_user_id)
    ON openmettle.user_capability_denies TO openmettle_api;
GRANT INSERT (user_id, capability, granted, updated_by_user_id)
    ON openmettle.user_capability_grants TO openmettle_api;
GRANT UPDATE (granted, revision, updated_at, updated_by_user_id)
    ON openmettle.user_capability_grants TO openmettle_api;
GRANT INSERT (actor_user_id, action, target_kind, target_id, request_key, reason, details)
    ON openmettle.authorization_audit TO openmettle_api;

-- Execution-time recheck (ADR 0027): the worker reads the non-secret authority, membership,
-- group and capability rows. None of these columns holds a secret, key or session credential.
-- It reads no account_admin, audit or project settings row.
GRANT SELECT ON openmettle.membership_observations, openmettle.local_identity_approvals,
    openmettle.login_providers, openmettle.login_provider_revisions,
    openmettle.user_identities, openmettle.local_groups, openmettle.local_group_memberships,
    openmettle.platform_capability_denies, openmettle.user_capability_denies,
    openmettle.user_capability_grants TO openmettle_worker;

-- Share, revoke and disable transactions invalidate queued work immediately (API); the
-- worker invalidates at its recheck. Only the lifecycle columns, never ownership or input.
GRANT UPDATE (state, wait_reason) ON openmettle.runs TO openmettle_api, openmettle_worker;
