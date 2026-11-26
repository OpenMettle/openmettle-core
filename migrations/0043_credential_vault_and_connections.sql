-- V1-28 migration 43 (ADR 0045): credential vault, external connection lifecycle, and
-- deletion-journal/restore reconciliation for external connection revocations.
-- Adds scope-owned openmettle.external_connections (encrypted access/refresh secrets,
-- non-widening allowed/granted scopes, single-flight refresh leasing and monotonic
-- credential/revocation/share generations), explicit openmettle.external_connection_shares,
-- monotonic/worker/restore-gate triggers, two worker SECURITY DEFINER helpers (scope lifecycle
-- and redacted worker audit), widens authorization_audit for connection and vault events, and
-- integrates disconnect, credential supersession, and share revocation into
-- openmettle.deletion_journal and openmettle.restore_reconciliation_gate.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (ADR 0027, ADR 0041, ADR 0045):
--   account_admin_lock -> projects -> login_providers -> local_identity_approvals ->
--   users (ascending id) -> external_connections -> external_connection_shares ->
--   restore_reconciliation_gate (FOR SHARE) -> deletion_journal_head (FOR UPDATE, deferred).
--
-- Role boundaries (verified by src/boundaries.sql):
--   - openmettle_api: column-scoped SELECT on non-secret metadata + has_refresh only (zero
--     SELECT on ciphertext, salt, nonce, encryption_key_id or refresh lease columns),
--     column-scoped INSERT/UPDATE for connection metadata, write-only authorization,
--     disconnect and explicit sharing. No DELETE or TRUNCATE.
--   - openmettle_worker: SELECT on external_connections and external_connection_shares,
--     column-scoped UPDATE strictly for refresh leasing/commit and reauth_required
--     transitions (trigger-guarded including NEW.granted_scopes <@ OLD.granted_scopes), plus
--     EXECUTE on external_connection_scope_lifecycle and external_connection_audit_worker.
--     Zero SELECT on project_settings or authorization_audit.
--   - openmettle_issuance and openmettle_gateway: zero privileges.

-- Acquire ACCESS EXCLUSIVE on every pre-existing table modified by migration 43 in one atomic
-- bounded NOWAIT retry loop at the top of the transaction so concurrent writers cannot
-- deadlock with DDL.
DO $$
DECLARE
    v_timeout interval;
    v_deadline timestamptz;
BEGIN
    SELECT coalesce(nullif(setting::bigint, 0), 15000) * interval '1 millisecond'
      INTO v_timeout
      FROM pg_catalog.pg_settings
     WHERE name = 'lock_timeout';
    v_timeout := coalesce(v_timeout, interval '15 seconds');
    v_deadline := pg_catalog.clock_timestamp() + v_timeout;

    LOOP
        BEGIN
            LOCK TABLE openmettle.authorization_audit,
                       openmettle.deletion_journal,
                       openmettle.deletion_journal_head,
                       openmettle.restore_reconciliation_gate
                IN ACCESS EXCLUSIVE MODE NOWAIT;
            EXIT;
        EXCEPTION
            WHEN lock_not_available THEN
                IF pg_catalog.clock_timestamp() >= v_deadline THEN
                    RAISE EXCEPTION 'canceling statement due to lock timeout'
                        USING ERRCODE = '55P03';
                END IF;
                PERFORM pg_catalog.pg_sleep(0.02);
        END;
    END LOOP;
END
$$;

-- Canonical scope-array validator shared by allowed_scopes and granted_scopes CHECKs.
-- Requires a 1-D array of 0..64 (or 1..64 when p_allow_empty is false) non-null lowercase
-- ASCII scope tokens in strictly ascending C-collation order (unique and canonical).
CREATE FUNCTION openmettle.external_connection_scopes_valid(
    p_scopes text[],
    p_allow_empty boolean)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    v_len integer;
    v_i integer;
    v_cur text;
    v_prev text;
BEGIN
    v_len := pg_catalog.cardinality(p_scopes);
    IF v_len = 0 THEN
        RETURN p_allow_empty;
    END IF;
    IF pg_catalog.array_ndims(p_scopes) <> 1 OR v_len > 64 THEN
        RETURN false;
    END IF;
    FOR v_i IN 1..v_len LOOP
        v_cur := p_scopes[v_i];
        IF v_cur IS NULL
           OR pg_catalog.octet_length(v_cur) NOT BETWEEN 1 AND 128
           OR v_cur COLLATE "C" !~ '^[a-z0-9][a-z0-9._:/-]{0,127}$' THEN
            RETURN false;
        END IF;
        IF v_i > 1 AND NOT (v_prev COLLATE "C" < v_cur COLLATE "C") THEN
            RETURN false;
        END IF;
        v_prev := v_cur;
    END LOOP;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.external_connection_scopes_valid(text[], boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.external_connection_scopes_valid(text[], boolean)
    TO openmettle_api, openmettle_worker;

-- Scope-owned external connections holding versioned-key HKDF-SHA256 + AES-256-GCM
-- encrypted access and optional refresh credentials. Personal connections belong solely to
-- their personal scope owner; project connections belong to the project (managed by project
-- owners) with creator provenance in owner_user_id.
CREATE TABLE openmettle.external_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind IN ('personal', 'project')),
    owner_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    personal_owner_user_id uuid GENERATED ALWAYS AS (
        CASE WHEN scope_kind = 'personal' THEN owner_user_id END
    ) STORED,
    provider_kind text NOT NULL CHECK (
        pg_catalog.octet_length(provider_kind) BETWEEN 1 AND 64
        AND provider_kind COLLATE "C" ~ '^[a-z][a-z0-9._-]{0,63}$'
    ),
    account_id text NOT NULL CHECK (
        pg_catalog.octet_length(account_id) BETWEEN 1 AND 256
        AND account_id = pg_catalog.btrim(account_id)
        AND account_id COLLATE "C" !~ '[[:cntrl:]]'
        AND pg_catalog.strpos(account_id, '*') = 0
    ),
    endpoint_origin text NOT NULL CHECK (
        pg_catalog.octet_length(endpoint_origin) BETWEEN 9 AND 256
        AND endpoint_origin COLLATE "C" ~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)+(:[1-9][0-9]{0,4})?$'
    ),
    allowed_scopes text[] NOT NULL CHECK (
        openmettle.external_connection_scopes_valid(allowed_scopes, false)
    ),
    granted_scopes text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (
        openmettle.external_connection_scopes_valid(granted_scopes, true)
        AND granted_scopes <@ allowed_scopes
    ),
    state text NOT NULL DEFAULT 'pending_auth' CHECK (
        state IN ('pending_auth', 'authorized', 'reauth_required', 'disconnected')
    ),
    expires_at timestamptz,
    encryption_key_id text CHECK (
        encryption_key_id IS NULL
        OR (
            pg_catalog.octet_length(encryption_key_id) BETWEEN 1 AND 64
            AND encryption_key_id COLLATE "C" ~ '^[A-Za-z0-9_-]+$'
        )
    ),
    access_salt bytea CHECK (access_salt IS NULL OR pg_catalog.octet_length(access_salt) = 32),
    access_nonce bytea CHECK (access_nonce IS NULL OR pg_catalog.octet_length(access_nonce) = 12),
    access_ciphertext bytea CHECK (
        access_ciphertext IS NULL
        OR pg_catalog.octet_length(access_ciphertext) BETWEEN 17 AND 4112
    ),
    refresh_salt bytea CHECK (refresh_salt IS NULL OR pg_catalog.octet_length(refresh_salt) = 32),
    refresh_nonce bytea CHECK (refresh_nonce IS NULL OR pg_catalog.octet_length(refresh_nonce) = 12),
    refresh_ciphertext bytea CHECK (
        refresh_ciphertext IS NULL
        OR pg_catalog.octet_length(refresh_ciphertext) BETWEEN 17 AND 16400
    ),
    has_refresh boolean GENERATED ALWAYS AS (refresh_ciphertext IS NOT NULL) STORED,
    credential_generation bigint NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    revocation_generation bigint NOT NULL DEFAULT 0 CHECK (revocation_generation >= 0),
    share_revision bigint NOT NULL DEFAULT 0 CHECK (share_revision >= 0),
    refresh_claim_token uuid,
    refresh_lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    disconnected_at timestamptz,
    CONSTRAINT external_connections_scope_fkey
        FOREIGN KEY (scope_id, scope_kind) REFERENCES openmettle.scopes (id, kind),
    CONSTRAINT external_connections_personal_owner_fkey
        FOREIGN KEY (scope_id, personal_owner_user_id)
        REFERENCES openmettle.scopes (id, personal_user_id),
    CONSTRAINT external_connections_id_scope_key UNIQUE (id, scope_id),
    CONSTRAINT external_connections_access_tuple_check CHECK (
        (access_salt IS NULL) = (access_nonce IS NULL)
        AND (access_salt IS NULL) = (access_ciphertext IS NULL)
    ),
    CONSTRAINT external_connections_refresh_tuple_check CHECK (
        (refresh_salt IS NULL) = (refresh_nonce IS NULL)
        AND (refresh_salt IS NULL) = (refresh_ciphertext IS NULL)
    ),
    CONSTRAINT external_connections_lease_check CHECK (
        (refresh_claim_token IS NULL) = (refresh_lease_until IS NULL)
        AND (state = 'authorized' OR refresh_claim_token IS NULL)
    ),
    CONSTRAINT external_connections_state_secrets_check CHECK (
        (
            state = 'authorized'
            AND encryption_key_id IS NOT NULL
            AND access_ciphertext IS NOT NULL
            AND pg_catalog.cardinality(granted_scopes) >= 1
            AND disconnected_at IS NULL
        ) OR (
            state IN ('pending_auth', 'reauth_required', 'disconnected')
            AND encryption_key_id IS NULL
            AND access_ciphertext IS NULL
            AND refresh_ciphertext IS NULL
            AND expires_at IS NULL
            AND pg_catalog.cardinality(granted_scopes) = 0
            AND (state = 'disconnected') = (disconnected_at IS NOT NULL)
        )
    )
);
CREATE INDEX external_connections_scope_created_idx
    ON openmettle.external_connections (scope_id, created_at, id);
CREATE INDEX external_connections_key_id_idx
    ON openmettle.external_connections (encryption_key_id, id)
    WHERE encryption_key_id IS NOT NULL;

-- Explicit, revocable execution-use grants on external connections (never exposing raw
-- credentials). Supports user, local_group, oidc_group and (project scopes only) project.
CREATE TABLE openmettle.external_connection_shares (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    grantee_kind text NOT NULL CHECK (
        grantee_kind IN ('user', 'local_group', 'oidc_group', 'project')
    ),
    grantee_user_id uuid REFERENCES openmettle.users (id),
    grantee_local_group_id uuid REFERENCES openmettle.local_groups (id),
    grantee_oidc_group_id text CHECK (
        grantee_oidc_group_id IS NULL
        OR (
            pg_catalog.octet_length(grantee_oidc_group_id) BETWEEN 1 AND 1024
            AND grantee_oidc_group_id COLLATE "C" !~ '[[:cntrl:]]'
        )
    ),
    access text NOT NULL CHECK (access IN ('use')),
    active boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    CONSTRAINT external_connection_shares_connection_fkey
        FOREIGN KEY (connection_id, scope_id)
        REFERENCES openmettle.external_connections (id, scope_id),
    CONSTRAINT external_connection_shares_grantee_check CHECK (
        (
            grantee_kind = 'user'
            AND grantee_user_id IS NOT NULL
            AND grantee_local_group_id IS NULL
            AND grantee_oidc_group_id IS NULL
        ) OR (
            grantee_kind = 'local_group'
            AND grantee_user_id IS NULL
            AND grantee_local_group_id IS NOT NULL
            AND grantee_oidc_group_id IS NULL
        ) OR (
            grantee_kind = 'oidc_group'
            AND grantee_user_id IS NULL
            AND grantee_local_group_id IS NULL
            AND grantee_oidc_group_id IS NOT NULL
        ) OR (
            grantee_kind = 'project'
            AND grantee_user_id IS NULL
            AND grantee_local_group_id IS NULL
            AND grantee_oidc_group_id IS NULL
        )
    ),
    CONSTRAINT external_connection_shares_unique_key
        UNIQUE NULLS NOT DISTINCT (
            connection_id,
            grantee_kind,
            grantee_user_id,
            grantee_local_group_id,
            grantee_oidc_group_id
        )
);
CREATE INDEX external_connection_shares_conn_active_idx
    ON openmettle.external_connection_shares (connection_id)
    WHERE active;

-- Guard external_connections mutations: enforce restore_reconciliation_gate for runtime
-- roles (OMR02), immutable ownership/origin/allowed_scopes, monotonic generations, terminal
-- disconnected state, and worker refresh-only transition and non-widening scope boundaries.
CREATE FUNCTION openmettle.enforce_external_connection_guards()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    v_is_owner boolean;
    v_is_worker boolean;
    v_secrets_changed boolean;
BEGIN
    v_is_owner := pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE');
    v_is_worker := pg_catalog.pg_has_role(current_user, 'openmettle_worker', 'USAGE')
                   AND NOT v_is_owner;

    IF NOT v_is_owner THEN
        IF NOT openmettle.restore_gate_lock_open() THEN
            RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
           OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
           OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
           OR NEW.provider_kind IS DISTINCT FROM OLD.provider_kind
           OR NEW.account_id IS DISTINCT FROM OLD.account_id
           OR NEW.endpoint_origin IS DISTINCT FROM OLD.endpoint_origin
           OR NEW.allowed_scopes IS DISTINCT FROM OLD.allowed_scopes
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'external connection identity and allowed_scopes are immutable'
                USING ERRCODE = '23514';
        END IF;

        IF NEW.credential_generation < OLD.credential_generation
           OR NEW.revocation_generation < OLD.revocation_generation
           OR NEW.share_revision < OLD.share_revision THEN
            RAISE EXCEPTION 'external connection generations must be monotonic'
                USING ERRCODE = '23514';
        END IF;

        IF OLD.state = 'disconnected' AND NEW.state <> 'disconnected' THEN
            RAISE EXCEPTION 'disconnected external connection is terminal'
                USING ERRCODE = '23514';
        END IF;

        v_secrets_changed :=
            NEW.encryption_key_id IS DISTINCT FROM OLD.encryption_key_id
            OR NEW.access_salt IS DISTINCT FROM OLD.access_salt
            OR NEW.access_nonce IS DISTINCT FROM OLD.access_nonce
            OR NEW.access_ciphertext IS DISTINCT FROM OLD.access_ciphertext
            OR NEW.refresh_salt IS DISTINCT FROM OLD.refresh_salt
            OR NEW.refresh_nonce IS DISTINCT FROM OLD.refresh_nonce
            OR NEW.refresh_ciphertext IS DISTINCT FROM OLD.refresh_ciphertext;

        IF v_secrets_changed
           AND NEW.access_ciphertext IS NOT NULL
           AND NEW.credential_generation <= OLD.credential_generation THEN
            RAISE EXCEPTION 'secret writes must advance credential_generation'
                USING ERRCODE = '23514';
        END IF;

        IF NEW.state IN ('disconnected', 'reauth_required')
           AND OLD.state <> NEW.state
           AND NEW.revocation_generation <= OLD.revocation_generation THEN
            RAISE EXCEPTION 'revocation transition must advance revocation_generation'
                USING ERRCODE = '23514';
        END IF;

        IF v_is_worker THEN
            IF OLD.state <> 'authorized' OR NEW.state NOT IN ('authorized', 'reauth_required') THEN
                RAISE EXCEPTION 'worker may only refresh or require reauth on authorized connections'
                    USING ERRCODE = '42501';
            END IF;
            IF NOT (NEW.granted_scopes <@ OLD.granted_scopes) THEN
                RAISE EXCEPTION 'worker refresh may not widen granted_scopes'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_external_connection_guards() FROM PUBLIC;
CREATE TRIGGER external_connections_guards
    BEFORE INSERT OR UPDATE ON openmettle.external_connections
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_external_connection_guards();

-- Guard external_connection_shares mutations: enforce restore gate (OMR02), reject whole-project
-- grantee on personal connections, and enforce immutable key columns + monotonic revision.
CREATE FUNCTION openmettle.enforce_external_connection_share_guards()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    v_scope_kind text;
BEGIN
    IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        IF NOT openmettle.restore_gate_lock_open() THEN
            RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
        END IF;
    END IF;

    IF NEW.grantee_kind = 'project' THEN
        SELECT scope_kind INTO v_scope_kind
          FROM openmettle.external_connections
         WHERE id = NEW.connection_id AND scope_id = NEW.scope_id;
        IF v_scope_kind IS DISTINCT FROM 'project' THEN
            RAISE EXCEPTION 'project grantee is valid only for project-scoped connections'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
           OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
           OR NEW.grantee_kind IS DISTINCT FROM OLD.grantee_kind
           OR NEW.grantee_user_id IS DISTINCT FROM OLD.grantee_user_id
           OR NEW.grantee_local_group_id IS DISTINCT FROM OLD.grantee_local_group_id
           OR NEW.grantee_oidc_group_id IS DISTINCT FROM OLD.grantee_oidc_group_id
           OR NEW.access IS DISTINCT FROM OLD.access THEN
            RAISE EXCEPTION 'external connection share identity is immutable'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.revision <= OLD.revision THEN
            RAISE EXCEPTION 'external connection share revision must advance'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_external_connection_share_guards() FROM PUBLIC;
CREATE TRIGGER external_connection_shares_guards
    BEFORE INSERT OR UPDATE ON openmettle.external_connection_shares
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_external_connection_share_guards();

-- Least-privilege worker helper: exposes only scope ownership and project archive/delete
-- booleans without granting openmettle_worker SELECT on openmettle.project_settings.
CREATE FUNCTION openmettle.external_connection_scope_lifecycle(p_scope_id uuid)
RETURNS TABLE(
    scope_kind text,
    project_id uuid,
    personal_user_id uuid,
    archived boolean,
    deleted boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT s.kind,
           s.project_id,
           s.personal_user_id,
           coalesce(ps.archived_at IS NOT NULL, false),
           coalesce(ps.deleted_at IS NOT NULL, false)
      FROM openmettle.scopes s
      LEFT JOIN openmettle.project_settings ps ON ps.project_id = s.project_id
     WHERE s.id = p_scope_id;
$$;
REVOKE ALL ON FUNCTION openmettle.external_connection_scope_lifecycle(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.external_connection_scope_lifecycle(uuid)
    TO openmettle_worker;

-- Least-privilege worker audit helper: lets openmettle_worker append strictly non-secret
-- connection.refreshed and connection.reauth_required audit rows without gaining direct
-- SELECT or INSERT on openmettle.authorization_audit.
CREATE FUNCTION openmettle.external_connection_audit_worker(
    p_actor_user_id uuid,
    p_action text,
    p_connection_id uuid,
    p_request_key text,
    p_reason text,
    p_details jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_key text;
BEGIN
    IF p_actor_user_id IS NULL
       OR p_connection_id IS NULL
       OR p_action NOT IN ('connection.refreshed', 'connection.reauth_required') THEN
        RAISE EXCEPTION 'invalid worker connection audit parameters' USING ERRCODE = '22023';
    END IF;

    IF p_details IS NULL
       OR pg_catalog.jsonb_typeof(p_details) <> 'object'
       OR pg_catalog.octet_length(p_details::text) > 4096 THEN
        RAISE EXCEPTION 'invalid worker connection audit details' USING ERRCODE = '22023';
    END IF;

    FOR v_key IN SELECT pg_catalog.jsonb_object_keys(p_details) LOOP
        IF v_key NOT IN (
            'credential_generation',
            'revocation_generation',
            'encryption_key_id',
            'granted_scope_count',
            'reason'
        ) THEN
            RAISE EXCEPTION 'unexpected worker connection audit detail key'
                USING ERRCODE = '22023';
        END IF;
    END LOOP;

    IF NOT EXISTS (
        SELECT 1 FROM openmettle.external_connections WHERE id = p_connection_id
    ) THEN
        RAISE EXCEPTION 'external connection not found' USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO openmettle.authorization_audit (
        actor_kind,
        actor_user_id,
        action,
        target_kind,
        target_id,
        request_key,
        reason,
        details
    ) VALUES (
        'user',
        p_actor_user_id,
        p_action,
        'external_connection',
        p_connection_id::text,
        p_request_key,
        p_reason,
        p_details
    )
    ON CONFLICT (actor_user_id, request_key) DO NOTHING;
END
$$;
REVOKE ALL ON FUNCTION openmettle.external_connection_audit_worker(uuid, text, uuid, text, text, jsonb)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.external_connection_audit_worker(uuid, text, uuid, text, text, jsonb)
    TO openmettle_worker;

-- Widen authorization_audit constraints additively for connection lifecycle and vault rotation.
ALTER TABLE openmettle.authorization_audit
    DROP CONSTRAINT authorization_audit_action_check,
    ADD CONSTRAINT authorization_audit_action_check CHECK (action IN (
        'account_admin.grant', 'account_admin.revoke',
        'user.disable', 'user.enable',
        'local_group.create', 'local_group.rename', 'local_group.disable', 'local_group.enable',
        'local_group.member_add', 'local_group.member_remove',
        'project.create', 'project.settings_update', 'project.archive', 'project.restore',
        'project.delete', 'project.member_grant', 'project.member_revoke',
        'resource.share', 'resource.unshare',
        'capability.platform_deny', 'capability.platform_allow',
        'capability.user_deny', 'capability.user_allow',
        'capability.user_grant', 'capability.user_revoke',
        'conversation.create', 'branch.create', 'quota.override.set', 'quota.override.revoke',
        'retention.policy_update', 'retention.deadlines_apply',
        'retention.status_read', 'retention.deadlines_preview',
        'artifact.delete', 'artifact_revision.delete', 'artifact_revision.restore',
        'family_policy.set', 'family_policy.clear',
        'family_policy.model_study_allow', 'family_policy.model_study_revoke',
        'family_policy.model_disable', 'family_policy.model_enable',
        'restore.accept_coverage_gap',
        'connection.created', 'connection.authorized',
        'connection.shared', 'connection.share_revoked',
        'connection.refreshed', 'connection.reauth_required',
        'connection.disconnected', 'vault.rotated')),
    DROP CONSTRAINT authorization_audit_target_kind_check,
    ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN (
        'user', 'project', 'conversation', 'artifact', 'local_group', 'capability',
        'scope', 'branch', 'quota_scope', 'retention_policy',
        'family_policy', 'oidc_group', 'restore_gate',
        'external_connection', 'vault')),
    ADD CONSTRAINT authorization_audit_connection_check CHECK (
        (action IN (
            'connection.created', 'connection.authorized',
            'connection.shared', 'connection.share_revoked',
            'connection.refreshed', 'connection.reauth_required',
            'connection.disconnected'
        )) = (target_kind = 'external_connection')
    ),
    ADD CONSTRAINT authorization_audit_vault_check CHECK (
        (action = 'vault.rotated') = (target_kind = 'vault')
        AND (
            action <> 'vault.rotated'
            OR (
                actor_kind = 'operator'
                AND actor_user_id IS NULL
                AND operator_id IS NOT NULL
                AND target_id = 'external_connections'
            )
        )
    );

-- ============================================================================
-- Deletion journal and restore reconciliation for external connection revocations
-- ============================================================================

ALTER TABLE openmettle.deletion_journal_head
    ADD COLUMN connection_coverage_started_at timestamptz;
DO $$
DECLARE
    v_started timestamptz;
BEGIN
    IF pg_catalog.to_regclass('openmettle._sqlx_migrations') IS NOT NULL THEN
        EXECUTE 'SELECT installed_on FROM openmettle._sqlx_migrations WHERE version = 43'
           INTO v_started;
    END IF;
    UPDATE openmettle.deletion_journal_head
       SET connection_coverage_started_at = coalesce(v_started, pg_catalog.clock_timestamp())
     WHERE id;
END
$$;
ALTER TABLE openmettle.deletion_journal_head
    ALTER COLUMN connection_coverage_started_at SET NOT NULL,
    ALTER COLUMN connection_coverage_started_at SET DEFAULT clock_timestamp();

ALTER TABLE openmettle.restore_reconciliation_gate
    ADD COLUMN snapshot_connection_origin_us bigint,
    ADD COLUMN required_connection_origin_us bigint,
    ADD COLUMN connection_gap_reconciled boolean NOT NULL DEFAULT false;

UPDATE openmettle.restore_reconciliation_gate g
   SET snapshot_connection_origin_us = (
       SELECT (extract(epoch FROM h.connection_coverage_started_at) * 1000000)::bigint
         FROM openmettle.deletion_journal_head h
        WHERE h.id
   )
 WHERE g.id
   AND NOT g.open
   AND g.snapshot_connection_origin_us IS NULL;

ALTER TABLE openmettle.restore_reconciliation_gate
    DROP CONSTRAINT restore_reconciliation_gate_closed_check,
    ADD CONSTRAINT restore_reconciliation_gate_closed_check CHECK (
        (
            open
            AND restore_run_id IS NULL
            AND required_origin_us IS NULL
            AND snapshot_lifecycle_origin_us IS NULL
            AND snapshot_lifecycle_baseline_digest IS NULL
            AND required_lifecycle_origin_us IS NULL
            AND required_lifecycle_baseline_digest IS NULL
            AND replayed_lifecycle_baseline_digest IS NULL
            AND snapshot_connection_origin_us IS NULL
            AND required_connection_origin_us IS NULL
            AND NOT connection_gap_reconciled
            AND checkpoints = '[]'::jsonb
            AND volume_claim_token IS NULL
            AND volume_lease_until IS NULL
        ) OR (
            NOT open
            AND restore_run_id IS NOT NULL
            AND required_origin_us IS NOT NULL
            AND snapshot_lifecycle_origin_us IS NOT NULL
            AND snapshot_lifecycle_baseline_digest IS NOT NULL
            AND snapshot_connection_origin_us IS NOT NULL
            AND ((required_lifecycle_origin_us IS NULL) = (required_lifecycle_baseline_digest IS NULL))
            AND locked_at IS NOT NULL
            AND snapshot_journal_seq IS NOT NULL
            AND required_journal_seq >= snapshot_journal_seq
            AND required_chain_digest IS NOT NULL
            AND opened_at IS NULL
            AND ((volume_claim_token IS NULL) = (volume_lease_until IS NULL))
        )
    );

ALTER TABLE openmettle.deletion_journal
    DROP CONSTRAINT deletion_journal_event_kind_check,
    DROP CONSTRAINT deletion_journal_fields_check,
    ADD CONSTRAINT deletion_journal_event_kind_check CHECK (event_kind IN (
        'artifact_revision.purged',
        'artifact_revision.retained',
        'artifact_revision.deadline_adjusted',
        'artifact_revision.restored',
        'external_connection.disconnected',
        'external_connection.credential_superseded',
        'external_connection.share_revoked'
    )),
    ADD CONSTRAINT deletion_journal_fields_check CHECK (
        (
            event_kind = 'artifact_revision.purged'
            AND original_purge_after IS NOT NULL
            AND purged_at IS NOT NULL
            AND retained_at IS NULL
        )
        OR (
            event_kind IN ('artifact_revision.retained', 'artifact_revision.deadline_adjusted')
            AND retained_at IS NOT NULL
            AND original_purge_after IS NOT NULL
            AND original_purge_after >= retained_at
            AND purged_at IS NULL
        )
        OR (
            event_kind = 'artifact_revision.restored'
            AND retained_at IS NULL
            AND original_purge_after IS NULL
            AND purged_at IS NULL
        )
        OR (
            event_kind IN (
                'external_connection.disconnected',
                'external_connection.credential_superseded',
                'external_connection.share_revoked'
            )
            AND retained_at IS NULL
            AND original_purge_after IS NULL
            AND purged_at IS NULL
            AND policy_revision IS NOT NULL
            AND policy_revision >= 1
        )
    );

-- Deferred append trigger for external_connections disconnects and credential supersessions.
-- Fires at commit so deletion_journal_head is always locked last and rolled-back transactions
-- append nothing. Skipped only during owner deletion_journal_replay / restore_accept_coverage_gap
-- while the restore gate is closed.
CREATE FUNCTION openmettle.deletion_journal_append_connection()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    head openmettle.deletion_journal_head%ROWTYPE;
    e openmettle.deletion_journal%ROWTYPE;
    v_gen bigint;
BEGIN
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    e.journal_seq := head.journal_seq + 1;
    e.recorded_at := clock_timestamp();
    e.entity_id := NEW.id;
    e.scope_id := NEW.scope_id;
    e.retained_at := NULL;
    e.original_purge_after := NULL;
    e.purged_at := NULL;

    IF OLD.state <> 'disconnected' AND NEW.state = 'disconnected' THEN
        v_gen := greatest(NEW.revocation_generation, 1);
        e.event_kind := 'external_connection.disconnected';
        e.policy_revision := v_gen;
        e.content_digest := sha256(convert_to(
            'disconnect:' || NEW.id::text || ':' || v_gen::text, 'UTF8'));
    ELSIF OLD.state = 'authorized' AND NEW.state = 'reauth_required' THEN
        v_gen := greatest(NEW.credential_generation + 1, 1);
        e.event_kind := 'external_connection.credential_superseded';
        e.policy_revision := v_gen;
        e.content_digest := sha256(convert_to(
            'superseded:' || NEW.id::text || ':' || v_gen::text, 'UTF8'));
    ELSIF OLD.state = 'authorized'
          AND NEW.state = 'authorized'
          AND NEW.credential_generation > OLD.credential_generation
          AND (
              NEW.access_ciphertext IS DISTINCT FROM OLD.access_ciphertext
              OR NEW.refresh_ciphertext IS DISTINCT FROM OLD.refresh_ciphertext
              OR NEW.granted_scopes IS DISTINCT FROM OLD.granted_scopes
          ) THEN
        v_gen := greatest(NEW.credential_generation, 1);
        e.event_kind := 'external_connection.credential_superseded';
        e.policy_revision := v_gen;
        e.content_digest := sha256(convert_to(
            'superseded:' || NEW.id::text || ':' || v_gen::text, 'UTF8'));
    ELSE
        RETURN NULL;
    END IF;

    e.chain_digest := openmettle.deletion_journal_digest(head.chain_digest, e);
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head
       SET journal_seq = e.journal_seq,
           chain_digest = e.chain_digest
     WHERE id;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.deletion_journal_append_connection() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER external_connections_deletion_journal
    AFTER UPDATE OF state, credential_generation, access_ciphertext, refresh_ciphertext, granted_scopes
    ON openmettle.external_connections
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (
        (
            (OLD.state <> 'disconnected' AND NEW.state = 'disconnected')
            OR (OLD.state = 'authorized' AND NEW.state = 'reauth_required')
            OR (
                OLD.state = 'authorized'
                AND NEW.state = 'authorized'
                AND NEW.credential_generation > OLD.credential_generation
                AND (
                    NEW.access_ciphertext IS DISTINCT FROM OLD.access_ciphertext
                    OR NEW.refresh_ciphertext IS DISTINCT FROM OLD.refresh_ciphertext
                    OR NEW.granted_scopes IS DISTINCT FROM OLD.granted_scopes
                )
            )
        )
        AND NOT (
            CASE
                WHEN pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.current_setting('openmettle.replaying_deletion_journal', true) IS NOT DISTINCT FROM 'on'
                THEN openmettle.restore_gate_is_closed_for_owner()
                ELSE false
            END
        )
    )
    EXECUTE FUNCTION openmettle.deletion_journal_append_connection();

-- Deferred append trigger for external_connection_shares revocations (active -> false or DELETE).
CREATE FUNCTION openmettle.deletion_journal_append_connection_share()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    head openmettle.deletion_journal_head%ROWTYPE;
    e openmettle.deletion_journal%ROWTYPE;
    v_rev bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NOT (OLD.active AND NOT NEW.active) THEN
            RETURN NULL;
        END IF;
        v_rev := greatest(NEW.revision, 1);
    ELSIF TG_OP = 'DELETE' THEN
        IF NOT OLD.active THEN
            RETURN NULL;
        END IF;
        v_rev := greatest(OLD.revision, 1);
    ELSE
        RETURN NULL;
    END IF;

    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    e.journal_seq := head.journal_seq + 1;
    e.recorded_at := clock_timestamp();
    e.event_kind := 'external_connection.share_revoked';
    e.entity_id := OLD.id;
    e.scope_id := OLD.scope_id;
    e.retained_at := NULL;
    e.original_purge_after := NULL;
    e.purged_at := NULL;
    e.policy_revision := v_rev;
    e.content_digest := sha256(convert_to(
        'share_revoked:' || OLD.id::text || ':' || OLD.connection_id::text || ':' || v_rev::text,
        'UTF8'));
    e.chain_digest := openmettle.deletion_journal_digest(head.chain_digest, e);
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head
       SET journal_seq = e.journal_seq,
           chain_digest = e.chain_digest
     WHERE id;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.deletion_journal_append_connection_share() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER external_connection_shares_deletion_journal
    AFTER UPDATE OF active OR DELETE
    ON openmettle.external_connection_shares
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (
        OLD.active
        AND NOT (
            CASE
                WHEN pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.current_setting('openmettle.replaying_deletion_journal', true) IS NOT DISTINCT FROM 'on'
                THEN openmettle.restore_gate_is_closed_for_owner()
                ELSE false
            END
        )
    )
    EXECUTE FUNCTION openmettle.deletion_journal_append_connection_share();

-- Owner only: extend restore_gate_lock with optional trailing p_connection_origin_us (DEFAULT NULL
-- so pre-43 6/8-arg callers keep resolving cleanly). When external connections or shares exist,
-- p_coverage_complete = true requires a matching p_connection_origin_us.
DROP FUNCTION openmettle.restore_gate_lock(bigint, bigint, bytea, boolean, uuid, boolean, bigint, bytea);

CREATE FUNCTION openmettle.restore_gate_lock(
    p_origin_us bigint,
    p_required_seq bigint,
    p_required_digest bytea,
    p_coverage_complete boolean,
    p_replace_restore_run uuid DEFAULT NULL,
    p_new_restore boolean DEFAULT true,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
RETURNS openmettle.restore_reconciliation_gate
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_genesis bytea := decode(repeat('00', 32), 'hex');
    v_head_origin_us bigint;
    v_head_lifecycle_origin_us bigint;
    v_head_connection_origin_us bigint;
    v_snapshot_lifecycle_origin_us bigint;
    v_snapshot_lifecycle_baseline_digest bytea;
    v_snapshot_connection_origin_us bigint;
    v_has_connections boolean;
    v_stored_digest bytea;
    v_digest_hex text;
    v_req_hex text;
    v_effective_required_seq bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_required_seq IS NULL OR p_required_seq < 0
       OR p_required_digest IS NULL OR octet_length(p_required_digest) <> 32
       OR p_coverage_complete IS NULL OR p_new_restore IS NULL
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32)
       OR ((p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL)) THEN
        RAISE EXCEPTION 'invalid restore gate lock parameters' USING ERRCODE = '22023';
    END IF;
    IF p_required_seq = 0 AND p_required_digest <> v_genesis THEN
        RAISE EXCEPTION 'sequence 0 requires the genesis chain digest' USING ERRCODE = 'OMR03';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        IF NOT p_new_restore OR p_replace_restore_run IS NOT NULL THEN
            RAISE EXCEPTION 'cannot replace a restore run while the restore gate is open'
                USING ERRCODE = 'OMR02';
        END IF;
        g.gate_generation := g.gate_generation + 1;
    ELSE
        IF p_replace_restore_run IS NULL OR p_replace_restore_run IS DISTINCT FROM g.restore_run_id THEN
            RAISE EXCEPTION 'restore gate is already closed; pass --replace-restore-run matching current restore_run_id'
                USING ERRCODE = 'OMR02';
        END IF;
        IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
            RAISE EXCEPTION 'restore volume phase is active' USING ERRCODE = 'OMR02';
        END IF;
        g.volume_claim_token := NULL;
        g.volume_lease_until := NULL;
    END IF;

    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
    v_head_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    v_head_connection_origin_us := (extract(epoch FROM head.connection_coverage_started_at) * 1000000)::bigint;
    IF g.open THEN
        v_snapshot_lifecycle_origin_us := v_head_lifecycle_origin_us;
        v_snapshot_lifecycle_baseline_digest := head.lifecycle_baseline_digest;
        v_snapshot_connection_origin_us := v_head_connection_origin_us;
    ELSE
        v_snapshot_lifecycle_origin_us := g.snapshot_lifecycle_origin_us;
        v_snapshot_lifecycle_baseline_digest := g.snapshot_lifecycle_baseline_digest;
        v_snapshot_connection_origin_us := g.snapshot_connection_origin_us;
    END IF;
    v_has_connections := EXISTS (SELECT 1 FROM openmettle.external_connections)
                         OR EXISTS (SELECT 1 FROM openmettle.external_connection_shares);

    IF p_origin_us IS DISTINCT FROM v_head_origin_us THEN
        RAISE EXCEPTION 'required origin % does not match restored journal origin %',
            p_origin_us, v_head_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_coverage_complete
       AND (p_lifecycle_origin_us IS NULL
            OR p_lifecycle_origin_us IS DISTINCT FROM v_snapshot_lifecycle_origin_us) THEN
        RAISE EXCEPTION 'cannot assert complete export coverage when lifecycle journal origin % does not match restored %',
            p_lifecycle_origin_us, v_snapshot_lifecycle_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_coverage_complete
       AND p_lifecycle_baseline_digest IS DISTINCT FROM v_snapshot_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'cannot assert complete export coverage when lifecycle baseline digest does not match restored head'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_coverage_complete
       AND p_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM v_snapshot_connection_origin_us THEN
        RAISE EXCEPTION 'cannot assert complete export coverage when connection journal origin % does not match restored %',
            p_connection_origin_us, v_snapshot_connection_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_coverage_complete AND v_has_connections AND p_connection_origin_us IS NULL THEN
        RAISE EXCEPTION 'cannot assert complete export coverage for external connections without matching connection origin'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_required_seq <= head.journal_seq THEN
        IF p_required_seq = 0 THEN
            v_stored_digest := v_genesis;
        ELSE
            SELECT chain_digest INTO v_stored_digest
              FROM openmettle.deletion_journal
             WHERE journal_seq = p_required_seq;
        END IF;
        IF v_stored_digest IS DISTINCT FROM p_required_digest THEN
            RAISE EXCEPTION 'required watermark digest does not match stored journal at %',
                p_required_seq USING ERRCODE = 'OMR03';
        END IF;
    END IF;
    IF g.open OR p_new_restore THEN
        v_effective_required_seq := head.journal_seq;
    ELSE
        v_effective_required_seq := greatest(head.journal_seq, g.required_journal_seq);
    END IF;
    IF p_coverage_complete AND p_required_seq < v_effective_required_seq THEN
        RAISE EXCEPTION 'cannot assert complete export coverage for watermark % below target sequence %',
            p_required_seq, v_effective_required_seq USING ERRCODE = 'OMR04';
    END IF;

    v_digest_hex := encode(p_required_digest, 'hex');
    IF g.open OR p_new_restore THEN
        g.restore_run_id := gen_random_uuid();
        g.required_origin_us := p_origin_us;
        g.snapshot_lifecycle_origin_us := v_snapshot_lifecycle_origin_us;
        g.snapshot_lifecycle_baseline_digest := v_snapshot_lifecycle_baseline_digest;
        g.required_lifecycle_origin_us := p_lifecycle_origin_us;
        g.required_lifecycle_baseline_digest := p_lifecycle_baseline_digest;
        g.replayed_lifecycle_baseline_digest := NULL;
        g.snapshot_connection_origin_us := v_snapshot_connection_origin_us;
        g.required_connection_origin_us := p_connection_origin_us;
        g.connection_gap_reconciled := false;
        g.snapshot_journal_seq := head.journal_seq;
        g.locked_at := clock_timestamp();
        g.opened_at := NULL;
        g.coverage_complete := p_coverage_complete;
        g.volume_claim_token := NULL;
        g.volume_lease_until := NULL;
        g.checkpoints := jsonb_build_array(
            jsonb_build_object('seq', p_required_seq, 'digest', v_digest_hex)
        );
        IF p_required_seq >= head.journal_seq THEN
            g.required_journal_seq := p_required_seq;
            g.required_chain_digest := p_required_digest;
        ELSE
            g.required_journal_seq := head.journal_seq;
            g.required_chain_digest := head.chain_digest;
            v_req_hex := encode(head.chain_digest, 'hex');
            g.checkpoints := g.checkpoints || jsonb_build_array(
                jsonb_build_object('seq', head.journal_seq, 'digest', v_req_hex)
            );
        END IF;
    ELSE
        IF p_origin_us IS DISTINCT FROM g.required_origin_us THEN
            RAISE EXCEPTION 'required origin % conflicts with locked restore origin %',
                p_origin_us, g.required_origin_us USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_lifecycle_origin_us IS NOT NULL
           AND p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
            RAISE EXCEPTION 'required lifecycle origin % conflicts with locked restore lifecycle origin %',
                p_lifecycle_origin_us, g.required_lifecycle_origin_us USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_lifecycle_origin_us IS NULL AND p_lifecycle_origin_us IS NOT NULL THEN
            g.required_lifecycle_origin_us := p_lifecycle_origin_us;
        END IF;
        IF g.required_lifecycle_baseline_digest IS NOT NULL
           AND p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'required lifecycle baseline digest conflicts with locked restore baseline'
                USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_lifecycle_baseline_digest IS NULL AND p_lifecycle_baseline_digest IS NOT NULL THEN
            g.required_lifecycle_baseline_digest := p_lifecycle_baseline_digest;
        END IF;
        IF g.required_connection_origin_us IS NOT NULL
           AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
            RAISE EXCEPTION 'required connection origin % conflicts with locked restore connection origin %',
                p_connection_origin_us, g.required_connection_origin_us USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_connection_origin_us IS NULL AND p_connection_origin_us IS NOT NULL THEN
            g.required_connection_origin_us := p_connection_origin_us;
        END IF;
        IF EXISTS (
            SELECT FROM pg_catalog.jsonb_array_elements(g.checkpoints) AS c
             WHERE (c->>'seq')::bigint = p_required_seq
               AND (c->>'digest') IS DISTINCT FROM v_digest_hex
        ) THEN
            RAISE EXCEPTION 'required watermark digest conflicts with pinned checkpoint at %',
                p_required_seq USING ERRCODE = 'OMR03';
        END IF;
        IF p_required_seq = g.required_journal_seq AND p_required_digest <> g.required_chain_digest THEN
            RAISE EXCEPTION 'required watermark digest conflicts with locked gate'
                USING ERRCODE = 'OMR03';
        END IF;
        IF NOT EXISTS (
            SELECT FROM pg_catalog.jsonb_array_elements(g.checkpoints) AS c
             WHERE (c->>'seq')::bigint = p_required_seq
        ) THEN
            g.checkpoints := g.checkpoints || jsonb_build_array(
                jsonb_build_object('seq', p_required_seq, 'digest', v_digest_hex)
            );
        END IF;
        IF p_required_seq > g.required_journal_seq THEN
            g.required_journal_seq := p_required_seq;
            g.required_chain_digest := p_required_digest;
            g.coverage_complete := p_coverage_complete;
        ELSIF p_required_seq = g.required_journal_seq THEN
            g.coverage_complete := g.coverage_complete OR p_coverage_complete;
        END IF;
    END IF;

    UPDATE openmettle.restore_reconciliation_gate
       SET open = false,
           restore_run_id = g.restore_run_id,
           required_origin_us = g.required_origin_us,
           snapshot_lifecycle_origin_us = g.snapshot_lifecycle_origin_us,
           snapshot_lifecycle_baseline_digest = g.snapshot_lifecycle_baseline_digest,
           required_lifecycle_origin_us = g.required_lifecycle_origin_us,
           required_lifecycle_baseline_digest = g.required_lifecycle_baseline_digest,
           replayed_lifecycle_baseline_digest = g.replayed_lifecycle_baseline_digest,
           snapshot_connection_origin_us = g.snapshot_connection_origin_us,
           required_connection_origin_us = g.required_connection_origin_us,
           connection_gap_reconciled = g.connection_gap_reconciled,
           gate_generation = g.gate_generation,
           snapshot_journal_seq = g.snapshot_journal_seq,
           required_journal_seq = g.required_journal_seq,
           required_chain_digest = g.required_chain_digest,
           checkpoints = g.checkpoints,
           coverage_complete = g.coverage_complete,
           volume_claim_token = NULL,
           volume_lease_until = NULL,
           locked_at = g.locked_at,
           opened_at = NULL
     WHERE id
    RETURNING * INTO STRICT g;
    RETURN g;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock(bigint, bigint, bytea, boolean, uuid, boolean, bigint, bytea, bigint) FROM PUBLIC;

-- Owner only: extend restore_verify_export to also lock referenced external_connections before
-- restore_reconciliation_gate and verify p_connection_origin_us.
DROP FUNCTION openmettle.restore_verify_export(bigint, bigint, bytea, bigint, bytea, uuid[]);

CREATE FUNCTION openmettle.restore_verify_export(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_lock_entity_ids uuid[] DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_head_lifecycle_origin_us bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'export verification requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32) THEN
        RAISE EXCEPTION 'invalid export verification parameters' USING ERRCODE = '22023';
    END IF;
    IF (p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL) THEN
        RAISE EXCEPTION 'schema-42 export must carry both lifecycle_origin and lifecycle_baseline'
            USING ERRCODE = 'OMR03';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(1330467394, 42);
    PERFORM 1
       FROM openmettle.artifact_revisions
      WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         OR state IN ('retained', 'purging')
      ORDER BY id ASC
        FOR UPDATE;
    PERFORM 1
       FROM openmettle.external_connections
      WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         OR id IN (
             SELECT connection_id
               FROM openmettle.external_connection_shares
              WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         )
      ORDER BY id ASC
        FOR UPDATE;
    SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
    END IF;
    IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase is active' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
    IF p_export_seq < g.snapshot_journal_seq
       OR p_export_seq < head.journal_seq
       OR p_export_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'export sequence % does not match locked restore requirement %',
            p_export_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'export watermark digest does not match locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    v_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR v_origin_us IS DISTINCT FROM p_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch: backup predates deletion journal creation or belongs to another installation'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'export lifecycle origin % does not match locked requirement %',
            p_lifecycle_origin_us, g.required_lifecycle_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'export lifecycle baseline digest does not match locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    IF p_lifecycle_origin_us IS NOT NULL
       AND p_lifecycle_origin_us = g.snapshot_lifecycle_origin_us
       AND p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'export lifecycle baseline digest does not match restored snapshot'
            USING ERRCODE = 'OMR03';
    END IF;
    IF p_lifecycle_origin_us IS NOT NULL
       AND p_lifecycle_origin_us = v_head_lifecycle_origin_us
       AND p_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'export lifecycle baseline digest does not match restored installation head'
            USING ERRCODE = 'OMR03';
    END IF;
    IF g.required_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
        RAISE EXCEPTION 'export connection origin % does not match locked requirement %',
            p_connection_origin_us, g.required_connection_origin_us USING ERRCODE = 'OMR04';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_verify_export(bigint, bigint, bytea, bigint, bytea, uuid[], bigint) FROM PUBLIC;

-- Owner only: extend restore_claim_volume_phase with optional trailing p_connection_origin_us.
DROP FUNCTION openmettle.restore_claim_volume_phase(bigint, bigint, bytea, bigint, bytea);

CREATE FUNCTION openmettle.restore_claim_volume_phase(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
RETURNS TABLE(restore_run_id uuid, volume_claim_token uuid)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_lifecycle_origin_us bigint;
    v_token uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore volume phase claim requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32) THEN
        RAISE EXCEPTION 'invalid restore volume phase parameters' USING ERRCODE = '22023';
    END IF;
    IF (p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL) THEN
        RAISE EXCEPTION 'lifecycle origin and lifecycle baseline digest must be supplied together'
            USING ERRCODE = 'OMR03';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'restore gate is not closed' USING ERRCODE = 'OMR02';
    END IF;
    IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase is already active' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
    v_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    v_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'lifecycle journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest does not match locked requirement' USING ERRCODE = 'OMR03';
    END IF;
    IF g.required_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
        RAISE EXCEPTION 'connection journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS NOT NULL AND p_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
        IF p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
           OR p_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle baseline digest does not match restored head' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_lifecycle_origin_us IS NOT NULL THEN
        IF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest
           OR v_lifecycle_origin_us IS DISTINCT FROM p_lifecycle_origin_us
           OR head.lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle upgrade baseline must be replayed before claiming volume phase'
                USING ERRCODE = 'OMR04';
        END IF;
    END IF;
    IF p_export_seq IS DISTINCT FROM head.journal_seq OR head.journal_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export sequence does not match restored head or locked requirement'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM head.chain_digest OR head.chain_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'journal chain digest does not match export or locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    PERFORM openmettle.restore_verify_checkpoints();
    IF p_lifecycle_origin_us IS NOT NULL AND EXISTS (
        SELECT 1
          FROM openmettle.artifact_revisions r
         WHERE r.state IN ('retained', 'purging')
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.retention_upgrade_baseline b
                WHERE b.artifact_revision_id = r.id
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.deletion_journal j
                WHERE j.entity_id = r.id
                  AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
           )
    ) THEN
        RAISE EXCEPTION 'unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal'
            USING ERRCODE = 'OMR04';
    END IF;
    v_token := gen_random_uuid();
    UPDATE openmettle.restore_reconciliation_gate
       SET volume_claim_token = v_token,
           volume_lease_until = clock_timestamp() + interval '300 seconds'
     WHERE id;
    RETURN QUERY SELECT g.restore_run_id, v_token;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_claim_volume_phase(bigint, bigint, bytea, bigint, bytea, bigint) FROM PUBLIC;

-- Owner only: extend deletion_journal_replay to replay external connection disconnects,
-- credential supersessions, and share revocations alongside artifact revision commitments.
CREATE OR REPLACE FUNCTION openmettle.deletion_journal_replay(
    p_seq bigint, p_recorded_us bigint, p_event_kind text, p_entity_id uuid, p_scope_id uuid,
    p_original_purge_after_us bigint, p_purged_us bigint, p_content_digest bytea,
    p_policy_revision bigint, p_chain_digest bytea, p_retained_us bigint DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    e openmettle.deletion_journal%ROWTYPE;
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_state text;
    v_size bigint;
    v_content bytea;
    v_conn_id uuid;
    v_conn_state text;
    v_conn_gen bigint;
    v_share_active boolean;
    v_share_rev bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'journal replay requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_seq IS NULL OR p_seq <= 0 OR p_recorded_us IS NULL
       OR p_event_kind IS NULL
       OR p_entity_id IS NULL OR p_scope_id IS NULL
       OR p_content_digest IS NULL OR octet_length(p_content_digest) <> 32
       OR p_chain_digest IS NULL OR octet_length(p_chain_digest) <> 32
       OR (p_policy_revision IS NOT NULL AND p_policy_revision <= 0) THEN
        RAISE EXCEPTION 'invalid journal replay record' USING ERRCODE = 'OMR03';
    END IF;
    IF p_event_kind = 'artifact_revision.purged' THEN
        IF p_original_purge_after_us IS NULL OR p_purged_us IS NULL OR p_retained_us IS NOT NULL THEN
            RAISE EXCEPTION 'invalid purged journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_event_kind IN ('artifact_revision.retained', 'artifact_revision.deadline_adjusted') THEN
        IF p_retained_us IS NULL OR p_original_purge_after_us IS NULL
           OR p_original_purge_after_us < p_retained_us OR p_purged_us IS NOT NULL THEN
            RAISE EXCEPTION 'invalid retention journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_event_kind = 'artifact_revision.restored' THEN
        IF p_retained_us IS NOT NULL OR p_original_purge_after_us IS NOT NULL OR p_purged_us IS NOT NULL THEN
            RAISE EXCEPTION 'invalid restore journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_event_kind IN (
        'external_connection.disconnected',
        'external_connection.credential_superseded',
        'external_connection.share_revoked'
    ) THEN
        IF p_retained_us IS NOT NULL OR p_original_purge_after_us IS NOT NULL
           OR p_purged_us IS NOT NULL OR p_policy_revision IS NULL THEN
            RAISE EXCEPTION 'invalid external connection journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown journal replay event kind' USING ERRCODE = 'OMR03';
    END IF;

    e.journal_seq := p_seq;
    e.recorded_at := timestamptz 'epoch' + p_recorded_us * interval '1 microsecond';
    e.event_kind := p_event_kind;
    e.entity_id := p_entity_id;
    e.scope_id := p_scope_id;
    e.original_purge_after := CASE WHEN p_original_purge_after_us IS NOT NULL
        THEN timestamptz 'epoch' + p_original_purge_after_us * interval '1 microsecond' END;
    e.purged_at := CASE WHEN p_purged_us IS NOT NULL
        THEN timestamptz 'epoch' + p_purged_us * interval '1 microsecond' END;
    e.content_digest := p_content_digest;
    e.policy_revision := p_policy_revision;
    e.chain_digest := p_chain_digest;
    e.retained_at := CASE WHEN p_retained_us IS NOT NULL
        THEN timestamptz 'epoch' + p_retained_us * interval '1 microsecond' END;

    PERFORM pg_catalog.pg_advisory_xact_lock(1330467394, 42);
    IF p_seq <= (SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id) THEN
        PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF NOT EXISTS (SELECT FROM openmettle.deletion_journal j
                        WHERE j.journal_seq = p_seq AND j IS NOT DISTINCT FROM e) THEN
            RAISE EXCEPTION 'exported journal record % differs from the restored journal', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        RETURN false;
    END IF;

    IF p_event_kind LIKE 'artifact_revision.%' THEN
        SELECT state, size_bytes, content_digest INTO v_state, v_size, v_content
          FROM openmettle.artifact_revisions WHERE scope_id = p_scope_id AND id = p_entity_id FOR UPDATE;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_state IS NOT NULL AND v_content IS DISTINCT FROM p_content_digest THEN
            RAISE EXCEPTION 'journal record % names a revision with other content', p_seq
                USING ERRCODE = 'OMR03';
        END IF;

        IF p_event_kind = 'artifact_revision.purged' THEN
            IF v_state = 'purged' THEN
                RAISE EXCEPTION 'journal record % names a revision already purged under another sequence', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF EXISTS (SELECT FROM openmettle.deletion_journal
                        WHERE event_kind = 'artifact_revision.purged' AND entity_id = e.entity_id) THEN
                RAISE EXCEPTION 'journal record % duplicates an existing purged entity', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF g.required_lifecycle_origin_us IS NOT NULL
               AND p_recorded_us > g.required_lifecycle_origin_us
               AND NOT EXISTS (
                   SELECT 1
                     FROM openmettle.retention_upgrade_baseline b
                    WHERE b.artifact_revision_id = p_entity_id
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM openmettle.deletion_journal j
                    WHERE j.entity_id = p_entity_id
                      AND j.event_kind = 'artifact_revision.retained'
                      AND j.journal_seq < p_seq
               ) THEN
                RAISE EXCEPTION 'post-upgrade purge record % lacks baseline or prior retained commitment', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            DELETE FROM openmettle.artifact_retention_holds
             WHERE scope_id = p_scope_id AND artifact_revision_id = p_entity_id;
            IF v_state = 'active' THEN
                PERFORM openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
                 WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
                UPDATE openmettle.storage_accounts
                   SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size
                 WHERE scope_id = p_scope_id;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
                END IF;
                UPDATE openmettle.storage_instance
                   SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size;
            END IF;
            IF v_state IN ('active', 'retained') THEN
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
                UPDATE openmettle.artifact_revisions
                   SET state = 'purging',
                       retained_at = least(coalesce(retained_at, e.original_purge_after), e.original_purge_after),
                       purge_after = e.original_purge_after,
                       retention_policy_revision = e.policy_revision,
                       purging_at = greatest(clock_timestamp(), e.original_purge_after)
                 WHERE scope_id = p_scope_id AND id = p_entity_id;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
            END IF;
        ELSIF p_event_kind = 'artifact_revision.retained' THEN
            IF v_state IN ('purging', 'purged') THEN
                RAISE EXCEPTION 'journal record % cannot transition a purging or purged revision', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF v_state = 'active' THEN
                PERFORM openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
                 WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
                UPDATE openmettle.storage_accounts
                   SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size
                 WHERE scope_id = p_scope_id;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
                END IF;
                UPDATE openmettle.storage_instance
                   SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size;
            END IF;
            IF v_state IN ('active', 'retained') THEN
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
                UPDATE openmettle.artifact_revisions
                   SET state = 'retained',
                       retained_at = e.retained_at,
                       purge_after = e.original_purge_after,
                       retention_policy_revision = e.policy_revision
                 WHERE scope_id = p_scope_id AND id = p_entity_id;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
            END IF;
        ELSIF p_event_kind = 'artifact_revision.deadline_adjusted' THEN
            IF (v_state IS NOT NULL AND v_state <> 'retained')
               OR (NOT EXISTS (
                       SELECT 1 FROM openmettle.retention_upgrade_baseline b
                        WHERE b.artifact_revision_id = p_entity_id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM openmettle.deletion_journal j
                        WHERE j.entity_id = p_entity_id
                          AND j.event_kind = 'artifact_revision.retained'
                          AND j.journal_seq < p_seq
                   )) THEN
                RAISE EXCEPTION 'journal record % requires a retained revision for deadline adjustment', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF v_state = 'retained' THEN
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
                UPDATE openmettle.artifact_revisions
                   SET retained_at = e.retained_at,
                       purge_after = e.original_purge_after,
                       retention_policy_revision = e.policy_revision
                 WHERE scope_id = p_scope_id AND id = p_entity_id;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
            END IF;
        ELSIF p_event_kind = 'artifact_revision.restored' THEN
            IF (v_state IS NOT NULL AND v_state <> 'retained')
               OR (NOT EXISTS (
                       SELECT 1 FROM openmettle.retention_upgrade_baseline b
                        WHERE b.artifact_revision_id = p_entity_id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM openmettle.deletion_journal j
                        WHERE j.entity_id = p_entity_id
                          AND j.event_kind = 'artifact_revision.retained'
                          AND j.journal_seq < p_seq
                   )) THEN
                RAISE EXCEPTION 'journal record % requires a retained revision for restore', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF v_state = 'retained' THEN
                PERFORM openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
                 WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
                UPDATE openmettle.storage_accounts
                   SET retained_bytes = retained_bytes - v_size, active_bytes = active_bytes + v_size
                 WHERE scope_id = p_scope_id;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
                END IF;
                UPDATE openmettle.storage_instance
                   SET retained_bytes = retained_bytes - v_size, active_bytes = active_bytes + v_size;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
                UPDATE openmettle.artifact_revisions
                   SET state = 'active',
                       retained_at = NULL,
                       purge_after = NULL,
                       retention_policy_revision = NULL
                 WHERE scope_id = p_scope_id AND id = p_entity_id;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
            END IF;
        END IF;

        IF e.policy_revision IS NOT NULL THEN
            UPDATE openmettle.retention_policy
               SET revision = e.policy_revision + 1
             WHERE id AND revision <= e.policy_revision;
        END IF;
    ELSIF p_event_kind = 'external_connection.disconnected' THEN
        IF p_content_digest IS DISTINCT FROM sha256(convert_to(
            'disconnect:' || p_entity_id::text || ':' || p_policy_revision::text, 'UTF8')) THEN
            RAISE EXCEPTION 'invalid external connection disconnect journal digest at %', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        SELECT state INTO v_conn_state
          FROM openmettle.external_connections
         WHERE id = p_entity_id AND scope_id = p_scope_id
           FOR UPDATE;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_conn_state IS NOT NULL THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            IF v_conn_state <> 'disconnected' THEN
                UPDATE openmettle.external_connections
                   SET granted_scopes = ARRAY[]::text[],
                       state = 'disconnected',
                       expires_at = NULL,
                       encryption_key_id = NULL,
                       access_salt = NULL,
                       access_nonce = NULL,
                       access_ciphertext = NULL,
                       refresh_salt = NULL,
                       refresh_nonce = NULL,
                       refresh_ciphertext = NULL,
                       revocation_generation = greatest(revocation_generation + 1, p_policy_revision),
                       refresh_claim_token = NULL,
                       refresh_lease_until = NULL,
                       disconnected_at = coalesce(disconnected_at, e.recorded_at),
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id;
            ELSE
                UPDATE openmettle.external_connections
                   SET revocation_generation = greatest(revocation_generation, p_policy_revision),
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id
                   AND revocation_generation < p_policy_revision;
            END IF;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind = 'external_connection.credential_superseded' THEN
        IF p_content_digest IS DISTINCT FROM sha256(convert_to(
            'superseded:' || p_entity_id::text || ':' || p_policy_revision::text, 'UTF8')) THEN
            RAISE EXCEPTION 'invalid external connection supersession journal digest at %', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        SELECT state, credential_generation INTO v_conn_state, v_conn_gen
          FROM openmettle.external_connections
         WHERE id = p_entity_id AND scope_id = p_scope_id
           FOR UPDATE;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_conn_state IS NOT NULL THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            IF v_conn_state = 'authorized' AND v_conn_gen < p_policy_revision THEN
                UPDATE openmettle.external_connections
                   SET granted_scopes = ARRAY[]::text[],
                       state = 'reauth_required',
                       expires_at = NULL,
                       encryption_key_id = NULL,
                       access_salt = NULL,
                       access_nonce = NULL,
                       access_ciphertext = NULL,
                       refresh_salt = NULL,
                       refresh_nonce = NULL,
                       refresh_ciphertext = NULL,
                       credential_generation = p_policy_revision,
                       revocation_generation = revocation_generation + 1,
                       refresh_claim_token = NULL,
                       refresh_lease_until = NULL,
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id;
            ELSIF v_conn_state IN ('pending_auth', 'reauth_required')
                  AND v_conn_gen < p_policy_revision THEN
                UPDATE openmettle.external_connections
                   SET credential_generation = p_policy_revision,
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id;
            END IF;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind = 'external_connection.share_revoked' THEN
        SELECT connection_id INTO v_conn_id
          FROM openmettle.external_connection_shares
         WHERE id = p_entity_id AND scope_id = p_scope_id;
        IF v_conn_id IS NOT NULL THEN
            IF p_content_digest IS DISTINCT FROM sha256(convert_to(
                'share_revoked:' || p_entity_id::text || ':' || v_conn_id::text || ':' || p_policy_revision::text,
                'UTF8')) THEN
                RAISE EXCEPTION 'invalid external connection share revocation journal digest at %', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            PERFORM 1 FROM openmettle.external_connections
             WHERE id = v_conn_id AND scope_id = p_scope_id
               FOR UPDATE;
            SELECT active, revision INTO v_share_active, v_share_rev
              FROM openmettle.external_connection_shares
             WHERE id = p_entity_id AND scope_id = p_scope_id
               FOR UPDATE;
        END IF;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_conn_id IS NOT NULL AND (v_share_active OR v_share_rev < p_policy_revision) THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.external_connection_shares
               SET active = false,
                   revision = greatest(revision + 1, p_policy_revision),
                   updated_at = clock_timestamp()
             WHERE id = p_entity_id AND scope_id = p_scope_id;
            UPDATE openmettle.external_connections
               SET share_revision = share_revision + 1,
                   revocation_generation = revocation_generation + 1,
                   updated_at = clock_timestamp()
             WHERE id = v_conn_id AND scope_id = p_scope_id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    END IF;

    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    IF p_seq <> head.journal_seq + 1
       OR p_chain_digest IS DISTINCT FROM openmettle.deletion_journal_digest(head.chain_digest, e) THEN
        RAISE EXCEPTION 'journal record % does not extend the restored chain', p_seq
            USING ERRCODE = 'OMR03';
    END IF;
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head SET journal_seq = p_seq, chain_digest = p_chain_digest
     WHERE id;
    RETURN true;
END
$$;

-- Owner only: extend restore_gate_open with optional trailing p_connection_origin_us and enforce
-- that zero authorized external connections or active shares survive an unverified connection
-- coverage gap (OMR04).
DROP FUNCTION openmettle.restore_gate_open(uuid, uuid, bigint, bigint, bytea, uuid, bigint, bytea);

CREATE FUNCTION openmettle.restore_gate_open(
    p_restore_run_id uuid,
    p_claim_token uuid,
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_expected_volume_id uuid,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_lifecycle_origin_us bigint;
    v_connection_origin_us bigint;
    v_volume_id uuid;
    v_adoption_run_id uuid;
    v_has_live_conn_auth boolean;
    v_conn_origin_verified boolean;
    v_gap_accepted boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL OR p_claim_token IS NULL
       OR p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32) THEN
        RAISE EXCEPTION 'invalid restore gate open parameters' USING ERRCODE = '22023';
    END IF;
    IF (p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL) THEN
        RAISE EXCEPTION 'lifecycle origin and lifecycle baseline digest must be supplied together'
            USING ERRCODE = 'OMR03';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'restore gate is not closed' USING ERRCODE = 'OMR02';
    END IF;
    IF g.restore_run_id IS DISTINCT FROM p_restore_run_id
       OR g.volume_claim_token IS DISTINCT FROM p_claim_token
       OR g.volume_lease_until IS NULL
       OR g.volume_lease_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase lease lost or mismatched' USING ERRCODE = 'OMR02';
    END IF;
    SELECT volume_id, adoption_run_id
      INTO STRICT v_volume_id, v_adoption_run_id
      FROM openmettle.storage_volume_control
     WHERE id
       FOR SHARE;
    IF v_adoption_run_id IS NOT NULL OR v_volume_id IS DISTINCT FROM p_expected_volume_id THEN
        RAISE EXCEPTION 'storage volume pin changed or adoption/rebind in progress'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF NOT g.coverage_complete THEN
        RAISE EXCEPTION 'unexported purge window after last export; inspect or run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
    v_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    v_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    v_connection_origin_us := (extract(epoch FROM head.connection_coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'lifecycle journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest does not match locked requirement' USING ERRCODE = 'OMR03';
    END IF;
    IF g.required_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
        RAISE EXCEPTION 'connection journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS NOT NULL AND p_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
        IF p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
           OR p_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle baseline digest does not match restored head' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_lifecycle_origin_us IS NOT NULL THEN
        IF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest
           OR v_lifecycle_origin_us IS DISTINCT FROM p_lifecycle_origin_us
           OR head.lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle upgrade baseline must be replayed before opening restore gate'
                USING ERRCODE = 'OMR04';
        END IF;
    END IF;
    v_gap_accepted := EXISTS (
        SELECT FROM openmettle.authorization_audit
         WHERE actor_kind = 'operator'
           AND action = 'restore.accept_coverage_gap'
           AND target_kind = 'restore_gate'
           AND target_id = 'instance'
           AND (details->>'restore_run_id') = g.restore_run_id::text
           AND (details->>'required_journal_seq')::bigint = g.required_journal_seq
           AND (details->>'required_chain_digest') = encode(g.required_chain_digest, 'hex')
    );
    IF (p_lifecycle_origin_us IS NULL
        OR p_lifecycle_origin_us IS DISTINCT FROM g.snapshot_lifecycle_origin_us
        OR p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest)
       AND NOT v_gap_accepted THEN
        RAISE EXCEPTION 'backup predates lifecycle journal coverage; inspect or run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    v_has_live_conn_auth := EXISTS (
        SELECT 1 FROM openmettle.external_connections WHERE state = 'authorized'
    ) OR EXISTS (
        SELECT 1 FROM openmettle.external_connection_shares WHERE active
    );
    v_conn_origin_verified := g.required_connection_origin_us IS NOT NULL
        AND p_connection_origin_us = g.required_connection_origin_us
        AND g.required_connection_origin_us = g.snapshot_connection_origin_us
        AND g.required_connection_origin_us = v_connection_origin_us
        AND NOT g.connection_gap_reconciled
        AND NOT v_gap_accepted;
    IF NOT v_conn_origin_verified AND v_has_live_conn_auth THEN
        RAISE EXCEPTION 'authorized external connections or active shares cannot survive an unverified connection coverage gap; run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_seq IS DISTINCT FROM head.journal_seq
       OR head.journal_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export ends at %, the restored journal at %, restore requires %',
            p_export_seq, head.journal_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM head.chain_digest
       OR head.chain_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'journal chain digest does not match export or locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    PERFORM openmettle.restore_verify_checkpoints();
    IF p_lifecycle_origin_us IS NOT NULL AND EXISTS (
        SELECT 1
          FROM openmettle.artifact_revisions r
         WHERE r.state IN ('retained', 'purging')
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.retention_upgrade_baseline b
                WHERE b.artifact_revision_id = r.id
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.deletion_journal j
                WHERE j.entity_id = r.id
                  AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
           )
    ) THEN
        RAISE EXCEPTION 'unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal'
            USING ERRCODE = 'OMR04';
    END IF;
    IF EXISTS (SELECT FROM openmettle.deletion_journal j JOIN openmettle.artifact_revisions r
                 ON r.scope_id = j.scope_id AND r.id = j.entity_id
                WHERE j.event_kind = 'artifact_revision.purged' AND r.state <> 'purged') THEN
        RAISE EXCEPTION 'journaled revisions are not purged yet' USING ERRCODE = 'OMR05';
    END IF;
    UPDATE openmettle.restore_reconciliation_gate
       SET open = true,
           opened_at = clock_timestamp(),
           restore_run_id = NULL,
           required_origin_us = NULL,
           snapshot_lifecycle_origin_us = NULL,
           snapshot_lifecycle_baseline_digest = NULL,
           required_lifecycle_origin_us = NULL,
           required_lifecycle_baseline_digest = NULL,
           replayed_lifecycle_baseline_digest = NULL,
           snapshot_connection_origin_us = NULL,
           required_connection_origin_us = NULL,
           connection_gap_reconciled = false,
           checkpoints = '[]'::jsonb,
           volume_claim_token = NULL,
           volume_lease_until = NULL
     WHERE id;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_open(uuid, uuid, bigint, bigint, bytea, uuid, bigint, bytea, bigint) FROM PUBLIC;

-- Owner only: break-glass coverage-gap acceptance also transitions every authorized external
-- connection to reauth_required (wiping stored ciphertexts) and deactivates every active
-- connection share so no unverified post-backup authorization can survive an incomplete journal.
CREATE OR REPLACE FUNCTION openmettle.restore_accept_coverage_gap(
    p_restore_run_id uuid,
    p_operator_id uuid,
    p_request_key text,
    p_reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    v_details jsonb;
    v_existing record;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL
       OR p_operator_id IS NULL
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 512
       OR btrim(p_reason) <> p_reason
       OR p_reason COLLATE "C" ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid coverage gap acceptance parameters' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM openmettle.external_connections ORDER BY id ASC FOR UPDATE;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open OR g.restore_run_id IS DISTINCT FROM p_restore_run_id THEN
        RAISE EXCEPTION 'restore gate is not closed under the specified restore_run_id'
            USING ERRCODE = 'OMR02';
    END IF;
    v_details := jsonb_build_object(
        'restore_run_id', g.restore_run_id,
        'required_origin_us', g.required_origin_us,
        'required_lifecycle_origin_us', g.required_lifecycle_origin_us,
        'required_lifecycle_baseline_digest', encode(g.required_lifecycle_baseline_digest, 'hex'),
        'required_connection_origin_us', g.required_connection_origin_us,
        'snapshot_journal_seq', g.snapshot_journal_seq,
        'required_journal_seq', g.required_journal_seq,
        'required_chain_digest', encode(g.required_chain_digest, 'hex')
    );
    SELECT actor_kind, operator_id, target_kind, target_id, reason, details
      INTO v_existing
      FROM openmettle.authorization_audit
     WHERE actor_kind = 'operator'
       AND action = 'restore.accept_coverage_gap'
       AND request_key = p_request_key;
    IF FOUND THEN
        IF v_existing.actor_kind = 'operator'
           AND v_existing.operator_id = p_operator_id
           AND v_existing.target_kind = 'restore_gate'
           AND v_existing.target_id = 'instance'
           AND v_existing.reason = p_reason
           AND v_existing.details = v_details THEN
            RETURN false;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;

    PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
    WITH deactivated AS (
        UPDATE openmettle.external_connection_shares
           SET active = false,
               revision = revision + 1,
               updated_at = clock_timestamp()
         WHERE active
        RETURNING connection_id
    )
    UPDATE openmettle.external_connections c
       SET share_revision = c.share_revision + 1,
           revocation_generation = c.revocation_generation + 1,
           updated_at = clock_timestamp()
     WHERE c.id IN (SELECT DISTINCT connection_id FROM deactivated);

    UPDATE openmettle.external_connections
       SET granted_scopes = ARRAY[]::text[],
           state = 'reauth_required',
           expires_at = NULL,
           encryption_key_id = NULL,
           access_salt = NULL,
           access_nonce = NULL,
           access_ciphertext = NULL,
           refresh_salt = NULL,
           refresh_nonce = NULL,
           refresh_ciphertext = NULL,
           revocation_generation = revocation_generation + 1,
           refresh_claim_token = NULL,
           refresh_lease_until = NULL,
           updated_at = clock_timestamp()
     WHERE state = 'authorized';
    PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);

    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id, request_key, reason, details)
    VALUES
        ('operator', NULL, p_operator_id, 'restore.accept_coverage_gap', 'restore_gate',
         'instance', p_request_key, p_reason, v_details);
    UPDATE openmettle.restore_reconciliation_gate
       SET coverage_complete = true,
           connection_gap_reconciled = true
     WHERE id;
    RETURN true;
END
$$;

-- Least-privilege table and column grants (zero privileges for PUBLIC, issuance, gateway).
REVOKE ALL ON TABLE openmettle.external_connections,
    openmettle.external_connection_shares FROM PUBLIC;

-- API: read non-secret metadata only; write-only to encrypted secret columns on authorize/disconnect.
GRANT SELECT (
    id, scope_id, scope_kind, owner_user_id, provider_kind, account_id,
    endpoint_origin, allowed_scopes, granted_scopes, state, expires_at,
    has_refresh, credential_generation, revocation_generation, share_revision,
    created_at, updated_at, disconnected_at
) ON openmettle.external_connections TO openmettle_api;
GRANT INSERT (
    id, scope_id, scope_kind, owner_user_id, provider_kind, account_id,
    endpoint_origin, allowed_scopes
) ON openmettle.external_connections TO openmettle_api;
GRANT UPDATE (
    granted_scopes, state, expires_at,
    encryption_key_id,
    access_salt, access_nonce, access_ciphertext,
    refresh_salt, refresh_nonce, refresh_ciphertext,
    credential_generation, revocation_generation, share_revision,
    refresh_claim_token, refresh_lease_until,
    updated_at, disconnected_at
) ON openmettle.external_connections TO openmettle_api;

GRANT SELECT ON openmettle.external_connection_shares TO openmettle_api;
GRANT INSERT (
    connection_id, scope_id, grantee_kind, grantee_user_id,
    grantee_local_group_id, grantee_oidc_group_id,
    access, active, updated_by_user_id
) ON openmettle.external_connection_shares TO openmettle_api;
GRANT UPDATE (
    active, revision, updated_at, updated_by_user_id
) ON openmettle.external_connection_shares TO openmettle_api;

-- Worker: reads connection rows and shares for execution-time resolution; updates strictly
-- refresh lease/secret/reauth columns (guarded by external_connections_guards).
GRANT SELECT ON openmettle.external_connections,
    openmettle.external_connection_shares TO openmettle_worker;
GRANT UPDATE (
    granted_scopes, state, expires_at,
    encryption_key_id,
    access_salt, access_nonce, access_ciphertext,
    refresh_salt, refresh_nonce, refresh_ciphertext,
    credential_generation, revocation_generation,
    refresh_claim_token, refresh_lease_until,
    updated_at
) ON openmettle.external_connections TO openmettle_worker;
