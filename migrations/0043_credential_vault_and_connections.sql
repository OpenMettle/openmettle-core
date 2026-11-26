-- V1-28 migration 43 (ADR 0045): credential vault and external connection lifecycle.
-- Adds scope-owned openmettle.external_connections (encrypted access/refresh secrets,
-- non-widening allowed/granted scopes, single-flight refresh leasing and monotonic
-- credential/revocation/share generations), explicit openmettle.external_connection_shares,
-- monotonic/restore-gate triggers, two worker SECURITY DEFINER helpers (scope lifecycle and
-- redacted worker audit), and widens authorization_audit for connection and vault events.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (ADR 0027, ADR 0041, ADR 0045):
--   account_admin_lock -> projects -> login_providers -> local_identity_approvals ->
--   users (ascending id) -> external_connections -> external_connection_shares ->
--   restore_reconciliation_gate (FOR SHARE).
--
-- Role boundaries (verified by src/boundaries.sql):
--   - openmettle_api: column-scoped SELECT on non-secret metadata + has_refresh only (zero
--     SELECT on ciphertext, salt, nonce, encryption_key_id or refresh lease columns),
--     column-scoped INSERT/UPDATE for connection metadata, write-only authorization,
--     disconnect and explicit sharing. No DELETE or TRUNCATE.
--   - openmettle_worker: SELECT on external_connections and external_connection_shares,
--     column-scoped UPDATE strictly for refresh leasing/commit and reauth_required
--     transitions (trigger-guarded), plus EXECUTE on external_connection_scope_lifecycle
--     and external_connection_audit_worker. Zero SELECT on project_settings or
--     authorization_audit.
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
            LOCK TABLE openmettle.authorization_audit
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
        OR pg_catalog.octet_length(access_ciphertext) BETWEEN 17 AND 16400
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
-- disconnected state, and worker refresh-only transition boundaries.
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
