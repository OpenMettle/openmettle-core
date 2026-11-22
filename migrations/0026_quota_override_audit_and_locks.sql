-- V1-17 migration 26: transactional quota override audit consolidation, adoption-lock helper,
-- active-only override limit_revision semantics, and executing-rule probe partial index.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.

-- Serialize quota override mutations against storage volume adoption without requiring a pinned
-- volume, so unpinned deployments may manage overrides while adoption runs cannot overlap.
CREATE FUNCTION openmettle.storage_lock_not_adopting()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_adopt uuid;
BEGIN
    SELECT adoption_run_id
      INTO v_adopt
      FROM openmettle.storage_volume_control
     WHERE id
       FOR SHARE;
    IF NOT FOUND OR v_adopt IS NOT NULL THEN
        RAISE EXCEPTION 'storage volume adoption is in progress'
            USING ERRCODE = 'OMQ03';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.storage_lock_not_adopting() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.storage_lock_not_adopting() TO openmettle_api;

-- Partial index for the hot claim_next executing-rule probe so unrelated storage/usage overrides
-- are never scanned under run_dispatch_lock.
CREATE INDEX quota_overrides_executing_active_idx
    ON openmettle.quota_overrides (resource_kind)
    WHERE resource_kind IN ('executing_runs_per_actor', 'executing_runs_per_scope')
      AND revoked_at IS NULL;

-- Consolidate override mutations to record exactly one authoritative authorization_audit row
-- carrying both the SQL audit fields and the caller's idempotency request/response snapshot.
DROP FUNCTION openmettle.quota_upsert_scope_override(uuid, uuid, text, bigint, timestamptz, text);
DROP FUNCTION openmettle.quota_revoke_scope_override(uuid, uuid, text, text);

CREATE FUNCTION openmettle.quota_upsert_scope_override(
    p_scope uuid,
    p_actor uuid,
    p_resource text,
    p_limit bigint,
    p_expires timestamptz,
    p_reason text,
    p_request_key text DEFAULT NULL,
    p_request jsonb DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    kind text;
    prior bigint;
    rec openmettle.quota_overrides%ROWTYPE;
    v_details jsonb;
BEGIN
    IF p_request_key IS NOT NULL AND (octet_length(p_request_key) = 0 OR octet_length(p_request_key) > 128) THEN
        RAISE EXCEPTION 'invalid request_key' USING ERRCODE = '23514';
    END IF;
    kind := openmettle.quota_lock_override(p_scope, p_actor, p_resource);
    IF p_resource = 'usage_cost_micros' AND NOT EXISTS (
        SELECT FROM openmettle.quota_defaults
         WHERE scope_kind = 'instance'
           AND resource_kind = p_resource
           AND cost_denomination IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cost denomination required' USING ERRCODE = 'OMQ02';
    END IF;
    SELECT hard_limit
      INTO prior
      FROM openmettle.quota_overrides
     WHERE scope_id = p_scope
       AND resource_kind = p_resource
       AND revoked_at IS NULL
       AND (expires_at IS NULL OR expires_at > clock_timestamp());
    INSERT INTO openmettle.quota_overrides AS o (
        scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id
    )
    VALUES (p_scope, kind, p_resource, p_limit, p_expires, p_reason, p_actor)
    ON CONFLICT (scope_id, resource_kind) DO UPDATE SET
        hard_limit = excluded.hard_limit,
        expires_at = excluded.expires_at,
        revoked_at = NULL,
        reason = excluded.reason,
        updated_by_user_id = p_actor,
        updated_at = clock_timestamp(),
        revision = o.revision + 1
    RETURNING * INTO STRICT rec;
    v_details := jsonb_build_object(
        'scope_id', p_scope,
        'resource_kind', p_resource,
        'old_limit', prior,
        'new_limit', p_limit,
        'expires_at', p_expires,
        'revision', rec.revision
    );
    IF p_request IS NOT NULL THEN
        v_details := v_details || jsonb_build_object(
            'request', p_request,
            'response', jsonb_build_object(
                'scope_id', rec.scope_id::text,
                'scope_kind', rec.scope_kind,
                'resource_kind', rec.resource_kind,
                'hard_limit', rec.hard_limit::text,
                'expires_at', CASE WHEN rec.expires_at IS NOT NULL
                                   THEN to_char(rec.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
                'revoked_at', CASE WHEN rec.revoked_at IS NOT NULL
                                   THEN to_char(rec.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
                'revision', rec.revision::text,
                'updated_at', to_char(rec.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            )
        );
    END IF;
    INSERT INTO openmettle.authorization_audit (
        actor_user_id, action, target_kind, target_id, request_key, reason, details
    )
    VALUES (
        p_actor,
        'quota.override.set',
        'quota_scope',
        p_scope::text,
        coalesce(p_request_key, gen_random_uuid()::text),
        p_reason,
        v_details
    );
    RETURN rec.revision;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_upsert_scope_override(uuid, uuid, text, bigint, timestamptz, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_upsert_scope_override(uuid, uuid, text, bigint, timestamptz, text, text, jsonb) TO openmettle_api;

CREATE FUNCTION openmettle.quota_revoke_scope_override(
    p_scope uuid,
    p_actor uuid,
    p_resource text,
    p_reason text,
    p_request_key text DEFAULT NULL,
    p_request jsonb DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    prior bigint;
    rec openmettle.quota_overrides%ROWTYPE;
    v_details jsonb;
BEGIN
    IF p_request_key IS NOT NULL AND (octet_length(p_request_key) = 0 OR octet_length(p_request_key) > 128) THEN
        RAISE EXCEPTION 'invalid request_key' USING ERRCODE = '23514';
    END IF;
    PERFORM openmettle.quota_lock_override(p_scope, p_actor, p_resource);
    SELECT hard_limit
      INTO prior
      FROM openmettle.quota_overrides
     WHERE scope_id = p_scope
       AND resource_kind = p_resource
       AND revoked_at IS NULL;
    UPDATE openmettle.quota_overrides
       SET revoked_at = clock_timestamp(),
           revision = revision + 1,
           updated_at = clock_timestamp(),
           updated_by_user_id = p_actor,
           reason = p_reason
     WHERE scope_id = p_scope
       AND resource_kind = p_resource
       AND revoked_at IS NULL
    RETURNING * INTO rec;
    IF FOUND THEN
        v_details := jsonb_build_object(
            'scope_id', p_scope,
            'resource_kind', p_resource,
            'old_limit', prior,
            'new_limit', NULL,
            'expires_at', NULL,
            'revision', rec.revision
        );
        IF p_request IS NOT NULL THEN
            v_details := v_details || jsonb_build_object(
                'request', p_request,
                'response', jsonb_build_object(
                    'scope_id', rec.scope_id::text,
                    'scope_kind', rec.scope_kind,
                    'resource_kind', rec.resource_kind,
                    'hard_limit', rec.hard_limit::text,
                    'expires_at', CASE WHEN rec.expires_at IS NOT NULL
                                       THEN to_char(rec.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
                    'revoked_at', CASE WHEN rec.revoked_at IS NOT NULL
                                       THEN to_char(rec.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,
                    'revision', rec.revision::text,
                    'updated_at', to_char(rec.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                )
            );
        END IF;
        INSERT INTO openmettle.authorization_audit (
            actor_user_id, action, target_kind, target_id, request_key, reason, details
        )
        VALUES (
            p_actor,
            'quota.override.revoke',
            'quota_scope',
            p_scope::text,
            coalesce(p_request_key, gen_random_uuid()::text),
            p_reason,
            v_details
        );
        RETURN rec.revision;
    END IF;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_revoke_scope_override(uuid, uuid, text, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_revoke_scope_override(uuid, uuid, text, text, text, jsonb) TO openmettle_api;

-- Ensure expired or revoked overrides revert limit_revision to 0 so default-level threshold
-- warnings re-arm cleanly and obsolete override warnings drop out of quota summaries.
CREATE OR REPLACE FUNCTION openmettle.quota_limit(p_scope uuid, p_kind text, p_resource text)
RETURNS TABLE (
    hard_limit bigint,
    window_seconds integer,
    warn1 smallint,
    warn2 smallint,
    config_revision bigint,
    limit_revision bigint
)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
    SELECT coalesce(
               CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > statement_timestamp())
                    THEN o.hard_limit END,
               d.hard_limit
           ),
           d.window_seconds,
           coalesce(d.warn_pct_1, 80)::smallint,
           coalesce(d.warn_pct_2, 90)::smallint,
           coalesce(d.config_revision, 1),
           coalesce(
               CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > statement_timestamp())
                    THEN o.revision END,
               0
           )
      FROM (VALUES (1)) AS seed(id)
      LEFT JOIN openmettle.quota_defaults d
        ON d.scope_kind = p_kind AND d.resource_kind = p_resource
      LEFT JOIN openmettle.quota_overrides o
        ON o.scope_id = p_scope AND o.resource_kind = p_resource
$$;

CREATE OR REPLACE FUNCTION openmettle.quota_record_storage_warning(p_scope uuid, p_added bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    a openmettle.storage_accounts%ROWTYPE;
    i openmettle.storage_instance%ROWTYPE;
    charged numeric;
    lim bigint;
    rev bigint;
    bucket timestamptz := date_trunc('day', clock_timestamp(), 'UTC');
BEGIN
    SELECT * INTO STRICT a FROM openmettle.storage_accounts WHERE scope_id = p_scope FOR UPDATE;
    SELECT * INTO STRICT i FROM openmettle.storage_instance WHERE id FOR NO KEY UPDATE;
    SELECT coalesce(
               CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > statement_timestamp())
                    THEN o.hard_limit END,
               CASE WHEN s.kind = 'personal' THEN i.personal_limit_bytes ELSE i.project_limit_bytes END
           ),
           coalesce(
               CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > statement_timestamp())
                    THEN o.revision END,
               0
           )
      INTO STRICT lim, rev
      FROM openmettle.scopes s
      LEFT JOIN openmettle.quota_overrides o
        ON o.scope_id = s.id AND o.resource_kind = 'storage_bytes'
     WHERE s.id = p_scope;
    charged := a.active_bytes::numeric + a.retained_bytes + a.reserved_bytes;
    PERFORM openmettle.quota_warn(
        'scope', p_scope, 'storage_bytes', bucket,
        charged - p_added, charged, lim, i.warn_pct_1, i.warn_pct_2, i.config_revision, rev
    );
    charged := i.active_bytes::numeric + i.retained_bytes + i.reserved_bytes;
    PERFORM openmettle.quota_warn(
        'instance', NULL, 'storage_bytes', bucket,
        charged - p_added, charged, i.instance_budget_bytes, i.warn_pct_1, i.warn_pct_2, i.config_revision, 0
    );
END;
$$;
