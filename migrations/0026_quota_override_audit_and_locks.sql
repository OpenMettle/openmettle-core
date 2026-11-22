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

-- Attach the locked failing tier (personal, project, or instance) in SQLSTATE DETAIL on OMQ01,
-- OMQ02, and OMQ05 so callers never re-query quota state after a savepoint rollback.
CREATE OR REPLACE FUNCTION openmettle.quota_reserve(
    p_scope uuid,
    p_actor uuid,
    p_resource text,
    p_units bigint,
    p_key text,
    p_run uuid,
    p_request uuid,
    p_dispatch bytea,
    p_lease timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    actor_scope uuid;
    primary_kind text;
    origin text;
    identity_bytes bytea;
    hold openmettle.quota_reservations%ROWTYPE;
    req openmettle.gateway_requests%ROWTYPE;
    target record;
    cfg record;
    budget openmettle.quota_budgets%ROWTYPE;
    stamp timestamptz := clock_timestamp();
    start_at timestamptz;
    win text;
BEGIN
    origin := CASE WHEN pg_has_role(session_user, 'openmettle_api', 'USAGE') THEN 'api'
                   WHEN pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN 'worker' END;
    IF origin IS NULL OR p_lease IS NULL OR p_lease <= stamp OR p_units IS NULL OR p_units <= 0 THEN
        RAISE EXCEPTION 'invalid quota reservation' USING ERRCODE = '23514';
    END IF;
    SELECT id INTO STRICT actor_scope FROM openmettle.scopes WHERE personal_user_id = p_actor;
    SELECT kind INTO STRICT primary_kind FROM openmettle.scopes WHERE id = p_scope;
    IF p_run IS NOT NULL THEN
        PERFORM FROM openmettle.runs
         WHERE id = p_run AND scope_id = p_scope AND actor_user_id = p_actor
           FOR NO KEY UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'invalid run' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF p_request IS NOT NULL THEN
        SELECT * INTO req
          FROM openmettle.gateway_requests
         WHERE id = p_request
           AND state = 'reserved'
           AND scope_id = p_scope
           AND actor_user_id = p_actor
           AND run_id IS NULL
           AND octet_length(p_dispatch) = 32
           AND dispatch_hash = sha256(p_dispatch)
           FOR KEY SHARE;
        IF NOT FOUND OR origin <> 'api' OR p_run IS NOT NULL
           OR (p_resource = 'usage_tokens' AND req.units <> p_units) THEN
            RAISE EXCEPTION 'invalid gateway hold' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF p_resource = 'usage_cost_micros' AND NOT EXISTS (
        SELECT FROM openmettle.quota_defaults
         WHERE scope_kind = 'instance'
           AND resource_kind = p_resource
           AND cost_denomination IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cost denomination unconfigured'
            USING ERRCODE = 'OMQ02', DETAIL = 'instance';
    END IF;
    identity_bytes := convert_to(
        jsonb_build_array(p_scope, p_actor, p_resource, p_units, p_key, p_run, p_request, origin)::text,
        'UTF8'
    );
    INSERT INTO openmettle.quota_reservations (
        scope_id, actor_user_id, actor_scope_id, origin_role, resource_kind,
        idempotency_key, request_identity, request_digest, run_id, gateway_request_id,
        reserved_units, held_units, lease_expires_at
    )
    VALUES (
        p_scope, p_actor, actor_scope, origin, p_resource,
        p_key, identity_bytes, sha256(identity_bytes), p_run, p_request,
        p_units, p_units, p_lease
    )
    ON CONFLICT (scope_id, actor_user_id, resource_kind, idempotency_key) DO NOTHING
    RETURNING * INTO hold;
    IF NOT FOUND THEN
        SELECT * INTO STRICT hold
          FROM openmettle.quota_reservations
         WHERE scope_id = p_scope
           AND actor_user_id = p_actor
           AND resource_kind = p_resource
           AND idempotency_key = p_key;
        IF hold.request_identity <> identity_bytes THEN
            RAISE EXCEPTION 'quota replay conflict' USING ERRCODE = '23505';
        END IF;
        RETURN hold.id;
    END IF;
    FOR target IN
        SELECT * FROM (VALUES
            (p_scope, primary_kind, 'primary_scope'),
            (actor_scope, 'personal', 'actor_scope'),
            (NULL::uuid, 'instance', 'instance')
        ) t(scope, kind, charge)
        WHERE charge <> 'actor_scope' OR actor_scope <> p_scope
        ORDER BY scope NULLS LAST
    LOOP
        SELECT * INTO cfg FROM openmettle.quota_limit(target.scope, target.kind, p_resource);
        IF cfg.hard_limit IS NULL THEN
            IF target.kind IN ('instance', 'project') THEN CONTINUE; END IF;
            RAISE EXCEPTION 'quota limit unconfigured'
                USING ERRCODE = 'OMQ05', DETAIL = target.kind;
        END IF;
        win := CASE WHEN p_resource = 'device_reservations' THEN 'concurrent'
                    WHEN cfg.window_seconds IS NULL THEN 'static'
                    ELSE 'windowed' END;
        start_at := CASE WHEN win = 'windowed'
                         THEN date_bin(make_interval(secs => cfg.window_seconds), stamp, 'epoch')
                         ELSE 'epoch'::timestamptz END;
        INSERT INTO openmettle.quota_budgets (
            target_kind, scope_id, resource_kind, window_kind, window_start, window_end
        )
        VALUES (
            CASE WHEN target.scope IS NULL THEN 'instance' ELSE 'scope' END,
            target.scope, p_resource, win, start_at,
            CASE WHEN win = 'windowed' THEN start_at + make_interval(secs => cfg.window_seconds) END
        )
        ON CONFLICT DO NOTHING;
        SELECT * INTO STRICT budget
          FROM openmettle.quota_budgets
         WHERE scope_id IS NOT DISTINCT FROM target.scope
           AND resource_kind = p_resource
           AND window_kind = win
           AND window_start = start_at
           FOR NO KEY UPDATE;
        SELECT * INTO cfg FROM openmettle.quota_limit(target.scope, target.kind, p_resource);
        IF cfg.hard_limit IS NULL THEN
            RAISE EXCEPTION 'quota configuration changed' USING ERRCODE = '40001';
        END IF;
        IF budget.active_used + budget.reserved_held + p_units > cfg.hard_limit THEN
            RAISE EXCEPTION 'quota limit exceeded'
                USING ERRCODE = 'OMQ01', DETAIL = target.kind;
        END IF;
        INSERT INTO openmettle.quota_reservation_charges VALUES (hold.id, budget.id, target.charge);
        UPDATE openmettle.quota_budgets
           SET reserved_held = reserved_held + p_units,
               revision = revision + 1,
               updated_at = stamp
         WHERE id = budget.id;
        PERFORM openmettle.quota_warn(
            budget.target_kind, target.scope, p_resource,
            CASE WHEN win = 'windowed' THEN start_at ELSE date_trunc('day', stamp, 'UTC') END,
            budget.active_used + budget.reserved_held,
            budget.active_used + budget.reserved_held + p_units,
            cfg.hard_limit, cfg.warn1, cfg.warn2, cfg.config_revision, cfg.limit_revision
        );
    END LOOP;
    RETURN hold.id;
END;
$$;

-- Allow openmettle_api and openmettle_worker to immediately unwind held run-level parent holds
-- when transitioning a queued or waiting run to cancelled or failed (with no in-flight operations).
CREATE OR REPLACE FUNCTION openmettle.quota_release_unsent(
    p_id uuid,
    p_dispatch bytea DEFAULT NULL,
    p_sweep boolean DEFAULT false
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    h openmettle.quota_reservations%ROWTYPE;
    q openmettle.gateway_requests%ROWTYPE;
    r_state text;
    terminal_parent boolean := false;
BEGIN
    IF p_sweep IS NULL OR (p_sweep AND NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE')) THEN
        RAISE EXCEPTION 'invalid sweep authority' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO h FROM openmettle.quota_reservations WHERE id = p_id AND state = 'held';
    IF NOT FOUND THEN RETURN false; END IF;
    IF NOT p_sweep THEN
        IF pg_has_role(session_user, 'openmettle_' || h.origin_role, 'USAGE') THEN
            NULL;
        ELSIF h.run_id IS NOT NULL
              AND h.gateway_request_id IS NULL
              AND (
                  pg_has_role(session_user, 'openmettle_api', 'USAGE')
                  OR pg_has_role(session_user, 'openmettle_worker', 'USAGE')
              ) THEN
            terminal_parent := true;
        ELSE
            RAISE EXCEPTION 'invalid release authority' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF h.run_id IS NOT NULL THEN
        IF p_sweep THEN
            PERFORM FROM openmettle.runs r
             WHERE id = h.run_id
               AND r.state IN ('succeeded', 'failed', 'cancelled', 'interrupted')
               AND NOT EXISTS (
                   SELECT FROM openmettle.operations
                    WHERE run_id = r.id
                      AND outcome IN ('intent', 'outcome_unknown')
               )
               FOR NO KEY UPDATE SKIP LOCKED;
        ELSE
            SELECT state INTO r_state
              FROM openmettle.runs
             WHERE id = h.run_id
               FOR NO KEY UPDATE;
        END IF;
        IF NOT FOUND THEN RETURN false; END IF;
        IF terminal_parent AND r_state NOT IN ('cancelled', 'failed') THEN
            RAISE EXCEPTION 'invalid release authority' USING ERRCODE = '42501';
        END IF;
        IF NOT p_sweep AND h.gateway_request_id IS NULL
           AND r_state IN ('cancelled', 'failed')
           AND EXISTS (
               SELECT FROM openmettle.operations
                WHERE run_id = h.run_id
                  AND outcome IN ('intent', 'outcome_unknown')
           ) THEN
            RETURN false;
        END IF;
    END IF;
    IF h.gateway_request_id IS NOT NULL THEN
        SELECT * INTO STRICT q FROM openmettle.gateway_requests WHERE id = h.gateway_request_id;
        IF NOT p_sweep AND (
            p_dispatch IS NULL
            OR octet_length(p_dispatch) <> 32
            OR q.dispatch_hash <> sha256(p_dispatch)
        ) THEN
            RAISE EXCEPTION 'invalid release authority' USING ERRCODE = '42501';
        END IF;
        IF p_sweep THEN
            PERFORM FROM openmettle.gateway_reservations
             WHERE id = q.reservation_id
               FOR NO KEY UPDATE SKIP LOCKED;
            IF NOT FOUND THEN RETURN false; END IF;
            SELECT * INTO q
              FROM openmettle.gateway_requests
             WHERE id = h.gateway_request_id
               FOR NO KEY UPDATE SKIP LOCKED;
        ELSE
            PERFORM FROM openmettle.gateway_reservations
             WHERE id = q.reservation_id
               FOR NO KEY UPDATE;
            SELECT * INTO q
              FROM openmettle.gateway_requests
             WHERE id = h.gateway_request_id
               FOR NO KEY UPDATE;
        END IF;
        IF NOT FOUND OR q.state = 'handed_off' OR (NOT p_sweep AND q.state <> 'released') THEN
            RETURN false;
        END IF;
    END IF;
    IF h.parent_reservation_id IS NOT NULL THEN
        IF p_sweep THEN
            PERFORM FROM openmettle.quota_reservations
             WHERE id = h.parent_reservation_id
               FOR NO KEY UPDATE SKIP LOCKED;
        ELSE
            PERFORM FROM openmettle.quota_reservations
             WHERE id = h.parent_reservation_id
               FOR NO KEY UPDATE;
        END IF;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    IF p_sweep THEN
        SELECT * INTO h
          FROM openmettle.quota_reservations
         WHERE id = p_id
           AND state = 'held'
           AND lease_expires_at <= clock_timestamp()
           FOR NO KEY UPDATE SKIP LOCKED;
    ELSE
        SELECT * INTO h
          FROM openmettle.quota_reservations
         WHERE id = p_id
           AND state = 'held'
           FOR NO KEY UPDATE;
    END IF;
    IF NOT FOUND THEN RETURN false; END IF;
    IF h.gateway_request_id IS NOT NULL THEN
        IF (h.scope_id, h.actor_user_id, h.run_id) IS DISTINCT FROM (q.scope_id, q.actor_user_id, q.run_id) THEN
            RAISE EXCEPTION 'gateway quota ownership mismatch' USING ERRCODE = '23514';
        END IF;
        IF q.state = 'reserved' THEN
            UPDATE openmettle.gateway_requests SET state = 'released' WHERE id = q.id;
            UPDATE openmettle.gateway_reservations SET allocated = allocated - q.units WHERE id = q.reservation_id;
        END IF;
    END IF;
    PERFORM openmettle.quota_unwind_hold(h.id, CASE WHEN p_sweep THEN 'stale_sweep' ELSE 'release' END);
    RETURN true;
END;
$$;
