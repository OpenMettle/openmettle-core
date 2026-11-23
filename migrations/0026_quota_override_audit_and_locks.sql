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

-- Retain o.revision on explicitly revoked overrides so default-level threshold warnings re-arm
-- in the same bucket (ADR 0040), while naturally expired unrevoked overrides revert to 0.
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
           CASE
               WHEN o.revoked_at IS NOT NULL THEN o.revision
               WHEN o.expires_at IS NULL OR o.expires_at > statement_timestamp() THEN coalesce(o.revision, 0)
               ELSE 0
           END
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
           CASE
               WHEN o.revoked_at IS NOT NULL THEN o.revision
               WHEN o.expires_at IS NULL OR o.expires_at > statement_timestamp() THEN coalesce(o.revision, 0)
               ELSE 0
           END
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
-- when transitioning a run to a terminal state (with no in-flight operations).
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
        IF terminal_parent AND r_state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted') THEN
            RAISE EXCEPTION 'invalid release authority' USING ERRCODE = '42501';
        END IF;
        IF NOT p_sweep AND h.gateway_request_id IS NULL
           AND r_state IN ('succeeded', 'failed', 'cancelled', 'interrupted')
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

-- Deadlock-free batch release of unallocated run-level parent holds across terminal runs.
-- Locks runs (ORDER BY id), parent holds (ORDER BY resource_kind, id), and all charged
-- quota_budgets in canonical (resource_kind ASC, scope_id ASC NULLS LAST, window_start, id)
-- order before unwinding any hold.
CREATE FUNCTION openmettle.quota_release_terminal_runs(p_runs uuid[])
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    eligible_runs uuid[];
    hold_ids uuid[];
    hold_id uuid;
    released integer := 0;
BEGIN
    IF NOT (
        pg_has_role(session_user, 'openmettle_api', 'USAGE')
        OR pg_has_role(session_user, 'openmettle_worker', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'invalid release authority' USING ERRCODE = '42501';
    END IF;
    IF p_runs IS NULL OR coalesce(array_length(p_runs, 1), 0) = 0 THEN
        RETURN 0;
    END IF;
    SELECT array_agg(id ORDER BY id)
      INTO eligible_runs
      FROM (
          SELECT r.id
            FROM openmettle.runs r
           WHERE r.id = ANY(p_runs)
             AND r.state IN ('succeeded', 'failed', 'cancelled', 'interrupted')
             AND NOT EXISTS (
                 SELECT FROM openmettle.operations o
                  WHERE o.run_id = r.id
                    AND o.outcome IN ('intent', 'outcome_unknown')
             )
           ORDER BY r.id
             FOR NO KEY UPDATE
      ) locked_runs;
    IF eligible_runs IS NULL THEN
        RETURN 0;
    END IF;
    SELECT array_agg(id ORDER BY resource_kind, id)
      INTO hold_ids
      FROM (
          SELECT h.id, h.resource_kind
            FROM openmettle.quota_reservations h
           WHERE h.run_id = ANY(eligible_runs)
             AND h.gateway_request_id IS NULL
             AND h.state = 'held'
           ORDER BY h.resource_kind, h.id
             FOR NO KEY UPDATE
      ) locked_holds;
    IF hold_ids IS NULL THEN
        RETURN 0;
    END IF;
    PERFORM FROM openmettle.quota_budgets b
     WHERE b.id IN (
         SELECT DISTINCT c.budget_id
           FROM openmettle.quota_reservation_charges c
          WHERE c.reservation_id = ANY(hold_ids)
     )
     ORDER BY b.resource_kind ASC, b.scope_id ASC NULLS LAST, b.window_start ASC, b.id ASC
       FOR NO KEY UPDATE;
    FOREACH hold_id IN ARRAY hold_ids LOOP
        PERFORM openmettle.quota_unwind_hold(hold_id, 'release');
        released := released + 1;
    END LOOP;
    RETURN released;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_release_terminal_runs(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_release_terminal_runs(uuid[]) TO openmettle_api, openmettle_worker;

-- Keep 3-arg openmettle.quota_ensure_legacy_run_holds(uuid, uuid, uuid) intact for draining N-1
-- workers, and add openmettle.quota_prepare_turn_round for schema-26 workers and reserve_with_cost
-- callers to recover missing gateway_reservations, device_reservations, and qualified per-round
-- cost_bound holds (returning gateway_reservations.id).
CREATE FUNCTION openmettle.quota_prepare_turn_round(
    p_scope uuid,
    p_run uuid,
    p_claim uuid,
    p_fallback_round_tokens bigint DEFAULT NULL,
    p_per_round_cost_micros bigint DEFAULT NULL,
    p_cost_bound_missing boolean DEFAULT false,
    p_cost_bound_overflow boolean DEFAULT false,
    p_requires_device_slot boolean DEFAULT false,
    p_require_holds boolean DEFAULT false
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    r openmettle.runs%ROWTYPE;
    g openmettle.gateway_reservations%ROWTYPE;
    v_cfg jsonb;
    v_round_tokens bigint;
    v_rounds integer;
    v_total_tokens bigint;
    v_enforced boolean;
    v_rem_rounds integer;
    v_scope_kind text;
    v_actor_scope uuid;
    v_cost_denom text;
    v_any_cost_limit boolean;
    v_cost_ceiling bigint;
    v_cost_units bigint;
BEGIN
    SELECT * INTO STRICT r
      FROM openmettle.runs
     WHERE scope_id = p_scope
       AND id = p_run
       AND state = 'running'
       AND cancel_reason IS NULL
       AND claim_token = p_claim
       AND lease_expires_at > clock_timestamp()
       FOR NO KEY UPDATE;

    SELECT * INTO g
      FROM openmettle.gateway_reservations
     WHERE run_id = p_run
       FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        BEGIN
            v_cfg := convert_from(r.config_snapshot, 'UTF8')::jsonb;
        EXCEPTION WHEN others THEN
            v_cfg := NULL;
        END;
        v_round_tokens := coalesce(
            (v_cfg #>> '{effective,ceiling,value}')::bigint,
            (v_cfg #>> '{config,effective,ceiling,value}')::bigint,
            p_fallback_round_tokens
        );
        IF v_round_tokens IS NULL OR v_round_tokens <= 0 THEN
            RAISE EXCEPTION 'missing token ceiling for legacy run' USING ERRCODE = '23514';
        END IF;
        v_rounds := greatest(1, coalesce(r.round_limit, 1));
        v_total_tokens := v_round_tokens * v_rounds;
        INSERT INTO openmettle.gateway_reservations
            (id, scope_id, actor_user_id, approval_id, run_id, units)
        VALUES (r.id, r.scope_id, r.actor_user_id, r.actor_approval_id, r.id, v_total_tokens)
        RETURNING * INTO STRICT g;
    END IF;

    SELECT metering_enforced INTO STRICT v_enforced
      FROM openmettle.quota_enforcement
     WHERE id;
    IF NOT v_enforced AND NOT p_require_holds THEN
        RETURN g.id;
    END IF;

    v_rem_rounds := greatest(
        1,
        coalesce(r.round_limit, 1) - coalesce(
            (SELECT count(*)::integer
               FROM openmettle.gateway_requests
              WHERE reservation_id = g.id
                AND run_id IS NOT NULL
                AND state <> 'released'),
            0
        )
    );

    -- 1. device_reservations (canonical alphabetical order)
    IF p_requires_device_slot AND NOT EXISTS (
        SELECT FROM openmettle.quota_reservations
         WHERE scope_id = p_scope
           AND run_id = p_run
           AND gateway_request_id IS NULL
           AND resource_kind = 'device_reservations'
    ) THEN
        PERFORM openmettle.quota_reserve(
            p_scope, r.actor_user_id, 'device_reservations', 1,
            'run:' || p_run, p_run, NULL, NULL, r.lease_expires_at
        );
    END IF;

    -- 2. usage_cost_micros
    SELECT kind INTO STRICT v_scope_kind FROM openmettle.scopes WHERE id = p_scope;
    SELECT id INTO STRICT v_actor_scope FROM openmettle.scopes WHERE personal_user_id = r.actor_user_id;
    SELECT cost_denomination INTO v_cost_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';
    v_any_cost_limit := EXISTS (
        SELECT 1
          FROM (VALUES
              (p_scope, v_scope_kind),
              (v_actor_scope, 'personal'::text),
              (NULL::uuid, 'instance'::text)
          ) t(scope_id, scope_kind)
          LEFT JOIN openmettle.quota_defaults d
            ON d.scope_kind = t.scope_kind AND d.resource_kind = 'usage_cost_micros'
          LEFT JOIN openmettle.quota_overrides o
            ON o.scope_id = t.scope_id AND o.resource_kind = 'usage_cost_micros'
         WHERE coalesce(
                   CASE WHEN o.revoked_at IS NULL
                         AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
                        THEN o.hard_limit END,
                   d.hard_limit
               ) IS NOT NULL
    );
    IF v_any_cost_limit AND g.units > g.allocated THEN
        IF v_cost_denom IS NULL OR p_cost_bound_missing THEN
            RAISE EXCEPTION 'cost bound or denomination unconfigured'
                USING ERRCODE = 'OMQ02', DETAIL = 'instance';
        END IF;
        IF NOT EXISTS (
            SELECT FROM openmettle.quota_reservations
             WHERE scope_id = p_scope
               AND run_id = p_run
               AND gateway_request_id IS NULL
               AND resource_kind = 'usage_cost_micros'
        ) THEN
            v_cost_ceiling := openmettle.quota_cost_ceiling(p_scope, r.actor_user_id);
            IF v_cost_ceiling IS NULL THEN
                RAISE EXCEPTION 'quota limit unconfigured'
                    USING ERRCODE = 'OMQ05', DETAIL = 'personal';
            END IF;
            IF p_cost_bound_overflow THEN
                RAISE EXCEPTION 'cost limit exceeded'
                    USING ERRCODE = 'OMQ01', DETAIL = 'personal';
            END IF;
            IF p_per_round_cost_micros IS NOT NULL THEN
                IF p_per_round_cost_micros <= 0 THEN
                    RAISE EXCEPTION 'invalid cost bound' USING ERRCODE = '23514';
                END IF;
                IF p_per_round_cost_micros::numeric * v_rem_rounds > 9223372036854775807 THEN
                    RAISE EXCEPTION 'cost limit exceeded'
                        USING ERRCODE = 'OMQ01', DETAIL = 'personal';
                END IF;
                v_cost_units := p_per_round_cost_micros * v_rem_rounds;
            ELSE
                v_cost_units := v_cost_ceiling;
            END IF;
            IF v_cost_units <= 0 THEN
                RAISE EXCEPTION 'cost limit exceeded'
                    USING ERRCODE = 'OMQ01', DETAIL = 'personal';
            END IF;
            PERFORM openmettle.quota_reserve(
                p_scope, r.actor_user_id, 'usage_cost_micros', v_cost_units,
                'run:' || p_run, p_run, NULL, NULL, r.lease_expires_at
            );
        END IF;
    END IF;

    -- 3. usage_tokens
    IF g.units > g.allocated AND NOT EXISTS (
        SELECT FROM openmettle.quota_reservations
         WHERE scope_id = p_scope
           AND run_id = p_run
           AND gateway_request_id IS NULL
           AND resource_kind = 'usage_tokens'
    ) THEN
        PERFORM openmettle.quota_reserve(
            p_scope, r.actor_user_id, 'usage_tokens', g.units - g.allocated,
            'run:' || p_run, p_run, NULL, NULL, r.lease_expires_at
        );
    END IF;

    RETURN g.id;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_prepare_turn_round(uuid, uuid, uuid, bigint, bigint, boolean, boolean, boolean, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_prepare_turn_round(uuid, uuid, uuid, bigint, bigint, boolean, boolean, boolean, boolean) TO openmettle_worker;

-- Require BOTH instance cost_denomination AND an active personal usage_cost_micros limit
-- whenever any cost tier applies; expiring a personal override must fail closed even if a
-- project or instance cost limit remains configured.
CREATE OR REPLACE FUNCTION openmettle.quota_cost_ceiling(p_scope uuid, p_actor uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    WITH tiers AS (
        SELECT id, kind, (personal_user_id = p_actor) AS is_personal
          FROM openmettle.scopes
         WHERE id = p_scope OR personal_user_id = p_actor
        UNION ALL
        SELECT NULL::uuid, 'instance'::text, false
    ),
    resolved AS (
        SELECT t.is_personal, cfg.hard_limit
          FROM tiers t
          CROSS JOIN LATERAL openmettle.quota_limit(t.id, t.kind, 'usage_cost_micros') cfg
    )
    SELECT CASE
               WHEN EXISTS (
                   SELECT 1 FROM openmettle.quota_defaults
                    WHERE scope_kind = 'instance'
                      AND resource_kind = 'usage_cost_micros'
                      AND cost_denomination IS NOT NULL
               )
                AND EXISTS (
                   SELECT 1 FROM resolved WHERE is_personal AND hard_limit IS NOT NULL
               )
               THEN (SELECT min(hard_limit) FROM resolved)
           END
$$;

-- Compute a run's per-round cost slice by dividing its remaining parent usage_cost_micros hold
-- across remaining unallocated rounds (including p_current_request if already inserted), using
-- gateway_requests_run_round_active_idx via gateway_reservations.id.
CREATE FUNCTION openmettle.quota_run_round_cost_slice(
    p_scope uuid,
    p_run uuid,
    p_current_request uuid DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_held bigint;
    v_round_limit integer;
    v_reservation_id uuid;
    v_prior_rounds integer;
    v_rem_rounds integer;
BEGIN
    SELECT h.held_units, coalesce(r.round_limit, 1)
      INTO v_held, v_round_limit
      FROM openmettle.quota_reservations h
      JOIN openmettle.runs r ON r.id = h.run_id AND r.scope_id = h.scope_id
     WHERE h.scope_id = p_scope
       AND h.run_id = p_run
       AND h.gateway_request_id IS NULL
       AND h.resource_kind = 'usage_cost_micros'
       AND h.state = 'held';
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF v_held <= 0 THEN
        RETURN 0;
    END IF;
    SELECT g.id
      INTO v_reservation_id
      FROM openmettle.gateway_reservations g
     WHERE g.run_id = p_run;
    IF v_reservation_id IS NOT NULL THEN
        SELECT count(*)::integer
          INTO v_prior_rounds
          FROM openmettle.gateway_requests q
         WHERE q.reservation_id = v_reservation_id
           AND q.run_id IS NOT NULL
           AND q.state <> 'released'
           AND (p_current_request IS NULL OR q.id <> p_current_request);
    ELSE
        v_prior_rounds := 0;
    END IF;
    v_rem_rounds := greatest(1, v_round_limit - coalesce(v_prior_rounds, 0));
    RETURN ((v_held - 1) / v_rem_rounds) + 1;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_run_round_cost_slice(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_run_round_cost_slice(uuid, uuid, uuid) TO openmettle_worker;

-- Serialize unmetered worker turn dispatch against metering_enforced activation and refuse
-- whenever metering is enforced or the run already holds quota reservations.
CREATE FUNCTION openmettle.quota_authorize_unmetered_turn_round(
    p_scope uuid,
    p_run uuid,
    p_claim uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_enforced boolean;
BEGIN
    PERFORM FROM openmettle.runs
     WHERE scope_id = p_scope
       AND id = p_run
       AND state = 'running'
       AND cancel_reason IS NULL
       AND claim_token = p_claim
       AND lease_expires_at > clock_timestamp()
       FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid unmetered turn round' USING ERRCODE = '42501';
    END IF;
    SELECT metering_enforced INTO STRICT v_enforced
      FROM openmettle.quota_enforcement
     WHERE id
       FOR SHARE;
    IF v_enforced OR EXISTS (
        SELECT 1 FROM openmettle.quota_reservations
         WHERE scope_id = p_scope
           AND run_id = p_run
    ) THEN
        RAISE EXCEPTION 'metered dispatch required' USING ERRCODE = 'OMQ04';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_authorize_unmetered_turn_round(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_authorize_unmetered_turn_round(uuid, uuid, uuid) TO openmettle_worker;

-- Acquire the exact gateway_handoff authorization prefix locks in canonical order
-- (`account_admin_lock -> projects -> login_providers/approvals -> users -> runs FOR NO KEY UPDATE`)
-- so TurnPending::handoff neither inverts against disable_user/archive_project nor upgrades
-- openmettle.runs after gateway_requests.
CREATE FUNCTION openmettle.quota_lock_turn_handoff_prefix(
    p_request uuid,
    p_dispatch bytea,
    p_scope uuid,
    p_run uuid,
    p_claim uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    SELECT * INTO req
      FROM openmettle.gateway_requests
     WHERE id = p_request
       AND scope_id = p_scope
       AND run_id = p_run
       AND state = 'reserved'
       AND octet_length(p_dispatch) = 32
       AND dispatch_hash = sha256(p_dispatch)
       AND pg_has_role(session_user, 'openmettle_worker', 'USAGE');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid turn handoff' USING ERRCODE = '42501';
    END IF;

    PERFORM FROM openmettle.account_admin_lock FOR SHARE;
    PERFORM FROM openmettle.projects p WHERE p.scope_id = req.scope_id FOR SHARE;
    PERFORM FROM openmettle.login_providers p
       JOIN openmettle.local_identity_approvals a ON a.provider_id = p.id
      WHERE a.id = req.approval_id
        FOR SHARE OF p, a;
    PERFORM FROM openmettle.users u WHERE u.id = req.actor_user_id FOR SHARE;
    PERFORM FROM openmettle.runs r
     WHERE r.scope_id = p_scope
       AND r.id = p_run
       AND r.state = 'running'
       AND r.cancel_reason IS NULL
       AND r.claim_token = p_claim
       AND r.lease_expires_at > clock_timestamp()
       FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid turn handoff' USING ERRCODE = '42501';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_lock_turn_handoff_prefix(uuid, bytea, uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_lock_turn_handoff_prefix(uuid, bytea, uuid, uuid, uuid) TO openmettle_worker;

-- Acquire the canonical authorization prefix locks (`account_admin_lock -> projects ->
-- login_providers/approvals -> users`) before a worker reservation transaction takes its first
-- lock on `openmettle.runs` and inserts FK-bearing `gateway_reservations` / `quota_reservations`
-- rows, preventing deadlocks with `disable_user` / `archive_project`.
CREATE FUNCTION openmettle.quota_lock_run_actor_prefix(
    p_scope uuid,
    p_run uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_actor uuid;
    v_approval uuid;
BEGIN
    SELECT r.actor_user_id, r.actor_approval_id
      INTO v_actor, v_approval
      FROM openmettle.runs r
     WHERE r.scope_id = p_scope
       AND r.id = p_run
       AND pg_has_role(session_user, 'openmettle_worker', 'USAGE');
    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM FROM openmettle.account_admin_lock FOR SHARE;
    PERFORM FROM openmettle.projects p WHERE p.scope_id = p_scope FOR SHARE;
    IF v_approval IS NOT NULL THEN
        PERFORM FROM openmettle.login_providers p
           JOIN openmettle.local_identity_approvals a ON a.provider_id = p.id
          WHERE a.id = v_approval
            FOR SHARE OF p, a;
    END IF;
    PERFORM FROM openmettle.users u WHERE u.id = v_actor FOR SHARE;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_lock_run_actor_prefix(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_lock_run_actor_prefix(uuid, uuid) TO openmettle_worker;

-- Atomically commit a worker turn round's quota_reservations in strict canonical lock order
-- (`account_admin_lock..users..runs` -> `gateway_requests` -> `quota_reservations (resource_kind, id)`).
-- Leaves `quota_gateway_handoffs -> quota_enforcement FOR SHARE` strictly to the deferred
-- `enforce_gateway_handoff_holds` trigger at COMMIT.
CREATE FUNCTION openmettle.quota_commit_turn_handoff(
    p_request uuid,
    p_dispatch bytea,
    p_scope uuid,
    p_run uuid,
    p_claim uuid,
    p_requires_device_slot boolean,
    p_device_grant uuid,
    p_cost_bound_missing boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
    v_hold openmettle.quota_reservations%ROWTYPE;
    r_lock openmettle.quota_reservations%ROWTYPE;
BEGIN
    SELECT * INTO STRICT req
      FROM openmettle.gateway_requests
     WHERE id = p_request
       AND scope_id = p_scope
       AND run_id = p_run
       AND state = 'handed_off'
       AND octet_length(p_dispatch) = 32
       AND dispatch_hash = sha256(p_dispatch)
       AND pg_has_role(session_user, 'openmettle_worker', 'USAGE');

    IF NOT EXISTS (
        SELECT 1
          FROM openmettle.runs
         WHERE scope_id = p_scope
           AND id = p_run
           AND state = 'running'
           AND cancel_reason IS NULL
           AND claim_token = p_claim
           AND lease_expires_at > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'invalid turn handoff' USING ERRCODE = '42501';
    END IF;

    -- Lock every target quota_reservations row in strict alphabetical (resource_kind, id) order:
    -- 'device_reservations' -> 'usage_cost_micros' -> 'usage_tokens'.
    FOR r_lock IN
        SELECT *
          FROM openmettle.quota_reservations
         WHERE (
                   p_requires_device_slot
                   AND scope_id = p_scope
                   AND run_id = p_run
                   AND gateway_request_id IS NULL
                   AND resource_kind = 'device_reservations'
               )
            OR (
                   gateway_request_id = req.id
                   AND state = 'held'
                   AND origin_role = 'worker'
               )
         ORDER BY resource_kind ASC, id ASC
           FOR NO KEY UPDATE
    LOOP
        IF r_lock.gateway_request_id IS NULL AND r_lock.resource_kind = 'device_reservations' THEN
            v_hold := r_lock;
        END IF;
    END LOOP;

    UPDATE openmettle.quota_reservations
       SET state = 'handoff_committed',
           revision = revision + 1
     WHERE gateway_request_id = req.id
       AND state = 'held'
       AND origin_role = 'worker';

    IF p_cost_bound_missing THEN
        PERFORM pg_catalog.set_config(
            'openmettle.turn_cost_unqualified_requests',
            coalesce(
                pg_catalog.current_setting('openmettle.turn_cost_unqualified_requests', true),
                ''
            ) || ',' || req.id::text || ',',
            true
        );
    END IF;

    IF p_requires_device_slot THEN
        PERFORM pg_catalog.set_config(
            'openmettle.turn_device_required_requests',
            coalesce(
                pg_catalog.current_setting('openmettle.turn_device_required_requests', true),
                ''
            ) || ',' || req.id::text || ',',
            true
        );
        IF v_hold.id IS NOT NULL THEN
            IF p_device_grant IS NULL THEN
                RAISE EXCEPTION 'invalid device handoff' USING ERRCODE = '42501';
            END IF;
            IF v_hold.state = 'held' THEN
                UPDATE openmettle.quota_reservations
                   SET state = 'handoff_committed',
                       device_grant_id = p_device_grant,
                       revision = revision + 1
                 WHERE id = v_hold.id
                   AND state = 'held';
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'invalid device handoff' USING ERRCODE = '42501';
                END IF;
            ELSIF v_hold.state = 'handoff_committed' AND v_hold.device_grant_id = p_device_grant THEN
                RETURN;
            ELSE
                RAISE EXCEPTION 'invalid device handoff' USING ERRCODE = '42501';
            END IF;
        END IF;
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_commit_turn_handoff(uuid, bytea, uuid, uuid, uuid, boolean, uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_commit_turn_handoff(uuid, bytea, uuid, uuid, uuid, boolean, uuid, boolean) TO openmettle_worker;

-- Extend the deferred gateway handoff constraint trigger so device-slot and cost-unqualified
-- turns are verified strictly AFTER inserting quota_gateway_handoffs and taking
-- quota_enforcement FOR SHARE (preserving ADR 0040's exact lock order).
CREATE OR REPLACE FUNCTION openmettle.enforce_gateway_handoff_holds()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_enforced boolean;
    v_scope_kind text;
    v_actor_scope_id uuid;
    v_cost_denom text;
    v_any_cost_limit boolean := false;
    v_cost_required boolean := false;
BEGIN
    IF EXISTS (
        SELECT 1
          FROM openmettle.quota_reservations qr
         WHERE qr.gateway_request_id = NEW.id
           AND qr.state <> 'handoff_committed'
    ) THEN
        RAISE EXCEPTION 'bound quota reservations must be handoff_committed on gateway handoff'
            USING ERRCODE = 'OMQ04';
    END IF;

    INSERT INTO openmettle.quota_gateway_handoffs (
        gateway_request_id, metering_enforced, cost_required
    ) VALUES (
        NEW.id, false, false
    );

    SELECT metering_enforced INTO STRICT v_enforced
      FROM openmettle.quota_enforcement
     WHERE id
       FOR SHARE;

    SELECT cost_denomination INTO v_cost_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    SELECT kind INTO v_scope_kind
      FROM openmettle.scopes
     WHERE id = NEW.scope_id;
    SELECT id INTO v_actor_scope_id
      FROM openmettle.scopes
     WHERE personal_user_id = NEW.actor_user_id;

    v_any_cost_limit := EXISTS (
        SELECT 1
          FROM openmettle.quota_defaults qd
         WHERE qd.resource_kind = 'usage_cost_micros'
           AND qd.hard_limit IS NOT NULL
           AND qd.scope_kind IN ('instance', 'personal', v_scope_kind)
    ) OR EXISTS (
        SELECT 1
          FROM openmettle.quota_overrides qo
         WHERE qo.resource_kind = 'usage_cost_micros'
           AND qo.scope_id IN (NEW.scope_id, v_actor_scope_id)
           AND qo.revoked_at IS NULL
           AND (qo.expires_at IS NULL OR qo.expires_at > clock_timestamp())
    );
    v_cost_required := v_cost_denom IS NOT NULL AND v_any_cost_limit;

    IF v_any_cost_limit
       AND position(
           ',' || NEW.id::text || ',' IN coalesce(
               pg_catalog.current_setting('openmettle.turn_cost_unqualified_requests', true),
               ''
           )
       ) > 0 THEN
        RAISE EXCEPTION 'missing qualified cost_bound for cost-limited gateway handoff'
            USING ERRCODE = 'OMQ04';
    END IF;

    IF v_enforced THEN
        IF v_any_cost_limit AND v_cost_denom IS NULL THEN
            RAISE EXCEPTION 'cost denomination unconfigured for cost-limited gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        IF NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_tokens'
               AND qr.state = 'handoff_committed'
               AND qr.reserved_units = NEW.units
               AND qr.held_units = NEW.units
               AND qr.settled_units = 0
               AND qr.accepted_source_revision IS NULL
               AND qr.scope_id = NEW.scope_id
               AND qr.actor_user_id = NEW.actor_user_id
               AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
        ) THEN
            RAISE EXCEPTION 'missing or mismatched handoff_committed usage_tokens reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        IF v_cost_required AND NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_cost_micros'
               AND qr.state = 'handoff_committed'
               AND qr.settled_units = 0
               AND qr.accepted_source_revision IS NULL
               AND qr.scope_id = NEW.scope_id
               AND qr.actor_user_id = NEW.actor_user_id
               AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
        ) THEN
            RAISE EXCEPTION 'missing or mismatched handoff_committed usage_cost_micros reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        IF position(
            ',' || NEW.id::text || ',' IN coalesce(
                pg_catalog.current_setting('openmettle.turn_device_required_requests', true),
                ''
            )
        ) > 0
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.quota_reservations qr
                WHERE qr.scope_id = NEW.scope_id
                  AND qr.run_id = NEW.run_id
                  AND qr.gateway_request_id IS NULL
                  AND qr.resource_kind = 'device_reservations'
                  AND qr.state = 'handoff_committed'
                  AND qr.device_grant_id IS NOT NULL
           ) THEN
            RAISE EXCEPTION 'missing handoff_committed device_reservations hold for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

    END IF;

    IF v_enforced OR v_cost_required THEN
        UPDATE openmettle.quota_gateway_handoffs
           SET metering_enforced = v_enforced,
               cost_required = v_cost_required
         WHERE gateway_request_id = NEW.id;
    END IF;

    RETURN NULL;
END;
$$;

-- Lock a replayed queued run in canonical order (runs -> gateway_reservations), reuse any
-- pre-existing gateway_reservations row (even with id <> run_id), or insert one using the
-- locked run's original actor_approval_id.
CREATE FUNCTION openmettle.quota_ensure_replayed_run_gateway_reservation(
    p_scope uuid,
    p_run uuid,
    p_actor uuid,
    p_units bigint
)
RETURNS TABLE (
    reservation_id uuid,
    units bigint,
    inserted boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    r openmettle.runs%ROWTYPE;
    g openmettle.gateway_reservations%ROWTYPE;
BEGIN
    SELECT * INTO r
      FROM openmettle.runs
     WHERE scope_id = p_scope
       AND id = p_run
       AND actor_user_id = p_actor
       FOR NO KEY UPDATE;
    IF NOT FOUND OR r.state <> 'queued' OR r.actor_approval_id IS NULL THEN
        RETURN;
    END IF;
    SELECT * INTO g
      FROM openmettle.gateway_reservations
     WHERE run_id = p_run
       FOR NO KEY UPDATE;
    IF FOUND THEN
        reservation_id := g.id;
        units := g.units;
        inserted := false;
        RETURN NEXT;
        RETURN;
    END IF;
    INSERT INTO openmettle.gateway_reservations
        (id, scope_id, actor_user_id, approval_id, run_id, units)
    VALUES (r.id, r.scope_id, r.actor_user_id, r.actor_approval_id, r.id, p_units)
    RETURNING * INTO STRICT g;
    reservation_id := g.id;
    units := g.units;
    inserted := true;
    RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_ensure_replayed_run_gateway_reservation(uuid, uuid, uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_ensure_replayed_run_gateway_reservation(uuid, uuid, uuid, bigint) TO openmettle_api;
