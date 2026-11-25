-- ADR 0044, increment 6: remove the superseded ADR 0037 gateway provisioning tables,
-- binding/caller-session columns, and legacy handoff functions; narrow `openmettle_api`
-- off round-level `gateway_requests` writes/recovery; and narrow `openmettle_gateway` to a
-- function-only database boundary (`gateway_dispatch`, `gateway_dispatch_scoped`, and
-- `gateway_settle_report`) with zero table or column privileges.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.

-- Acquire writer-excluding locks atomically via a bounded `NOWAIT` retry loop (matching
-- migration 34) inside one autocommit-safe `DO` block so no partial table lock is held across
-- retries and concurrent settlement writers cannot deadlock. Fail closed if any legacy bound,
-- caller-session, or caller-priced rows remain; then drop superseded functions, columns,
-- constraints, indexes, and tables.
DO $$
DECLARE
    v_timeout interval;
    v_deadline timestamptz;
    v_names text[];
    v_name text;
BEGIN
    SELECT coalesce(nullif(setting::bigint, 0), 15000) * interval '1 millisecond'
      INTO v_timeout
      FROM pg_catalog.pg_settings
     WHERE name = 'lock_timeout';
    v_timeout := coalesce(v_timeout, interval '15 seconds');
    v_deadline := pg_catalog.clock_timestamp() + v_timeout;

    LOOP
        BEGIN
            LOCK TABLE openmettle.gateway_reservations IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_requests IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_usage_reports IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_settlements IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_audit IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_intents IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_policy IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_bindings IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_generations IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_nonces IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.quota_reservations IN SHARE MODE NOWAIT;
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

    IF EXISTS (
        SELECT 1
          FROM openmettle.gateway_requests q
         WHERE q.binding_id IS NOT NULL
            OR q.generation IS NOT NULL
            OR q.policy_revision IS NOT NULL
            OR q.session_id IS NOT NULL
            OR q.run_id IS NULL
            OR q.round IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 37 cannot proceed with bound or caller-session gateway_requests rows'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM openmettle.gateway_reservations r
         WHERE r.run_id IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 37 cannot proceed with caller-session gateway_reservations rows'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM openmettle.gateway_usage_reports g
         WHERE g.cost IS NOT NULL
            OR g.unit IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 37 cannot proceed with caller-priced gateway_usage_reports rows'
            USING ERRCODE = '23514';
    END IF;

    DROP FUNCTION openmettle.gateway_handoff(uuid, bytea, bytea, bytea, uuid);
    DROP FUNCTION openmettle.quota_commit_handoff(uuid, bytea);

    REVOKE ALL PRIVILEGES ON TABLE openmettle.gateway_requests
        FROM openmettle_api, openmettle_gateway;

    DROP INDEX openmettle.gateway_requests_caller_reservation_idx;
    DROP INDEX openmettle.gateway_requests_unbound_outstanding_idx;

    SELECT pg_catalog.array_agg(c.conname::text) INTO v_names
      FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'openmettle.gateway_requests'::pg_catalog.regclass
       AND c.contype = 'c'
       AND (SELECT pg_catalog.array_agg(a.attname::text ORDER BY a.attname::text COLLATE "C")
              FROM pg_catalog.pg_attribute a
             WHERE a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey))
           = ARRAY['round', 'run_id', 'session_id'];
    IF coalesce(pg_catalog.cardinality(v_names), 0) <> 1 THEN
        RAISE EXCEPTION 'expected one gateway_requests caller/run CHECK, found %',
            coalesce(pg_catalog.cardinality(v_names), 0);
    END IF;
    EXECUTE pg_catalog.format(
        'ALTER TABLE openmettle.gateway_requests DROP CONSTRAINT %I',
        v_names[1]
    );

    SELECT pg_catalog.array_agg(c.conname::text ORDER BY c.conname::text COLLATE "C") INTO v_names
      FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'openmettle.gateway_requests'::pg_catalog.regclass
       AND c.contype = 'f'
       AND c.confrelid IN (
           'openmettle.gateway_generations'::pg_catalog.regclass,
           'openmettle.gateway_bindings'::pg_catalog.regclass,
           'openmettle.gateway_policy'::pg_catalog.regclass
       );
    IF coalesce(pg_catalog.cardinality(v_names), 0) <> 3 THEN
        RAISE EXCEPTION 'expected three superseded gateway_requests foreign keys, found %',
            coalesce(pg_catalog.cardinality(v_names), 0);
    END IF;
    FOREACH v_name IN ARRAY v_names LOOP
        EXECUTE pg_catalog.format(
            'ALTER TABLE openmettle.gateway_requests DROP CONSTRAINT %I',
            v_name
        );
    END LOOP;

    ALTER TABLE openmettle.gateway_requests
        DROP CONSTRAINT gateway_requests_handoff_check,
        DROP CONSTRAINT gateway_requests_cost_bound_check,
        DROP COLUMN binding_id,
        DROP COLUMN generation,
        DROP COLUMN policy_revision,
        DROP COLUMN session_id,
        ALTER COLUMN run_id SET NOT NULL,
        ALTER COLUMN round SET NOT NULL,
        ADD CONSTRAINT gateway_requests_handoff_check CHECK (
            (state = 'handed_off') = (report_source IS NOT NULL)
            AND (state <> 'handed_off' OR report_source = installation)
            AND (bearer_hash IS NOT NULL) = (state = 'handed_off')
            AND (claim_hash IS NOT NULL) = (bearer_hash IS NOT NULL)
            AND (bearer_hash IS NULL OR (
                octet_length(bearer_hash) = 32
                AND octet_length(claim_hash) = 32
                AND bearer_hash <> dispatch_hash
            ))
            AND (dispatched_at IS NULL OR state = 'handed_off')
        ),
        ADD CONSTRAINT gateway_requests_cost_bound_check CHECK (
            (cost_fixed_micros IS NULL) = (cost_micros_per_token IS NULL)
            AND (cost_fixed_micros IS NULL OR (
                state = 'handed_off'
                AND cost_fixed_micros >= 0
                AND cost_micros_per_token >= 0
                AND (cost_fixed_micros > 0 OR cost_micros_per_token > 0)
            ))
        );

    DROP TABLE openmettle.gateway_audit;
    DROP TABLE openmettle.gateway_intents;
    DROP TABLE openmettle.gateway_policy;

    SELECT pg_catalog.array_agg(c.conname::text) INTO v_names
      FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'openmettle.gateway_bindings'::pg_catalog.regclass
       AND c.confrelid = 'openmettle.gateway_generations'::pg_catalog.regclass
       AND c.contype = 'f';
    IF coalesce(pg_catalog.cardinality(v_names), 0) <> 1 THEN
        RAISE EXCEPTION 'expected one gateway_bindings -> gateway_generations foreign key, found %',
            coalesce(pg_catalog.cardinality(v_names), 0);
    END IF;
    EXECUTE pg_catalog.format(
        'ALTER TABLE openmettle.gateway_bindings DROP CONSTRAINT %I',
        v_names[1]
    );

    DROP TABLE openmettle.gateway_generations;
    DROP TABLE openmettle.gateway_nonces;
    DROP TABLE openmettle.gateway_bindings;
END
$$;

-- Every `gateway_requests` row belongs to a leased run round and is allocated only by
-- `openmettle_worker`.
CREATE OR REPLACE FUNCTION openmettle.gateway_allocate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.run_id IS NULL OR NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RAISE EXCEPTION 'incorrect inference role' USING ERRCODE = '42501';
    END IF;
    UPDATE openmettle.gateway_reservations SET allocated = allocated + NEW.units
     WHERE id = NEW.reservation_id AND units - allocated >= NEW.units;
    IF NOT FOUND THEN RAISE EXCEPTION 'reservation unavailable' USING ERRCODE = '23514'; END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openmettle.gateway_release(p_request uuid, p_dispatch bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    SELECT * INTO req FROM openmettle.gateway_requests WHERE id = p_request
        AND run_id IS NOT NULL
        AND octet_length(p_dispatch) = 32 AND dispatch_hash = sha256(p_dispatch) AND state = 'reserved'
        AND pg_has_role(session_user, 'openmettle_worker', 'USAGE');
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM FROM openmettle.gateway_reservations WHERE id = req.reservation_id FOR UPDATE;
    UPDATE openmettle.gateway_requests SET state = 'released' WHERE id = p_request AND state = 'reserved';
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE openmettle.gateway_reservations SET allocated = allocated - req.units WHERE id = req.reservation_id;
    RETURN true;
END
$$;
REVOKE EXECUTE ON FUNCTION openmettle.gateway_release(uuid, bytea) FROM openmettle_api;

CREATE OR REPLACE FUNCTION openmettle.gateway_handoff_round_confirm(p_request uuid, p_dispatch bytea, p_lease uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway handoff requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.gateway_requests q WHERE q.id = p_request AND q.run_id IS NOT NULL
        AND octet_length(p_dispatch) = 32 AND q.dispatch_hash = sha256(p_dispatch) AND q.state = 'handed_off'
        AND q.dispatched_at IS NULL
        AND pg_has_role(session_user, 'openmettle_worker', 'USAGE');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid turn handoff' USING ERRCODE = '42501';
    END IF;
    SET CONSTRAINTS ALL IMMEDIATE;
    IF NOT openmettle.gateway_round_authority(p_request, p_lease, clock_timestamp()) THEN
        RAISE EXCEPTION 'gateway handoff is no longer authorized' USING ERRCODE = '42501';
    END IF;
END
$$;

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
    v_cfg_txt text;
    v_snap record;
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

    IF EXISTS (
           SELECT 1
             FROM openmettle.quota_reservations qr
            WHERE qr.scope_id = NEW.scope_id
              AND qr.run_id = NEW.run_id
              AND qr.gateway_request_id IS NULL
              AND qr.resource_kind = 'device_reservations'
              AND (qr.state <> 'handoff_committed' OR qr.device_grant_id IS NULL)
       ) THEN
        RAISE EXCEPTION 'run device_reservations hold must be handoff_committed with a grant before gateway handoff'
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

    BEGIN
        SELECT convert_from(r.config_snapshot, 'UTF8') INTO v_cfg_txt
          FROM openmettle.runs r
         WHERE r.id = NEW.run_id
           AND r.snapshot_format = 'openmettle.conversation'
           AND r.snapshot_version = 1;
    EXCEPTION
        WHEN others THEN
            RAISE EXCEPTION 'invalid run config_snapshot for unbound gateway handoff'
                USING ERRCODE = 'OMQ04';
    END;
    IF v_cfg_txt IS NULL OR v_cfg_txt IS NOT JSON OBJECT WITH UNIQUE KEYS THEN
        RAISE EXCEPTION 'invalid run config_snapshot for unbound gateway handoff'
            USING ERRCODE = 'OMQ04';
    END IF;
    SELECT * INTO v_snap FROM openmettle.gateway_snapshot_cost_bound(v_cfg_txt);
    IF NOT v_snap.valid
       OR (NEW.cost_fixed_micros, NEW.cost_micros_per_token)
          IS DISTINCT FROM (v_snap.fixed_micros, v_snap.micros_per_token) THEN
        RAISE EXCEPTION 'recorded cost_bound does not match run snapshot'
            USING ERRCODE = 'OMQ04';
    END IF;

    IF (v_enforced AND v_cost_required)
       OR EXISTS (
           SELECT 1
             FROM openmettle.quota_reservations qr
            WHERE qr.gateway_request_id = NEW.id
              AND qr.resource_kind = 'usage_cost_micros'
       ) THEN
        IF NEW.cost_fixed_micros IS NULL
           OR NEW.cost_micros_per_token IS NULL
           OR NOT EXISTS (
               SELECT 1
                 FROM openmettle.quota_reservations qr
                WHERE qr.gateway_request_id = NEW.id
                  AND qr.resource_kind = 'usage_cost_micros'
                  AND qr.state = 'handoff_committed'
                  AND qr.reserved_units::numeric
                      = NEW.units::numeric * NEW.cost_micros_per_token + NEW.cost_fixed_micros
                  AND qr.held_units = qr.reserved_units
                  AND qr.settled_units = 0
                  AND qr.accepted_source_revision IS NULL
                  AND qr.scope_id = NEW.scope_id
                  AND qr.actor_user_id = NEW.actor_user_id
                  AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
           ) THEN
            RAISE EXCEPTION 'missing or mismatched recorded cost_bound for unbound gateway handoff'
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

CREATE OR REPLACE FUNCTION openmettle.quota_recover_lost_handoff(
    p_id uuid, p_dispatch bytea, p_scope uuid, p_actor uuid, p_run uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE q openmettle.gateway_requests%ROWTYPE; receipt openmettle.quota_gateway_handoffs%ROWTYPE;
BEGIN
    IF p_run IS NULL OR NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RAISE EXCEPTION 'invalid recovery authority' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO q FROM openmettle.gateway_requests
     WHERE id = p_id AND scope_id = p_scope AND actor_user_id = p_actor
       AND run_id = p_run AND octet_length(p_dispatch) = 32 AND dispatch_hash = sha256(p_dispatch);
    IF NOT FOUND THEN RAISE EXCEPTION 'invalid recovery authority' USING ERRCODE = '42501'; END IF;
    PERFORM FROM openmettle.runs WHERE id = p_run FOR NO KEY UPDATE;
    PERFORM FROM openmettle.gateway_reservations WHERE id = q.reservation_id FOR NO KEY UPDATE;
    SELECT * INTO STRICT q FROM openmettle.gateway_requests WHERE id = p_id FOR NO KEY UPDATE;
    IF q.state <> 'handed_off' THEN
        PERFORM openmettle.quota_unwind_request(q.id);
        RETURN 'unwound_unsent';
    END IF;
    SELECT * INTO receipt FROM openmettle.quota_gateway_handoffs WHERE gateway_request_id = q.id;
    IF EXISTS (SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id = q.id AND
        (h.state NOT IN ('handoff_committed', 'settled') OR (h.scope_id, h.actor_user_id, h.run_id) IS DISTINCT FROM
        (q.scope_id, q.actor_user_id, q.run_id) OR (h.resource_kind = 'usage_tokens' AND h.reserved_units <> q.units)
        OR (h.resource_kind = 'usage_cost_micros' AND (
            (q.cost_fixed_micros IS NOT NULL
                AND h.reserved_units::numeric <> q.units::numeric * q.cost_micros_per_token + q.cost_fixed_micros)
            OR (q.cost_fixed_micros IS NULL AND h.state <> 'settled')))))
      OR (receipt.metering_enforced AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE gateway_request_id = q.id AND resource_kind = 'usage_tokens'))
      OR (receipt.metering_enforced AND receipt.cost_required AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE gateway_request_id = q.id AND resource_kind = 'usage_cost_micros')) THEN
        RAISE EXCEPTION 'gateway handoff invariant failed' USING ERRCODE = 'OMQ04';
    END IF;
    IF NOT EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id = q.id) THEN
        RETURN 'unmetered_legacy_handoff';
    END IF;
    RETURN 'handoff_committed';
END
$$;
REVOKE EXECUTE ON FUNCTION openmettle.quota_recover_lost_handoff(uuid, bytea, uuid, uuid, uuid)
    FROM openmettle_api;

CREATE OR REPLACE FUNCTION openmettle.quota_gateway_fold(p_request uuid, p_kind text, p_units bigint, p_through bigint)
RETURNS TABLE(rev bigint, source uuid, report uuid, state text, settled numeric, held bigint)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
DECLARE
    step record; prompt numeric := 0; completion numeric := 0; reasoning numeric := 0;
    included boolean := true; separate_seen boolean := false; last_k bigint := -1; last_r bigint := -1;
    v_priced boolean := false; v_fixed bigint; v_rate bigint;
    tokens numeric; measured numeric; complete boolean;
BEGIN
    SELECT q.cost_fixed_micros IS NOT NULL,
           q.cost_fixed_micros, q.cost_micros_per_token
      INTO v_priced, v_fixed, v_rate
      FROM openmettle.gateway_requests q
     WHERE q.id = p_request;
    v_priced := coalesce(v_priced, false);
    state := 'handoff_committed'; settled := 0; held := p_units;
    FOR step IN SELECT g.* FROM openmettle.quota_accepted_gateway_reports a
        JOIN openmettle.gateway_usage_reports g USING (request_id, revision, final)
        WHERE a.request_id = p_request AND a.revision <= p_through ORDER BY a.revision
    LOOP
        rev := step.revision; source := step.source; report := step.report_id;
        IF p_kind = 'usage_cost_micros' AND NOT v_priced THEN
            measured := ceil(step.cost); complete := step.cost IS NOT NULL;
        ELSE
            IF step.prompt_tokens IS NOT NULL THEN prompt := step.prompt_tokens; END IF;
            IF step.completion_tokens IS NOT NULL THEN completion := step.completion_tokens; last_k := rev; END IF;
            IF step.reasoning_tokens IS NOT NULL THEN
                reasoning := step.reasoning_tokens; included := step.reasoning_included; last_r := rev;
                separate_seen := separate_seen OR NOT included;
            END IF;
            complete := step.prompt_tokens IS NOT NULL AND step.completion_tokens IS NOT NULL
                AND (step.reasoning_tokens IS NOT NULL OR NOT separate_seen);
            tokens := CASE WHEN num_nonnulls(step.prompt_tokens, step.completion_tokens, step.reasoning_tokens) = 0 THEN NULL
                WHEN NOT included THEN prompt + completion + reasoning
                WHEN last_r >= last_k THEN prompt + greatest(reasoning, completion)
                ELSE prompt + completion END;
            IF p_kind = 'usage_cost_micros' THEN
                IF tokens IS NULL THEN
                    measured := NULL;
                ELSE
                    measured := tokens * v_rate::numeric + v_fixed::numeric;
                    IF measured >= 1e38::numeric THEN
                        RAISE EXCEPTION 'gateway cost measurement exceeds numeric(38, 0) bound'
                            USING ERRCODE = '23514';
                    END IF;
                END IF;
            ELSE
                measured := tokens;
            END IF;
        END IF;
        IF step.incomplete IS NOT NULL THEN
            state := 'settled'; held := 0;
        ELSIF measured IS NOT NULL THEN
            settled := CASE WHEN complete THEN measured ELSE greatest(measured, settled) END;
            IF complete AND step.final THEN state := 'settled'; END IF;
            held := CASE WHEN state = 'settled' THEN 0 ELSE greatest(0, p_units - settled)::bigint END;
        END IF;
        RETURN NEXT;
    END LOOP;
END
$$;

CREATE OR REPLACE FUNCTION openmettle.gateway_backfill_legacy_request_cost_bound(
    p_request uuid,
    p_cost_fixed_micros bigint,
    p_cost_micros_per_token bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
    q openmettle.gateway_requests%ROWTYPE;
    h openmettle.quota_reservations%ROWTYPE;
    v_cfg_txt text;
    v_snap record;
    v_latest_rev bigint;
    v_latest_source uuid;
    v_latest_report uuid;
    f record;
    v_source_key text;
BEGIN
    IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        RAISE EXCEPTION 'gateway legacy cost_bound backfill requires openmettle_owner'
            USING ERRCODE = '42501';
    END IF;
    IF p_request IS NULL
       OR p_cost_fixed_micros IS NULL
       OR p_cost_micros_per_token IS NULL
       OR p_cost_fixed_micros < 0
       OR p_cost_micros_per_token < 0
       OR (p_cost_fixed_micros = 0 AND p_cost_micros_per_token = 0) THEN
        RAISE EXCEPTION 'invalid gateway cost bound' USING ERRCODE = '23514';
    END IF;
    PERFORM FROM openmettle.runs r
      WHERE r.id = (SELECT qr.run_id FROM openmettle.gateway_requests qr WHERE qr.id = p_request)
        FOR SHARE;
    SELECT * INTO q
      FROM openmettle.gateway_requests qr
     WHERE qr.id = p_request
       AND qr.state = 'handed_off'
       AND qr.cost_fixed_micros IS NULL
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'legacy request is not eligible for cost_bound backfill'
            USING ERRCODE = '23514';
    END IF;
    BEGIN
        SELECT convert_from(r.config_snapshot, 'UTF8') INTO v_cfg_txt
          FROM openmettle.runs r
         WHERE r.id = q.run_id
           AND r.snapshot_format = 'openmettle.conversation'
           AND r.snapshot_version = 1;
    EXCEPTION
        WHEN others THEN
            RAISE EXCEPTION 'backfill cost_bound does not match run snapshot'
                USING ERRCODE = '23514';
    END;
    SELECT * INTO v_snap FROM openmettle.gateway_snapshot_cost_bound(v_cfg_txt);
    IF NOT v_snap.valid
       OR (v_snap.fixed_micros IS NOT NULL
           AND (p_cost_fixed_micros, p_cost_micros_per_token)
               IS DISTINCT FROM (v_snap.fixed_micros, v_snap.micros_per_token)) THEN
        RAISE EXCEPTION 'backfill cost_bound does not match run snapshot'
            USING ERRCODE = '23514';
    END IF;
    PERFORM FROM openmettle.quota_reservations qr
      WHERE qr.gateway_request_id = q.id
        AND qr.state IN ('handoff_committed', 'settled')
      ORDER BY qr.resource_kind, qr.id
        FOR NO KEY UPDATE;
    SELECT * INTO h
      FROM openmettle.quota_reservations qr
     WHERE qr.gateway_request_id = q.id
       AND qr.resource_kind = 'usage_cost_micros'
       AND qr.state = 'settled'
       AND qr.settled_units = 0
       AND qr.held_units = 0
       AND qr.reserved_units::numeric
           = q.units::numeric * p_cost_micros_per_token + p_cost_fixed_micros;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'legacy request cost hold does not match backfill cost_bound'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id, revision, final)
         WHERE a.request_id = q.id
           AND (g.cost IS NOT NULL OR g.unit IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'legacy request already accepted a caller-priced usage report'
            USING ERRCODE = '23514';
    END IF;
    UPDATE openmettle.gateway_requests qr
       SET cost_fixed_micros = p_cost_fixed_micros,
           cost_micros_per_token = p_cost_micros_per_token
     WHERE qr.id = q.id;

    SELECT a.revision, g.source, g.report_id
      INTO v_latest_rev, v_latest_source, v_latest_report
      FROM openmettle.quota_accepted_gateway_reports a
      JOIN openmettle.gateway_usage_reports g USING (request_id, revision, final)
     WHERE a.request_id = q.id
     ORDER BY a.revision DESC
     LIMIT 1;
    IF FOUND THEN
        IF h.accepted_source_revision IS NOT NULL THEN
            IF h.accepted_source_revision > v_latest_rev THEN
                RAISE EXCEPTION 'legacy request cost hold revision exceeds accepted history'
                    USING ERRCODE = '23514';
            END IF;
            SELECT * INTO f
              FROM openmettle.quota_gateway_fold(
                       q.id,
                       'usage_cost_micros',
                       h.reserved_units,
                       h.accepted_source_revision
                   )
             ORDER BY rev DESC LIMIT 1;
            IF FOUND THEN
                IF f.state IS DISTINCT FROM 'settled' OR f.held <> 0 THEN
                    RAISE EXCEPTION 'legacy request accepted history does not close its cost hold'
                        USING ERRCODE = '23514';
                END IF;
                IF f.settled <> 0 THEN
                    PERFORM openmettle.quota_adjust(h.id, f.settled, 0);
                    h.revision := h.revision + 1;
                    v_source_key := CASE
                        WHEN EXISTS (
                            SELECT 1
                              FROM openmettle.quota_reconciliations rec
                             WHERE rec.reservation_id = h.id
                               AND rec.source_key = 'gateway:' || f.rev
                        ) THEN 'backfill:' || f.rev
                        ELSE 'gateway:' || f.rev
                    END;
                    INSERT INTO openmettle.quota_reconciliations (
                        reservation_id, transition_revision, source_key,
                        gateway_request_id, gateway_report_source, gateway_report_id,
                        source_revision, kind, cumulative_units, delta_active, delta_reserved
                    ) VALUES (
                        h.id, h.revision, v_source_key,
                        q.id, f.source, f.report,
                        f.rev, 'final_correction', f.settled, f.settled, 0
                    );
                    UPDATE openmettle.quota_reservations
                       SET settled_units = f.settled,
                           revision = h.revision
                     WHERE id = h.id;
                END IF;
            END IF;
        END IF;

        PERFORM openmettle.quota_settle_gateway_usage(
            q.id,
            v_latest_source,
            v_latest_report,
            v_latest_rev
        );

        IF EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = q.id
               AND (qr.state <> 'settled'
                    OR qr.held_units <> 0
                    OR qr.accepted_source_revision IS DISTINCT FROM v_latest_rev)
        ) THEN
            RAISE EXCEPTION 'legacy request accepted history does not close its holds'
                USING ERRCODE = '23514';
        END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION openmettle.quota_verify_accounting_drift()
RETURNS TABLE(storage_mismatches bigint, budget_mismatches bigint, settlement_mismatches bigint,
              pending_gateway_reconciliations bigint, oldest_pending_age interval)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    WITH storage AS (
        SELECT a.scope_id, a.active_bytes, a.retained_bytes, a.reserved_bytes,
            coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions
                WHERE scope_id = a.scope_id AND state = 'active'), 0) AS active,
            coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions
                WHERE scope_id = a.scope_id AND state IN ('retained', 'purging')), 0) AS retained,
            coalesce((SELECT sum(max_bytes) FROM openmettle.storage_reservations
                WHERE scope_id = a.scope_id AND state = 'reserved'), 0) AS reserved FROM openmettle.storage_accounts a
    ), storage_errors AS (
        SELECT FROM storage WHERE (active_bytes, retained_bytes, reserved_bytes) <> (active, retained, reserved)
        UNION ALL SELECT FROM openmettle.storage_instance i WHERE
            (i.active_bytes, i.retained_bytes, i.reserved_bytes) <> (SELECT coalesce(sum(active), 0), coalesce(sum(retained), 0),
                coalesce(sum(reserved), 0) FROM storage)
        UNION ALL SELECT FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr
            ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id
            WHERE r.state IN ('active', 'retained', 'purging') AND sr.payload_ino IS NULL
            AND EXISTS (SELECT FROM openmettle.storage_volume_control WHERE id AND volume_id IS NOT NULL)
    ), applied AS (
        SELECT h.* FROM openmettle.quota_reservations h WHERE gateway_request_id IS NOT NULL
            AND state IN ('handoff_committed', 'settled')
    ), gateway_errors AS (
        SELECT FROM applied h LEFT JOIN LATERAL (SELECT * FROM openmettle.quota_gateway_fold(
            h.gateway_request_id, h.resource_kind, h.reserved_units, h.accepted_source_revision)
            ORDER BY rev DESC LIMIT 1) f ON true
            WHERE (h.state, h.settled_units, h.held_units) IS DISTINCT FROM
            (coalesce(f.state, 'handoff_committed'), coalesce(f.settled, 0), coalesce(f.held, h.reserved_units))
        UNION ALL SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id IS NOT NULL
            AND h.state = 'held' AND (h.accepted_source_revision IS NOT NULL OR h.settled_units <> 0 OR h.held_units <> h.reserved_units)
        UNION ALL SELECT FROM openmettle.quota_gateway_handoffs receipt JOIN openmettle.gateway_requests q
            ON q.id = receipt.gateway_request_id WHERE q.state <> 'handed_off'
            OR EXISTS (SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id = q.id AND
                (h.state NOT IN ('handoff_committed', 'settled') OR (h.scope_id, h.actor_user_id, h.run_id) IS DISTINCT FROM
                (q.scope_id, q.actor_user_id, q.run_id) OR (h.resource_kind = 'usage_tokens' AND h.reserved_units <> q.units)
                OR (h.resource_kind = 'usage_cost_micros' AND (
                    (q.cost_fixed_micros IS NOT NULL
                        AND h.reserved_units::numeric <> q.units::numeric * q.cost_micros_per_token + q.cost_fixed_micros)
                    OR (q.cost_fixed_micros IS NULL AND h.state <> 'settled')))))
            OR (receipt.metering_enforced AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                WHERE h.gateway_request_id = q.id AND h.resource_kind = 'usage_tokens'))
            OR (receipt.metering_enforced AND receipt.cost_required AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                WHERE h.gateway_request_id = q.id AND h.resource_kind = 'usage_cost_micros'))
        UNION ALL SELECT FROM openmettle.gateway_settlements gs JOIN openmettle.gateway_usage_reports gr
            USING(request_id, revision, final) WHERE gs.measured IS DISTINCT FROM CASE
            WHEN num_nonnulls(gr.prompt_tokens, gr.completion_tokens, gr.reasoning_tokens) = 0 THEN NULL
            ELSE coalesce(gr.prompt_tokens, 0)::numeric + CASE WHEN gr.reasoning_included THEN
            greatest(coalesce(gr.completion_tokens, 0), coalesce(gr.reasoning_tokens, 0))::numeric
            ELSE coalesce(gr.completion_tokens, 0)::numeric + coalesce(gr.reasoning_tokens, 0) END END
    ), pending AS (
        SELECT h.id, min(a.accepted_at) AS oldest FROM applied h
        JOIN openmettle.quota_accepted_gateway_reports a ON a.request_id = h.gateway_request_id
            AND a.revision > coalesce(h.accepted_source_revision, -1) GROUP BY h.id
    )
    SELECT (SELECT count(*) FROM storage_errors),
        (SELECT count(*) FROM openmettle.quota_budgets b WHERE b.reserved_held <> (SELECT coalesce(sum(h.held_units), 0)
             FROM openmettle.quota_reservation_charges c JOIN openmettle.quota_reservations h ON h.id = c.reservation_id
             WHERE c.budget_id = b.id AND h.state IN ('held', 'handoff_committed'))
         OR b.active_used <> (SELECT coalesce(sum(rec.delta_active), 0) FROM openmettle.quota_reservation_charges c
             JOIN openmettle.quota_reconciliations rec USING(reservation_id) WHERE c.budget_id = b.id)),
        (SELECT count(*) FROM gateway_errors), (SELECT count(*) FROM pending), (SELECT now() - min(oldest) FROM pending)
$$;

CREATE OR REPLACE FUNCTION openmettle.enforce_gateway_report_sweep_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        RETURN NEW;
    END IF;
    IF NEW.incomplete IN ('not_dispatched', 'unreported') THEN
        RAISE EXCEPTION 'sweep-only incomplete reason requires openmettle_owner'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.revision = 0 THEN
        RAISE EXCEPTION 'revision 0 on an unbound request requires openmettle_owner'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION openmettle.enforce_gateway_report_bound_cost()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'unbound usage report cannot supply cost'
        USING ERRCODE = '23514';
END;
$$;

CREATE OR REPLACE FUNCTION openmettle.enforce_gateway_final_settlement_closes() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
    latest openmettle.gateway_settlements%ROWTYPE;
    has_not_dispatched boolean;
    has_other_reason boolean;
    folded text;
    cost_units bigint;
    cost_folded text;
    advanced boolean := (TG_OP = 'INSERT'
        OR (NEW.revision, NEW.final) IS DISTINCT FROM (OLD.revision, OLD.final));
BEGIN
    SELECT * INTO latest FROM openmettle.gateway_settlements s WHERE s.request_id = NEW.request_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO STRICT req FROM openmettle.gateway_requests q WHERE q.id = latest.request_id;

    SELECT EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id, revision, final)
         WHERE a.request_id = latest.request_id AND g.incomplete = 'not_dispatched'
    ), EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id, revision, final)
         WHERE a.request_id = latest.request_id AND g.incomplete IS NOT NULL
           AND g.incomplete <> 'not_dispatched'
    ) INTO has_not_dispatched, has_other_reason;
    IF has_not_dispatched AND (req.dispatched_at IS NOT NULL
        OR latest.revision <> 0 OR latest.measured IS NOT NULL
        OR EXISTS (SELECT FROM openmettle.quota_accepted_gateway_reports a
                    WHERE a.request_id = latest.request_id AND a.revision <> 0)) THEN
        RAISE EXCEPTION 'a not_dispatched report needs an undispatched request without a binding'
            USING ERRCODE = '23514';
    END IF;
    IF has_other_reason AND req.dispatched_at IS NULL THEN
        RAISE EXCEPTION 'an incomplete report needs a dispatched request without a binding'
            USING ERRCODE = '23514';
    END IF;

    IF req.dispatched_at IS NULL AND advanced THEN
        IF NOT (
            latest.final
            AND latest.revision = 0
            AND latest.measured IS NULL
            AND latest.outstanding = 0
            AND EXISTS (
                SELECT 1
                  FROM openmettle.gateway_usage_reports g
                 WHERE g.request_id = latest.request_id
                   AND g.revision = 0
                   AND g.final
                   AND g.incomplete = 'not_dispatched'
            )
            AND NOT EXISTS (
                SELECT 1
                  FROM openmettle.quota_accepted_gateway_reports a
                 WHERE a.request_id = latest.request_id
                   AND a.revision <> 0
            )
        ) THEN
            RAISE EXCEPTION 'an undispatched request without a binding can only close as not_dispatched'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF advanced AND EXISTS (
        SELECT 1
          FROM openmettle.gateway_usage_reports g
         WHERE g.request_id = NEW.request_id
           AND g.revision = NEW.revision
           AND (g.cost IS NOT NULL OR g.unit IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'unbound usage report cannot supply cost'
            USING ERRCODE = '23514';
    END IF;

    IF advanced
       AND req.cost_fixed_micros IS NULL
       AND EXISTS (
           SELECT 1
             FROM openmettle.quota_reservations h
            WHERE h.gateway_request_id = req.id
              AND h.resource_kind = 'usage_cost_micros'
       )
       AND EXISTS (
           SELECT 1
             FROM openmettle.gateway_usage_reports g
            WHERE g.request_id = NEW.request_id
              AND g.revision = NEW.revision
              AND g.incomplete IS NULL
       ) THEN
        RAISE EXCEPTION 'unbound cost-held request requires recorded cost_bound before accepting usage counts'
            USING ERRCODE = '23514';
    END IF;

    IF NOT latest.final THEN RETURN NULL; END IF;

    IF advanced
       AND EXISTS (
           SELECT FROM openmettle.quota_accepted_gateway_reports a
             JOIN openmettle.gateway_usage_reports g USING (request_id, revision, final)
            WHERE a.request_id = NEW.request_id AND a.revision = NEW.revision AND a.final
              AND g.incomplete IS NULL
              AND (g.prompt_tokens IS NULL OR g.completion_tokens IS NULL)
       ) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE = '23514';
    END IF;
    SELECT f.state INTO folded
      FROM openmettle.quota_gateway_fold(latest.request_id, 'usage_tokens', req.units, latest.revision) f
     ORDER BY f.rev DESC LIMIT 1;
    SELECT h.reserved_units INTO cost_units
      FROM openmettle.quota_reservations h
     WHERE h.gateway_request_id = latest.request_id
       AND h.resource_kind = 'usage_cost_micros';
    IF FOUND THEN
        SELECT f.state INTO cost_folded
          FROM openmettle.quota_gateway_fold(latest.request_id, 'usage_cost_micros', cost_units, latest.revision) f
         ORDER BY f.rev DESC LIMIT 1;
        IF cost_folded IS DISTINCT FROM 'settled' THEN
            RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF latest.outstanding <> 0 OR folded IS DISTINCT FROM 'settled' OR EXISTS (
        SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id = latest.request_id
           AND (h.accepted_source_revision IS DISTINCT FROM latest.revision
                OR h.state <> 'settled')) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION openmettle.gateway_unreported_candidates(
    p_after_created_at timestamptz,
    p_after_id uuid,
    p_upper_created_at timestamptz,
    p_upper_id uuid,
    p_limit integer)
RETURNS TABLE (created_at timestamptz, id uuid, eligible boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RAISE EXCEPTION 'gateway unreported sweep requires openmettle_worker' USING ERRCODE = '42501';
    END IF;
    IF p_after_created_at IS NULL OR p_after_id IS NULL
       OR p_upper_created_at IS NULL OR p_upper_id IS NULL
       OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'invalid gateway unreported page' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    WITH page AS MATERIALIZED (
        SELECT q.created_at, q.id, q.run_id, q.dispatched_at, q.claim_hash
          FROM openmettle.gateway_requests q
         WHERE q.state = 'handed_off'
           AND NOT q.settled_final
           AND (q.created_at, q.id) > (p_after_created_at, p_after_id)
           AND (q.created_at, q.id) <= (p_upper_created_at, p_upper_id)
         ORDER BY q.created_at, q.id
         LIMIT p_limit
    ),
    clock AS MATERIALIZED (SELECT clock_timestamp() AS t)
    SELECT p.created_at,
           p.id,
           (NOT EXISTS (
                SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = p.id
            )
            AND (
                (p.dispatched_at IS NULL AND (
                    r.state <> 'running'
                    OR r.cancel_reason IS NOT NULL
                    OR r.claim_token IS NULL
                    OR sha256(uuid_send(r.claim_token)) <> p.claim_hash
                    OR r.lease_expires_at IS NULL
                    OR r.lease_expires_at <= clock.t
                    OR r.execution_expires_at IS NULL
                    OR r.execution_expires_at <= clock.t
                ))
                OR (p.dispatched_at IS NOT NULL AND
                    coalesce(r.execution_expires_at, a.resume_execution_expires_at, p.dispatched_at)
                        + interval '15 minutes' <= clock.t)
            )) AS eligible
      FROM page p
      JOIN openmettle.runs r ON r.id = p.run_id
      LEFT JOIN openmettle.run_approvals a ON a.id = r.approval_wait_id
      CROSS JOIN clock
     ORDER BY p.created_at, p.id;
END
$$;

CREATE OR REPLACE FUNCTION openmettle.gateway_close_unreported(p_request uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_run uuid;
    r openmettle.runs%ROWTYPE;
    q openmettle.gateway_requests%ROWTYPE;
    v_deadline timestamptz;
    v_now timestamptz;
    v_reason text;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway unreported sweep requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RAISE EXCEPTION 'gateway unreported sweep requires openmettle_worker' USING ERRCODE = '42501';
    END IF;
    SELECT q0.run_id INTO v_run
      FROM openmettle.gateway_requests q0
     WHERE q0.id = p_request
       AND q0.state = 'handed_off'
       AND NOT q0.settled_final;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO r
      FROM openmettle.runs r0
     WHERE r0.id = v_run
       FOR SHARE SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT * INTO q
      FROM openmettle.gateway_requests q0
     WHERE q0.id = p_request
       AND q0.state = 'handed_off'
       AND NOT q0.settled_final
       FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = q.id) THEN
        RETURN NULL;
    END IF;
    v_now := clock_timestamp();
    IF q.dispatched_at IS NULL THEN
        IF r.state = 'running'
           AND r.cancel_reason IS NULL
           AND r.claim_token IS NOT NULL
           AND sha256(uuid_send(r.claim_token)) = q.claim_hash
           AND r.lease_expires_at > v_now
           AND r.execution_expires_at > v_now THEN
            RETURN NULL;
        END IF;
        v_reason := 'not_dispatched';
    ELSE
        v_deadline := coalesce(
            r.execution_expires_at,
            (SELECT a.resume_execution_expires_at
               FROM openmettle.run_approvals a
              WHERE a.id = r.approval_wait_id),
            q.dispatched_at
        );
        IF v_deadline + interval '15 minutes' > v_now THEN
            RETURN NULL;
        END IF;
        v_reason := 'unreported';
    END IF;
    INSERT INTO openmettle.gateway_usage_reports
        (request_id, source, report_id, revision, final, incomplete)
    VALUES (q.id, q.report_source, q.id, 0, true, v_reason);
    INSERT INTO openmettle.gateway_settlements
        (request_id, revision, final, measured, outstanding)
    VALUES (q.id, 0, true, NULL, 0);
    PERFORM openmettle.quota_settle_gateway_usage(q.id, q.report_source, q.id, 0);
    RETURN v_reason;
END
$$;

-- Sole settlement entry point for `openmettle_gateway` (ADR 0044, increment 6): validates
-- routing identity and report shape, preserves exact duplicate replay (including historical
-- accepted reports), detects conflicting reuse, advances `gateway_settlements` and folds
-- quota holds inside one transaction so `openmettle_gateway` needs zero table or column
-- privileges. Returns `'applied'`, `'duplicate'`, `'superseded'`, or `'conflict'`.
CREATE FUNCTION openmettle.gateway_settle_report(
    p_request uuid,
    p_installation uuid,
    p_principal uuid,
    p_scope uuid,
    p_source uuid,
    p_report_id uuid,
    p_revision bigint,
    p_final boolean,
    p_prompt_tokens bigint,
    p_completion_tokens bigint,
    p_reasoning_tokens bigint,
    p_reasoning_included boolean,
    p_cost numeric,
    p_unit text,
    p_incomplete text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_units bigint;
    v_prev_revision bigint;
    v_prev_final boolean;
    v_prev_outstanding bigint;
    v_match_count bigint;
    v_same boolean;
    v_accepted boolean;
    v_inserted integer := 0;
    v_measured numeric;
    v_previous bigint;
    v_held bigint;
    v_closed boolean;
    v_needs_reapply boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway settlement requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT pg_has_role(session_user, 'openmettle_gateway', 'USAGE') THEN
        RAISE EXCEPTION 'gateway settlement requires openmettle_gateway' USING ERRCODE = '42501';
    END IF;
    IF p_request IS NULL
       OR p_installation IS NULL
       OR p_principal IS NULL
       OR p_scope IS NULL
       OR p_source IS NULL
       OR p_report_id IS NULL
       OR p_revision IS NULL
       OR p_revision < 0
       OR p_final IS NULL
       OR (p_prompt_tokens IS NOT NULL AND p_prompt_tokens < 0)
       OR (p_completion_tokens IS NOT NULL AND p_completion_tokens < 0)
       OR (p_reasoning_tokens IS NOT NULL AND p_reasoning_tokens < 0)
       OR (p_reasoning_tokens IS NOT NULL AND p_reasoning_included IS NULL)
       OR ((p_cost IS NULL) <> (p_unit IS NULL)) THEN
        RAISE EXCEPTION 'invalid gateway usage report' USING ERRCODE = '23514';
    END IF;
    IF p_cost IS NOT NULL AND (
        p_cost = 'NaN'::numeric
        OR p_cost < 0
        OR p_cost >= 1e18
        OR scale(p_cost) > 12
        OR octet_length(p_unit) NOT BETWEEN 1 AND 32
    ) THEN
        RAISE EXCEPTION 'invalid gateway usage report' USING ERRCODE = '23514';
    END IF;
    IF p_incomplete IS NOT NULL AND (
        NOT p_final
        OR num_nonnulls(
            p_prompt_tokens, p_completion_tokens, p_reasoning_tokens,
            p_reasoning_included, p_cost, p_unit
        ) <> 0
        OR p_incomplete NOT IN (
            'model_not_served', 'model_mismatch', 'request_body', 'upstream_connect',
            'upstream_transport', 'upstream_timeout', 'upstream_status', 'upstream_encoding',
            'incomplete', 'caller_disconnected', 'no_usage', 'unparsable'
        )
    ) THEN
        RAISE EXCEPTION 'invalid incomplete gateway usage report' USING ERRCODE = '23514';
    END IF;

    PERFORM openmettle.quota_lock_gateway_request_for_settlement(p_request);

    SELECT q.units, s.revision, s.final, s.outstanding
      INTO v_units, v_prev_revision, v_prev_final, v_prev_outstanding
      FROM openmettle.gateway_requests q
      LEFT JOIN openmettle.gateway_settlements s ON s.request_id = q.id
     WHERE q.id = p_request
       AND q.state = 'handed_off'
       AND q.dispatched_at IS NOT NULL
       AND q.report_source = p_source
       AND q.installation = p_installation
       AND q.actor_user_id = p_principal
       AND q.scope_id = p_scope;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'gateway request not eligible for settlement' USING ERRCODE = '23514';
    END IF;

    -- Recognize an exact replay of a previously accepted historical report under the request
    -- lock before enforcing the new-write shape and revision-0 guards.
    SELECT count(*),
           bool_and(
               g.request_id = p_request
               AND g.source = p_source
               AND g.report_id = p_report_id
               AND g.revision = p_revision
               AND g.final = p_final
               AND g.prompt_tokens IS NOT DISTINCT FROM p_prompt_tokens
               AND g.completion_tokens IS NOT DISTINCT FROM p_completion_tokens
               AND g.reasoning_tokens IS NOT DISTINCT FROM p_reasoning_tokens
               AND g.reasoning_included IS NOT DISTINCT FROM p_reasoning_included
               AND g.cost IS NOT DISTINCT FROM p_cost
               AND g.unit IS NOT DISTINCT FROM p_unit
               AND g.incomplete IS NOT DISTINCT FROM p_incomplete
           )
      INTO v_match_count, v_same
      FROM openmettle.gateway_usage_reports g
     WHERE (g.source = p_source AND g.report_id = p_report_id AND g.revision = p_revision)
        OR (g.request_id = p_request AND g.revision = p_revision);

    IF v_match_count > 0 THEN
        IF v_match_count <> 1 OR NOT coalesce(v_same, false) THEN
            RETURN 'conflict';
        END IF;
        SELECT EXISTS (
            SELECT 1
              FROM openmettle.quota_accepted_gateway_reports a
             WHERE a.request_id = p_request
               AND a.revision = p_revision
        ) INTO v_accepted;
        IF v_accepted THEN
            PERFORM openmettle.quota_settle_gateway_usage(p_request, p_source, p_report_id, p_revision);
            RETURN 'duplicate';
        END IF;
        IF p_revision = 0
           OR p_cost IS NOT NULL
           OR p_unit IS NOT NULL
           OR (p_final AND p_incomplete IS NULL
               AND (p_prompt_tokens IS NULL OR p_completion_tokens IS NULL)) THEN
            RAISE EXCEPTION 'invalid gateway usage report' USING ERRCODE = '23514';
        END IF;
        v_inserted := 0;
    ELSE
        IF p_revision = 0
           OR p_cost IS NOT NULL
           OR p_unit IS NOT NULL
           OR (p_final AND p_incomplete IS NULL
               AND (p_prompt_tokens IS NULL OR p_completion_tokens IS NULL)) THEN
            RAISE EXCEPTION 'invalid gateway usage report' USING ERRCODE = '23514';
        END IF;
        INSERT INTO openmettle.gateway_usage_reports (
            request_id, source, report_id, revision, final,
            prompt_tokens, completion_tokens, reasoning_tokens, reasoning_included,
            cost, unit, incomplete
        ) VALUES (
            p_request, p_source, p_report_id, p_revision, p_final,
            p_prompt_tokens, p_completion_tokens, p_reasoning_tokens, p_reasoning_included,
            p_cost, p_unit, p_incomplete
        )
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
        IF v_inserted = 0 THEN
            SELECT count(*),
                   bool_and(
                       g.request_id = p_request
                       AND g.source = p_source
                       AND g.report_id = p_report_id
                       AND g.revision = p_revision
                       AND g.final = p_final
                       AND g.prompt_tokens IS NOT DISTINCT FROM p_prompt_tokens
                       AND g.completion_tokens IS NOT DISTINCT FROM p_completion_tokens
                       AND g.reasoning_tokens IS NOT DISTINCT FROM p_reasoning_tokens
                       AND g.reasoning_included IS NOT DISTINCT FROM p_reasoning_included
                       AND g.cost IS NOT DISTINCT FROM p_cost
                       AND g.unit IS NOT DISTINCT FROM p_unit
                       AND g.incomplete IS NOT DISTINCT FROM p_incomplete
                   )
              INTO v_match_count, v_same
              FROM openmettle.gateway_usage_reports g
             WHERE (g.source = p_source AND g.report_id = p_report_id AND g.revision = p_revision)
                OR (g.request_id = p_request AND g.revision = p_revision);
            IF v_match_count <> 1 OR NOT coalesce(v_same, false) THEN
                RETURN 'conflict';
            END IF;
        END IF;
    END IF;

    IF v_prev_revision = p_revision THEN
        PERFORM openmettle.quota_settle_gateway_usage(p_request, p_source, p_report_id, p_revision);
        RETURN 'duplicate';
    ELSIF (v_prev_revision IS NOT NULL AND v_prev_revision > p_revision)
          OR (coalesce(v_prev_final, false) AND NOT p_final) THEN
        IF v_inserted = 0 THEN
            RETURN 'duplicate';
        ELSE
            RETURN 'superseded';
        END IF;
    END IF;

    v_measured := CASE
        WHEN num_nonnulls(p_prompt_tokens, p_completion_tokens, p_reasoning_tokens) = 0 THEN NULL
        ELSE coalesce(p_prompt_tokens, 0)::numeric + CASE
            WHEN p_reasoning_included THEN
                greatest(coalesce(p_completion_tokens, 0), coalesce(p_reasoning_tokens, 0))::numeric
            ELSE
                coalesce(p_completion_tokens, 0)::numeric + coalesce(p_reasoning_tokens, 0)::numeric
        END
    END;
    v_previous := coalesce(v_prev_outstanding, v_units);

    -- Acceptance by the settlement trigger precedes the quota fold. Stage the settlement with
    -- the prior outstanding projection, fold quotas, and roll back the subtransaction to
    -- republish atomically whenever the folded hold differs.
    v_needs_reapply := false;
    BEGIN
        INSERT INTO openmettle.gateway_settlements (
            request_id, revision, final, measured, outstanding
        ) VALUES (
            p_request, p_revision, p_final, v_measured, v_previous
        )
        ON CONFLICT (request_id) DO UPDATE
           SET revision = EXCLUDED.revision,
               final = EXCLUDED.final,
               measured = EXCLUDED.measured,
               outstanding = EXCLUDED.outstanding;

        PERFORM openmettle.quota_settle_gateway_usage(p_request, p_source, p_report_id, p_revision);

        SELECT qr.held_units, qr.state = 'settled'
          INTO v_held, v_closed
          FROM openmettle.quota_reservations qr
         WHERE qr.gateway_request_id = p_request
           AND qr.resource_kind = 'usage_tokens';
        IF NOT FOUND THEN
            SELECT f.held, f.state = 'settled'
              INTO v_held, v_closed
              FROM openmettle.quota_gateway_fold(p_request, 'usage_tokens', v_units, p_revision) f
             ORDER BY f.rev DESC
             LIMIT 1;
            v_held := coalesce(v_held, v_units);
            v_closed := coalesce(v_closed, false);
        END IF;

        IF p_final AND NOT v_closed THEN
            RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE = '23514';
        END IF;

        IF v_held <> v_previous THEN
            v_needs_reapply := true;
            RAISE EXCEPTION 'reapply settlement with folded outstanding' USING ERRCODE = 'OMF01';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'OMF01' THEN
            NULL;
    END;

    IF v_needs_reapply THEN
        INSERT INTO openmettle.gateway_settlements (
            request_id, revision, final, measured, outstanding
        ) VALUES (
            p_request, p_revision, p_final, v_measured, v_held
        )
        ON CONFLICT (request_id) DO UPDATE
           SET revision = EXCLUDED.revision,
               final = EXCLUDED.final,
               measured = EXCLUDED.measured,
               outstanding = EXCLUDED.outstanding;

        PERFORM openmettle.quota_settle_gateway_usage(p_request, p_source, p_report_id, p_revision);
    END IF;

    RETURN 'applied';
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_settle_report(
    uuid, uuid, uuid, uuid, uuid, uuid, bigint, boolean,
    bigint, bigint, bigint, boolean, numeric, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_settle_report(
    uuid, uuid, uuid, uuid, uuid, uuid, bigint, boolean,
    bigint, bigint, bigint, boolean, numeric, text, text
) TO openmettle_gateway;

-- Revoke every remaining table, column, and internal helper privilege from `openmettle_gateway`
-- so its database surface is strictly `CONNECT`, schema `USAGE`, `gateway_dispatch`,
-- `gateway_dispatch_scoped`, and `gateway_settle_report`.
REVOKE ALL PRIVILEGES ON TABLE
    openmettle.gateway_reservations,
    openmettle.gateway_usage_reports,
    openmettle.gateway_settlements,
    openmettle.account_admin_lock,
    openmettle.projects,
    openmettle.users,
    openmettle.user_identities,
    openmettle.scopes,
    openmettle.local_identity_approvals,
    openmettle.login_providers,
    openmettle.login_provider_revisions,
    openmettle.grant_assignments,
    openmettle.grant_changes,
    openmettle.local_groups,
    openmettle.local_group_memberships,
    openmettle.membership_observations,
    openmettle.grant_mapping_rules,
    openmettle.grant_mapping_revisions,
    openmettle.project_settings,
    openmettle.platform_capability_denies,
    openmettle.user_capability_denies,
    openmettle.user_capability_grants,
    openmettle.quota_defaults,
    openmettle.quota_enforcement,
    openmettle.quota_overrides,
    openmettle.quota_budgets,
    openmettle.quota_reservations,
    openmettle.quota_reservation_charges,
    openmettle.quota_reconciliations,
    openmettle.quota_warning_events
    FROM openmettle_gateway;

REVOKE EXECUTE ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid)
    FROM openmettle_gateway;
REVOKE EXECUTE ON FUNCTION openmettle.quota_settle_gateway_usage(uuid, uuid, uuid, bigint)
    FROM openmettle_gateway;
