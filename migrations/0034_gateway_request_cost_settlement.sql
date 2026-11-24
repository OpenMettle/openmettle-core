-- ADR 0044 / V1-06 / V1-17 (issue #166): settle `usage_cost_micros` holds on binding-free
-- proxy rounds from immutable profile pricing recorded on `gateway_requests` at handoff,
-- instead of requiring caller-supplied `cost` on `gateway_usage_reports`.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.

-- Unbound requests derive cost solely from the profile prices recorded at handoff; never allow
-- a caller or even `openmettle_owner` to supply `cost` or `unit` on an unbound usage report.
-- Bound ADR 0037 requests (`binding_id IS NOT NULL`) continue to accept `cost` and `unit`.
CREATE FUNCTION openmettle.enforce_gateway_report_bound_cost()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM openmettle.gateway_requests q
         WHERE q.id = NEW.request_id
           AND q.binding_id IS NULL
    ) THEN
        RAISE EXCEPTION 'unbound usage report cannot supply cost'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_report_bound_cost() FROM PUBLIC;

-- Acquire writer-excluding locks in runtime lock order (`gateway_requests` ->
-- `gateway_usage_reports` -> `gateway_settlements` -> `quota_reservations`), run the upgrade
-- preflight, add the recorded pricing columns and CHECK to `gateway_requests`, and attach the
-- unbound caller-cost guard inside a single `DO` block so locks are always held inside a
-- transaction block even when harness fixtures replay raw SQL files in autocommit mode.
DO $$
BEGIN
    LOCK TABLE openmettle.gateway_requests IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE openmettle.gateway_usage_reports IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE openmettle.gateway_settlements IN SHARE MODE;
    LOCK TABLE openmettle.quota_reservations IN SHARE MODE;

    -- Fail closed if any unbound request still carries an unsettled `usage_cost_micros` hold
    -- (whether `settled_final` is false, or true from a pre-34 report that left its cost hold
    -- in `handoff_committed`): pre-34 rows carry no recorded pricing. Already-settled or
    -- released historical rows stay untouched.
    IF EXISTS (
        SELECT 1
          FROM openmettle.gateway_requests q
          JOIN openmettle.quota_reservations qr
            ON qr.gateway_request_id = q.id
         WHERE q.binding_id IS NULL
           AND qr.resource_kind = 'usage_cost_micros'
           AND qr.state IN ('held', 'handoff_committed')
    ) THEN
        RAISE EXCEPTION 'migration 34 cannot proceed with an unsettled usage_cost_micros hold on an unbound request'
            USING ERRCODE = '23514';
    END IF;

    ALTER TABLE openmettle.gateway_requests
        ADD COLUMN cost_fixed_micros bigint,
        ADD COLUMN cost_micros_per_token bigint,
        ADD CONSTRAINT gateway_requests_cost_bound_check CHECK (
            (cost_fixed_micros IS NULL) = (cost_micros_per_token IS NULL)
            AND (cost_fixed_micros IS NULL OR (
                binding_id IS NULL
                AND state = 'handed_off'
                AND cost_fixed_micros >= 0
                AND cost_micros_per_token >= 0
                AND (cost_fixed_micros > 0 OR cost_micros_per_token > 0)
            ))
        );

    -- Named to sort before `gateway_usage_reports_cost_unit_guard` so unbound requests carrying
    -- `cost` fail immediately with `23514` without touching `quota_cost_unit_lock`. Rows with
    -- `incomplete IS NOT NULL` remain constrained by `gateway_usage_reports_incomplete_check`.
    CREATE TRIGGER gateway_usage_reports_bound_cost_guard
        BEFORE INSERT OR UPDATE ON openmettle.gateway_usage_reports
        FOR EACH ROW
        WHEN (NEW.incomplete IS NULL AND (NEW.cost IS NOT NULL OR NEW.unit IS NOT NULL))
        EXECUTE FUNCTION openmettle.enforce_gateway_report_bound_cost();
END
$$;

-- Record the immutable `Profile.cost_bound` (`cost_fixed_micros`, `cost_micros_per_token`)
-- alongside the binding-free round handoff. Preserves migration 29's exact lock order and
-- authority check.
CREATE FUNCTION openmettle.gateway_handoff_round(
    p_request uuid,
    p_dispatch bytea,
    p_lease uuid,
    p_bearer_hash bytea,
    p_cost_fixed_micros bigint,
    p_cost_micros_per_token bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    -- A snapshot taken before the locks could miss a committed revocation.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway handoff requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT pg_has_role(session_user, 'openmettle_worker', 'USAGE') THEN
        RETURN false;
    END IF;
    IF (p_cost_fixed_micros IS NULL) <> (p_cost_micros_per_token IS NULL)
       OR (p_cost_fixed_micros IS NOT NULL AND (
           p_cost_fixed_micros < 0
           OR p_cost_micros_per_token < 0
           OR (p_cost_fixed_micros = 0 AND p_cost_micros_per_token = 0)
       )) THEN
        RAISE EXCEPTION 'invalid gateway cost bound' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO req FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.run_id IS NOT NULL
        AND octet_length(p_dispatch)=32 AND q.dispatch_hash=sha256(p_dispatch) AND q.state='reserved'
        AND octet_length(p_bearer_hash)=32 AND p_bearer_hash<>q.dispatch_hash;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM FROM openmettle.account_admin_lock FOR SHARE;
    PERFORM FROM openmettle.projects p WHERE p.scope_id=req.scope_id FOR SHARE;
    PERFORM FROM openmettle.login_providers p JOIN openmettle.local_identity_approvals a ON a.provider_id=p.id
        WHERE a.id=req.approval_id FOR SHARE OF p,a;
    PERFORM FROM openmettle.users u WHERE u.id=req.actor_user_id FOR SHARE;
    PERFORM FROM openmettle.runs r WHERE r.id=req.run_id FOR SHARE;
    PERFORM FROM openmettle.gateway_reservations WHERE id=req.reservation_id FOR SHARE;
    PERFORM FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.state='reserved' FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF NOT openmettle.gateway_round_authority(p_request,p_lease,clock_timestamp()) THEN
        RETURN false;
    END IF;
    UPDATE openmettle.gateway_requests q SET state='handed_off',report_source=q.installation,
           bearer_hash=p_bearer_hash,claim_hash=sha256(uuid_send(p_lease)),
           cost_fixed_micros=p_cost_fixed_micros,cost_micros_per_token=p_cost_micros_per_token
     WHERE q.id=p_request AND q.state='reserved';
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_handoff_round(uuid,bytea,uuid,bytea,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_handoff_round(uuid,bytea,uuid,bytea,bigint,bigint) TO openmettle_worker;

-- Compatibility 4-arg wrapper for draining N-1 token-only workers and direct SQL tests.
-- Any cost-metered round calling this leaves recorded pricing NULL and is rejected at commit
-- by `enforce_gateway_handoff_holds()` with `OMQ04`.
CREATE OR REPLACE FUNCTION openmettle.gateway_handoff_round(
    p_request uuid,p_dispatch bytea,p_lease uuid,p_bearer_hash bytea)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    RETURN openmettle.gateway_handoff_round(p_request,p_dispatch,p_lease,p_bearer_hash,NULL,NULL);
END
$$;

-- Extend the deferred handoff check so every unbound round with a required or bound
-- `usage_cost_micros` hold records immutable `(cost_fixed_micros, cost_micros_per_token)`
-- whose exact ceiling (`units * cost_micros_per_token + cost_fixed_micros`) equals the bound
-- cost reservation's `reserved_units`. Preserves migration 26's lock order, signature,
-- security and privileges.
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

    IF NEW.run_id IS NOT NULL
       AND EXISTS (
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

    IF NEW.binding_id IS NULL
       AND (
           (v_enforced AND v_cost_required)
           OR EXISTS (
               SELECT 1
                 FROM openmettle.quota_reservations qr
                WHERE qr.gateway_request_id = NEW.id
                  AND qr.resource_kind = 'usage_cost_micros'
           )
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

-- Enforce the same recorded-pricing consistency check on lost-handoff recovery while
-- preserving historical pre-34 unbound rows whose `usage_cost_micros` hold is already settled.
-- Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.quota_recover_lost_handoff(
    p_id uuid,p_dispatch bytea,p_scope uuid,p_actor uuid,p_run uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q openmettle.gateway_requests%ROWTYPE; receipt openmettle.quota_gateway_handoffs%ROWTYPE;
BEGIN
    SELECT * INTO q FROM openmettle.gateway_requests WHERE id=p_id AND scope_id=p_scope AND actor_user_id=p_actor
        AND run_id IS NOT DISTINCT FROM p_run AND octet_length(p_dispatch)=32 AND dispatch_hash=sha256(p_dispatch)
        AND pg_has_role(session_user,CASE WHEN p_run IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END,'USAGE');
    IF NOT FOUND THEN RAISE EXCEPTION 'invalid recovery authority' USING ERRCODE='42501'; END IF;
    PERFORM FROM openmettle.runs WHERE id=p_run FOR NO KEY UPDATE;
    PERFORM FROM openmettle.gateway_reservations WHERE id=q.reservation_id FOR NO KEY UPDATE;
    SELECT * INTO STRICT q FROM openmettle.gateway_requests WHERE id=p_id FOR NO KEY UPDATE;
    IF q.state<>'handed_off' THEN
        PERFORM openmettle.quota_unwind_request(q.id);
        RETURN 'unwound_unsent';
    END IF;
    SELECT * INTO receipt FROM openmettle.quota_gateway_handoffs WHERE gateway_request_id=q.id;
    IF EXISTS (SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=q.id AND
        (h.state NOT IN ('handoff_committed','settled') OR (h.scope_id,h.actor_user_id,h.run_id) IS DISTINCT FROM
        (q.scope_id,q.actor_user_id,q.run_id) OR (h.resource_kind='usage_tokens' AND h.reserved_units<>q.units)
        OR (q.binding_id IS NULL AND h.resource_kind='usage_cost_micros' AND (
            (q.cost_fixed_micros IS NOT NULL
                AND h.reserved_units::numeric <> q.units::numeric * q.cost_micros_per_token + q.cost_fixed_micros)
            OR (q.cost_fixed_micros IS NULL AND h.state <> 'settled')))))
      OR (receipt.metering_enforced AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE gateway_request_id=q.id AND resource_kind='usage_tokens'))
      OR (receipt.metering_enforced AND receipt.cost_required AND NOT EXISTS (SELECT FROM openmettle.quota_reservations
        WHERE gateway_request_id=q.id AND resource_kind='usage_cost_micros')) THEN
        RAISE EXCEPTION 'gateway handoff invariant failed' USING ERRCODE='OMQ04';
    END IF;
    IF NOT EXISTS (SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=q.id) THEN
        RETURN 'unmetered_legacy_handoff';
    END IF;
    RETURN 'handoff_committed';
END
$$;

-- Derive `usage_cost_micros` settlement on priced unbound requests from reported token counts
-- and the immutable `(cost_fixed_micros, cost_micros_per_token)` recorded on `gateway_requests`.
-- Bound ADR 0037 rows and historical pre-34 rows without recorded prices retain `ceil(step.cost)`.
-- Incomplete and swept reports keep charging nothing of their own (`0`, not `cost_fixed_micros`).
-- Signature, volatility, search path and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.quota_gateway_fold(p_request uuid,p_kind text,p_units bigint,p_through bigint)
RETURNS TABLE(rev bigint,source uuid,report uuid,state text,settled numeric,held bigint)
LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE
    step record; prompt numeric:=0; completion numeric:=0; reasoning numeric:=0;
    included boolean:=true; separate_seen boolean:=false; last_k bigint:=-1; last_r bigint:=-1;
    v_priced boolean:=false; v_fixed bigint; v_rate bigint;
    tokens numeric; measured numeric; complete boolean;
BEGIN
    SELECT q.binding_id IS NULL AND q.cost_fixed_micros IS NOT NULL,
           q.cost_fixed_micros, q.cost_micros_per_token
      INTO v_priced, v_fixed, v_rate
      FROM openmettle.gateway_requests q
     WHERE q.id = p_request;
    v_priced := coalesce(v_priced, false);
    state:='handoff_committed'; settled:=0; held:=p_units;
    FOR step IN SELECT g.* FROM openmettle.quota_accepted_gateway_reports a
        JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
        WHERE a.request_id=p_request AND a.revision<=p_through ORDER BY a.revision
    LOOP
        rev:=step.revision; source:=step.source; report:=step.report_id;
        IF p_kind='usage_cost_micros' AND NOT v_priced THEN
            measured:=ceil(step.cost); complete:=step.cost IS NOT NULL;
        ELSE
            IF step.prompt_tokens IS NOT NULL THEN prompt:=step.prompt_tokens; END IF;
            IF step.completion_tokens IS NOT NULL THEN completion:=step.completion_tokens; last_k:=rev; END IF;
            IF step.reasoning_tokens IS NOT NULL THEN
                reasoning:=step.reasoning_tokens; included:=step.reasoning_included; last_r:=rev;
                separate_seen:=separate_seen OR NOT included;
            END IF;
            complete:=step.prompt_tokens IS NOT NULL AND step.completion_tokens IS NOT NULL
                AND (step.reasoning_tokens IS NOT NULL OR NOT separate_seen);
            tokens:=CASE WHEN num_nonnulls(step.prompt_tokens,step.completion_tokens,step.reasoning_tokens)=0 THEN NULL
                WHEN NOT included THEN prompt+completion+reasoning
                WHEN last_r>=last_k THEN prompt+greatest(reasoning,completion)
                ELSE prompt+completion END;
            IF p_kind='usage_cost_micros' THEN
                IF tokens IS NULL THEN
                    measured:=NULL;
                ELSE
                    measured:=tokens * v_rate::numeric + v_fixed::numeric;
                    IF measured >= 1e38::numeric THEN
                        RAISE EXCEPTION 'gateway cost measurement exceeds numeric(38, 0) bound'
                            USING ERRCODE = '23514';
                    END IF;
                END IF;
            ELSE
                measured:=tokens;
            END IF;
        END IF;
        IF step.incomplete IS NOT NULL THEN
            state:='settled'; held:=0;
        ELSIF measured IS NOT NULL THEN
            settled:=CASE WHEN complete THEN measured ELSE greatest(measured,settled) END;
            IF complete AND step.final THEN state:='settled'; END IF;
            held:=CASE WHEN state='settled' THEN 0 ELSE greatest(0,p_units-settled)::bigint END;
        END IF;
        RETURN NEXT;
    END LOOP;
END
$$;

-- Include unbound recorded-pricing consistency in `gateway_errors` while preserving already-
-- settled pre-34 unbound cost rows. Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.quota_verify_accounting_drift()
RETURNS TABLE(storage_mismatches bigint,budget_mismatches bigint,settlement_mismatches bigint,
              pending_gateway_reconciliations bigint,oldest_pending_age interval)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
    WITH storage AS (
        SELECT a.scope_id,a.active_bytes,a.retained_bytes,a.reserved_bytes,
            coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions
                WHERE scope_id=a.scope_id AND state='active'),0) AS active,
            coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions
                WHERE scope_id=a.scope_id AND state IN ('retained','purging')),0) AS retained,
            coalesce((SELECT sum(max_bytes) FROM openmettle.storage_reservations
                WHERE scope_id=a.scope_id AND state='reserved'),0) AS reserved FROM openmettle.storage_accounts a
    ), storage_errors AS (
        SELECT FROM storage WHERE (active_bytes,retained_bytes,reserved_bytes)<>(active,retained,reserved)
        UNION ALL SELECT FROM openmettle.storage_instance i WHERE
            (i.active_bytes,i.retained_bytes,i.reserved_bytes)<>(SELECT coalesce(sum(active),0),coalesce(sum(retained),0),
                coalesce(sum(reserved),0) FROM storage)
        UNION ALL SELECT FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr
            ON sr.scope_id=r.scope_id AND sr.id=r.reservation_id
            WHERE r.state IN ('active','retained','purging') AND sr.payload_ino IS NULL
            AND EXISTS (SELECT FROM openmettle.storage_volume_control WHERE id AND volume_id IS NOT NULL)
    ), applied AS (
        SELECT h.* FROM openmettle.quota_reservations h WHERE gateway_request_id IS NOT NULL
            AND state IN ('handoff_committed','settled')
    ), gateway_errors AS (
        SELECT FROM applied h LEFT JOIN LATERAL (SELECT * FROM openmettle.quota_gateway_fold(
            h.gateway_request_id,h.resource_kind,h.reserved_units,h.accepted_source_revision)
            ORDER BY rev DESC LIMIT 1) f ON true
            WHERE (h.state,h.settled_units,h.held_units) IS DISTINCT FROM
            (coalesce(f.state,'handoff_committed'),coalesce(f.settled,0),coalesce(f.held,h.reserved_units))
        UNION ALL SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id IS NOT NULL
            AND h.state='held' AND (h.accepted_source_revision IS NOT NULL OR h.settled_units<>0 OR h.held_units<>h.reserved_units)
        UNION ALL SELECT FROM openmettle.quota_gateway_handoffs receipt JOIN openmettle.gateway_requests q
            ON q.id=receipt.gateway_request_id WHERE q.state<>'handed_off'
            OR EXISTS (SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=q.id AND
                (h.state NOT IN ('handoff_committed','settled') OR (h.scope_id,h.actor_user_id,h.run_id) IS DISTINCT FROM
                (q.scope_id,q.actor_user_id,q.run_id) OR (h.resource_kind='usage_tokens' AND h.reserved_units<>q.units)
                OR (q.binding_id IS NULL AND h.resource_kind='usage_cost_micros' AND (
                    (q.cost_fixed_micros IS NOT NULL
                        AND h.reserved_units::numeric <> q.units::numeric * q.cost_micros_per_token + q.cost_fixed_micros)
                    OR (q.cost_fixed_micros IS NULL AND h.state <> 'settled')))))
            OR (receipt.metering_enforced AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                WHERE h.gateway_request_id=q.id AND h.resource_kind='usage_tokens'))
            OR (receipt.metering_enforced AND receipt.cost_required AND NOT EXISTS (SELECT FROM openmettle.quota_reservations h
                WHERE h.gateway_request_id=q.id AND h.resource_kind='usage_cost_micros'))
        UNION ALL SELECT FROM openmettle.gateway_settlements gs JOIN openmettle.gateway_usage_reports gr
            USING(request_id,revision,final) WHERE gs.measured IS DISTINCT FROM CASE
            WHEN num_nonnulls(gr.prompt_tokens,gr.completion_tokens,gr.reasoning_tokens)=0 THEN NULL
            ELSE coalesce(gr.prompt_tokens,0)::numeric+CASE WHEN gr.reasoning_included THEN
            greatest(coalesce(gr.completion_tokens,0),coalesce(gr.reasoning_tokens,0))::numeric
            ELSE coalesce(gr.completion_tokens,0)::numeric+coalesce(gr.reasoning_tokens,0) END END
    ), pending AS (
        SELECT h.id,min(a.accepted_at) AS oldest FROM applied h
        JOIN openmettle.quota_accepted_gateway_reports a ON a.request_id=h.gateway_request_id
            AND a.revision>coalesce(h.accepted_source_revision,-1) GROUP BY h.id
    )
    SELECT (SELECT count(*) FROM storage_errors),
        (SELECT count(*) FROM openmettle.quota_budgets b WHERE b.reserved_held<>(SELECT coalesce(sum(h.held_units),0)
             FROM openmettle.quota_reservation_charges c JOIN openmettle.quota_reservations h ON h.id=c.reservation_id
             WHERE c.budget_id=b.id AND h.state IN ('held','handoff_committed'))
         OR b.active_used<>(SELECT coalesce(sum(rec.delta_active),0) FROM openmettle.quota_reservation_charges c
             JOIN openmettle.quota_reconciliations rec USING(reservation_id) WHERE c.budget_id=b.id)),
        (SELECT count(*) FROM gateway_errors),(SELECT count(*) FROM pending),(SELECT now()-min(oldest) FROM pending)
$$;

-- Remove migration 31's `#166` carve-out: every final settlement on an unbound request must
-- close EVERY bound quota hold (`usage_tokens` AND `usage_cost_micros`, regardless of whether
-- any accepted report carries `incomplete`), and when recorded prices are present the
-- `usage_cost_micros` fold must also end `settled`. Signature, security and privileges are
-- unchanged.
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
BEGIN
    SELECT * INTO latest FROM openmettle.gateway_settlements s WHERE s.request_id=NEW.request_id;
    IF NOT FOUND OR NOT latest.final THEN RETURN NULL; END IF;
    SELECT * INTO STRICT req FROM openmettle.gateway_requests q WHERE q.id=latest.request_id;
    SELECT EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
         WHERE a.request_id=latest.request_id AND g.incomplete='not_dispatched'
    ), EXISTS (
        SELECT FROM openmettle.quota_accepted_gateway_reports a
          JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
         WHERE a.request_id=latest.request_id AND g.incomplete IS NOT NULL
           AND g.incomplete<>'not_dispatched'
    ) INTO has_not_dispatched, has_other_reason;
    IF has_not_dispatched AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NOT NULL
        OR latest.revision<>0 OR latest.measured IS NOT NULL
        OR EXISTS (SELECT FROM openmettle.quota_accepted_gateway_reports a
                    WHERE a.request_id=latest.request_id AND a.revision<>0)) THEN
        RAISE EXCEPTION 'a not_dispatched report needs an undispatched request without a binding'
            USING ERRCODE='23514';
    END IF;
    IF has_other_reason AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NULL) THEN
        RAISE EXCEPTION 'an incomplete report needs a dispatched request without a binding'
            USING ERRCODE='23514';
    END IF;
    IF req.binding_id IS NOT NULL THEN RETURN NULL; END IF;
    IF (TG_OP='INSERT' OR (NEW.revision,NEW.final) IS DISTINCT FROM (OLD.revision,OLD.final))
       AND EXISTS (
           SELECT FROM openmettle.quota_accepted_gateway_reports a
             JOIN openmettle.gateway_usage_reports g USING (request_id,revision,final)
            WHERE a.request_id=NEW.request_id AND a.revision=NEW.revision AND a.final
              AND g.incomplete IS NULL
              AND (g.prompt_tokens IS NULL OR g.completion_tokens IS NULL)
       ) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE='23514';
    END IF;
    SELECT f.state INTO folded
      FROM openmettle.quota_gateway_fold(latest.request_id,'usage_tokens',req.units,latest.revision) f
     ORDER BY f.rev DESC LIMIT 1;
    IF req.cost_fixed_micros IS NOT NULL THEN
        SELECT coalesce(
            (SELECT h.reserved_units
               FROM openmettle.quota_reservations h
              WHERE h.gateway_request_id = latest.request_id
                AND h.resource_kind = 'usage_cost_micros'),
            0
        ) INTO cost_units;
        SELECT f.state INTO cost_folded
          FROM openmettle.quota_gateway_fold(latest.request_id,'usage_cost_micros',cost_units,latest.revision) f
         ORDER BY f.rev DESC LIMIT 1;
        IF cost_folded IS DISTINCT FROM 'settled' THEN
            RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE='23514';
        END IF;
    END IF;
    IF latest.outstanding<>0 OR folded IS DISTINCT FROM 'settled' OR EXISTS (
        SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=latest.request_id
           AND (h.accepted_source_revision IS DISTINCT FROM latest.revision
                OR h.state<>'settled')) THEN
        RAISE EXCEPTION 'a final settlement must close its request' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END
$$;
