-- ADR 0044 / V1-06 / V1-17 (issue #166): settle `usage_cost_micros` holds on binding-free
-- proxy rounds from immutable profile pricing pinned at admission in `runs.config_snapshot`
-- and recorded on `gateway_requests` at handoff, instead of requiring caller-supplied `cost`
-- on `gateway_usage_reports`.
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

-- Internal: parse and validate the optional admission-pinned `cost_bound` object in raw UTF-8
-- `runs.config_snapshot` text BEFORE `jsonb` normalization (so exponent or signed-zero spellings
-- like `1e2` and `-0` that Rust `CostBound` rejects are rejected identically in SQL). Absent or
-- JSON `null` returns `(true, NULL, NULL)` (preserving pre-34 snapshots and profiles without a
-- qualified `cost_bound`). When present and non-null, requires a JSON object with unique keys
-- subset of `('fixed_micros', 'micros_per_token')`, `'micros_per_token'` present, canonical
-- unsigned base-10 integer tokens (`^(0|[1-9][0-9]*)$`) in `0..=9223372036854775807` (defaulting
-- `fixed_micros` to `0` when omitted), and at least one coefficient strictly positive. Any
-- malformed value returns `(false, NULL, NULL)`.
CREATE FUNCTION openmettle.gateway_snapshot_cost_bound(p_cfg_txt text)
RETURNS TABLE(valid boolean, fixed_micros bigint, micros_per_token bigint)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
    v_doc json;
    v_cfg jsonb;
    v_cb jsonb;
    v_cb_raw json;
    v_rate_tok text;
    v_fixed_tok text;
    v_fixed bigint;
    v_rate bigint;
BEGIN
    IF p_cfg_txt IS NULL OR p_cfg_txt IS NOT JSON OBJECT WITH UNIQUE KEYS THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    BEGIN
        v_doc := p_cfg_txt::json;
        v_cfg := p_cfg_txt::jsonb;
    EXCEPTION WHEN others THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END;
    IF NOT (v_cfg ? 'cost_bound') OR v_cfg -> 'cost_bound' = 'null'::jsonb THEN
        RETURN QUERY SELECT true, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    v_cb := v_cfg -> 'cost_bound';
    IF jsonb_typeof(v_cb) <> 'object' THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF NOT (v_cb ? 'micros_per_token') OR EXISTS (
        SELECT 1
          FROM jsonb_object_keys(v_cb) AS k(key)
         WHERE k.key NOT IN ('fixed_micros', 'micros_per_token')
    ) THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;

    v_cb_raw := v_doc -> 'cost_bound';
    IF json_typeof(v_cb_raw -> 'micros_per_token') IS DISTINCT FROM 'number' THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    v_rate_tok := pg_catalog.btrim((v_cb_raw -> 'micros_per_token')::text, E' \t\n\r');
    IF v_rate_tok IS NULL
       OR v_rate_tok COLLATE "C" !~ '^(0|[1-9][0-9]*)$'
       OR v_rate_tok::numeric > 9223372036854775807::numeric THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    v_rate := v_rate_tok::bigint;

    IF v_cb ? 'fixed_micros' THEN
        IF json_typeof(v_cb_raw -> 'fixed_micros') IS DISTINCT FROM 'number' THEN
            RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
            RETURN;
        END IF;
        v_fixed_tok := pg_catalog.btrim((v_cb_raw -> 'fixed_micros')::text, E' \t\n\r');
        IF v_fixed_tok IS NULL
           OR v_fixed_tok COLLATE "C" !~ '^(0|[1-9][0-9]*)$'
           OR v_fixed_tok::numeric > 9223372036854775807::numeric THEN
            RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
            RETURN;
        END IF;
        v_fixed := v_fixed_tok::bigint;
    ELSE
        v_fixed := 0;
    END IF;

    IF v_fixed = 0 AND v_rate = 0 THEN
        RETURN QUERY SELECT false, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    RETURN QUERY SELECT true, v_fixed, v_rate;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_snapshot_cost_bound(text) FROM PUBLIC;

-- Acquire all four writer-excluding table locks atomically via a bounded `NOWAIT` retry loop
-- (rolling back each failed subtransaction on `lock_not_available` so no partial table lock is
-- held across retries and concurrent schema-33 `INSERT INTO gateway_usage_reports` writers
-- cannot deadlock on the `gateway_usage_reports` -> `gateway_requests` FK lock order). Then run
-- the upgrade preflight, delete any unaccepted historical raw cost reports on unbound requests,
-- add the recorded pricing columns and CHECK to `gateway_requests`, attach the unbound
-- caller-cost guard, and widen `gateway_final_settlement_closes` to fire on both final and
-- non-final settlements — all inside one autocommit-safe `DO` block.
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
            LOCK TABLE openmettle.gateway_requests IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_usage_reports IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE openmettle.gateway_settlements IN ACCESS EXCLUSIVE MODE NOWAIT;
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

    -- Remove unaccepted historical raw usage reports carrying caller-supplied `cost`/`unit` on
    -- unbound requests so no post-34 settlement advance can accept them. Already-accepted
    -- historical revisions (referenced by `gateway_settlements` or
    -- `quota_accepted_gateway_reports`) stay intact for exact duplicate replay.
    DELETE FROM openmettle.gateway_usage_reports g
     USING openmettle.gateway_requests q
     WHERE g.request_id = q.id
       AND q.binding_id IS NULL
       AND (g.cost IS NOT NULL OR g.unit IS NOT NULL)
       AND NOT EXISTS (
           SELECT 1
             FROM openmettle.gateway_settlements s
            WHERE s.request_id = g.request_id
              AND s.revision = g.revision
       )
       AND NOT EXISTS (
           SELECT 1
             FROM openmettle.quota_accepted_gateway_reports a
            WHERE a.request_id = g.request_id
              AND a.revision = g.revision
       );

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

    -- Fire on BOTH final and non-final settlements so direct `openmettle_gateway` SQL cannot
    -- write non-final measured usage on an undispatched unbound request or accept a cost/unit
    -- report on an unbound request.
    DROP TRIGGER gateway_final_settlement_closes ON openmettle.gateway_settlements;
    CREATE CONSTRAINT TRIGGER gateway_final_settlement_closes
        AFTER INSERT OR UPDATE ON openmettle.gateway_settlements
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION openmettle.enforce_gateway_final_settlement_closes();
END
$$;

-- Extend migration 29's internal authority check so a malformed `cost_bound` in
-- `runs.config_snapshot` refuses the round. Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.gateway_round_authority(p_request uuid,p_lease uuid,p_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
    txt text;
    cfg jsonb;
    ms bigint := floor(extract(epoch FROM p_at)*1000)::bigint;
BEGIN
    SELECT * INTO req FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.run_id IS NOT NULL;
    IF NOT FOUND THEN RETURN false; END IF;
    BEGIN
        SELECT convert_from(r.config_snapshot,'UTF8') INTO txt FROM openmettle.runs r
         WHERE r.id=req.run_id AND r.snapshot_format='openmettle.conversation' AND r.snapshot_version=1;
        IF txt IS NULL OR txt IS NOT JSON OBJECT WITH UNIQUE KEYS THEN RETURN false; END IF;
        cfg := txt::jsonb;
    EXCEPTION WHEN others THEN
        RETURN false;
    END;
    IF jsonb_typeof(cfg #> '{effective,model}') IS DISTINCT FROM 'string'
       OR jsonb_typeof(cfg -> 'required_capabilities') IS DISTINCT FROM 'object' THEN
        RETURN false;
    END IF;
    -- The capability name rule of migration 15's tables: an invalid name matches no deny row.
    IF cfg #>> '{effective,model}' <> req.model OR EXISTS (
        SELECT FROM jsonb_each(cfg -> 'required_capabilities') cap
         WHERE cap.value NOT IN ('"on_by_default"'::jsonb,'"opt_in"'::jsonb)
            OR octet_length(cap.key) NOT BETWEEN 1 AND 128
            OR cap.key COLLATE "C" !~ '^[abcdefghijklmnopqrstuvwxyz0123456789._-]+$') THEN
        RETURN false;
    END IF;
    IF NOT (SELECT cb.valid FROM openmettle.gateway_snapshot_cost_bound(txt) cb) THEN
        RETURN false;
    END IF;

    RETURN EXISTS (
        WITH oidc_groups AS (
            SELECT v.claim_value FROM openmettle.membership_observations m
            JOIN openmettle.local_identity_approvals a ON a.id=m.approval_id AND a.id=req.approval_id
            JOIN openmettle.user_identities i ON i.id=a.identity_id AND i.user_id=req.actor_user_id
            JOIN openmettle.users u ON u.id=i.user_id
            JOIN openmettle.grant_mapping_rules mr ON mr.id=m.rule_id AND mr.last_revision=m.rule_revision
                AND mr.provider_config_id=a.provider_id AND mr.issuer=i.issuer
            JOIN openmettle.grant_mapping_revisions v ON v.rule_id=mr.id AND v.revision=m.rule_revision
            JOIN openmettle.grant_assignments mg ON mg.mapping_rule_id=mr.id AND mg.grantee_user_id=u.id
                AND mg.scope_id=m.scope_id AND mg.project_id=m.project_id AND mg.assignment_key=a.id::text
                AND mg.assignment_format='openmettle.project-member' AND mg.assignment_version=1
            JOIN openmettle.grant_changes mh ON mh.assignment_id=mg.id AND mh.revision=mg.last_revision
            WHERE m.enabled AND v.enabled AND v.selector_kind='group'
              AND v.binding_format='openmettle.project-member' AND v.binding_version=1
              AND v.binding=convert_to(m.project_id::text,'UTF8')
              AND m.epoch=(SELECT max(pr.epoch) FROM openmettle.login_provider_revisions pr WHERE pr.provider_id=a.provider_id)
              AND m.approval_generation=a.access_generation AND m.user_generation=u.session_generation
              AND (m.observation).state='present' AND mh.id=(m.observation).change_id
              AND mh.decision='grant' AND mh.cycle_id=mh.id AND mh.mapping_revision=m.rule_revision
              AND m.issued_ms<=ms AND least(m.expires_ms,m.issued_ms+1000::bigint*m.max_age_seconds)>ms
        ), actor_grants AS (
            SELECT g.* FROM openmettle.grant_assignments g
            JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
            WHERE g.scope_id=req.scope_id AND h.decision='grant' AND g.assignment_version=1 AND g.source_kind='direct'
              AND (g.grantee_user_id=req.actor_user_id OR g.grantee_kind='project'
                   OR g.grantee_oidc_group_id IN (SELECT claim_value FROM oidc_groups)
                   OR EXISTS (SELECT FROM openmettle.local_groups lg JOIN openmettle.local_group_memberships lm ON lm.group_id=lg.id
                              WHERE lg.id=g.grantee_local_group_id AND lg.disabled_at IS NULL AND lm.active AND lm.user_id=req.actor_user_id))
        ), project_roles AS (
            SELECT g.* FROM actor_grants g WHERE g.target_kind='project' AND g.assignment_format='openmettle.project-role'
              AND g.assignment_key IN ('viewer','editor','owner') AND g.grantee_kind<>'project'
        )
        SELECT FROM openmettle.local_identity_approvals a
        JOIN openmettle.user_identities i ON i.id=a.identity_id AND i.user_id=req.actor_user_id
        JOIN openmettle.users u ON u.id=i.user_id AND u.disabled_at IS NULL
        JOIN openmettle.login_providers p ON p.id=a.provider_id AND p.issuer=i.issuer
        JOIN LATERAL (SELECT v.revision,v.epoch FROM openmettle.login_provider_revisions v
                      WHERE v.provider_id=p.id ORDER BY v.epoch DESC LIMIT 1) current ON current.revision IS NOT NULL
        JOIN openmettle.scopes sc ON sc.id=req.scope_id
        JOIN openmettle.runs r ON r.id=req.run_id AND r.actor_approval_id=a.id AND r.actor_user_id=u.id
            AND r.scope_id=sc.id
        WHERE a.id=req.approval_id AND a.active AND a.expires_ms>ms
          AND r.claim_token=p_lease AND r.state='running' AND r.cancel_reason IS NULL
          AND r.lease_expires_at>p_at AND r.execution_expires_at>p_at AND req.round<=r.round_limit
          AND NOT EXISTS (SELECT FROM jsonb_each(cfg -> 'required_capabilities') cap
              LEFT JOIN openmettle.platform_capability_denies pd ON pd.capability=cap.key
              LEFT JOIN openmettle.user_capability_denies ud ON ud.user_id=u.id AND ud.capability=cap.key
              LEFT JOIN openmettle.user_capability_grants ug ON ug.user_id=u.id AND ug.capability=cap.key
              WHERE pd.denied OR ud.denied OR (cap.value='"opt_in"'::jsonb AND NOT coalesce(ug.granted,false)))
          AND (sc.personal_user_id=u.id OR EXISTS (
              SELECT FROM project_roles g
              LEFT JOIN openmettle.project_settings ps ON ps.project_id=g.target_id
              WHERE g.target_id=sc.project_id
                AND ps.archived_at IS NULL AND ps.deleted_at IS NULL
                AND g.assignment_key IN ('editor','owner')
                AND EXISTS (
                    SELECT FROM openmettle.conversations c
                    WHERE c.id=r.conversation_id AND (c.owner_user_id=u.id OR EXISTS (
                        SELECT FROM actor_grants share WHERE share.target_kind='conversation' AND share.target_id=c.id
                          AND share.assignment_format='openmettle.resource-grant' AND share.assignment_key='write'
                          AND (share.grantee_kind IN ('user','project') OR EXISTS (
                              SELECT FROM project_roles member WHERE member.grantee_local_group_id=share.grantee_local_group_id
                                  OR member.grantee_oidc_group_id=share.grantee_oidc_group_id))))))));
END
$$;

-- Record the immutable `Profile.cost_bound` (`cost_fixed_micros`, `cost_micros_per_token`)
-- alongside the binding-free round handoff, validating both coefficients individually against
-- the locked run's admission `config_snapshot` (which `openmettle_worker` cannot write).
-- Preserves migration 29's exact lock order and authority check.
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
    txt text;
    snap record;
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
    SELECT convert_from(r.config_snapshot, 'UTF8') INTO txt
      FROM openmettle.runs r
     WHERE r.id = req.run_id
       AND r.snapshot_format = 'openmettle.conversation'
       AND r.snapshot_version = 1;
    SELECT * INTO snap FROM openmettle.gateway_snapshot_cost_bound(txt);
    IF NOT snap.valid
       OR (p_cost_fixed_micros, p_cost_micros_per_token)
          IS DISTINCT FROM (snap.fixed_micros, snap.micros_per_token) THEN
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
-- Any cost-metered round (or run whose snapshot pins `cost_bound`) calling this leaves recorded
-- pricing NULL and is rejected by 6-arg `gateway_handoff_round` (returning `false`) or by
-- `enforce_gateway_handoff_holds()` (`OMQ04`).
CREATE OR REPLACE FUNCTION openmettle.gateway_handoff_round(
    p_request uuid,p_dispatch bytea,p_lease uuid,p_bearer_hash bytea)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    RETURN openmettle.gateway_handoff_round(p_request,p_dispatch,p_lease,p_bearer_hash,NULL,NULL);
END
$$;

-- Extend the deferred handoff check so every unbound round matches its admission-pinned
-- `runs.config_snapshot.cost_bound` individually on `(cost_fixed_micros, cost_micros_per_token)`,
-- and every unbound round with a required or bound `usage_cost_micros` hold records non-null
-- immutable pricing whose exact ceiling (`units * cost_micros_per_token + cost_fixed_micros`)
-- equals the bound cost reservation's `reserved_units`. Preserves migration 26's lock order,
-- signature, security and privileges.
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

    IF NEW.binding_id IS NULL THEN
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
-- Bound ADR 0037 rows and historical pre-34 rows without recorded prices retain `ceil(step.cost)`
-- and migration 31's exact transition rule (preserving already-accepted schema-33 `unreported` +
-- token-report histories with zero drift), while `enforce_gateway_final_settlement_closes()`
-- requires recorded pricing before accepting any new count-bearing report on a cost-held unbound
-- request. Incomplete and swept reports keep charging nothing of their own (`0`, not
-- `cost_fixed_micros`). Signature, volatility, search path and privileges are unchanged.
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

-- Owner-only administrative reconciliation for a pre-34 unbound request whose `usage_cost_micros`
-- hold was closed at `0` without caller-supplied `cost` (e.g. by a schema-33 `unreported` sweep,
-- with or without a pre-upgrade token-only correction). Verifies `openmettle_owner`, valid
-- positive pricing, snapshot agreement when pinned, exact match against the request's
-- `usage_cost_micros` reservation ceiling, zero settled cost, and absence of any caller-priced
-- report (`cost` or `unit`), then stamps `(cost_fixed_micros, cost_micros_per_token)` and
-- reconciles any already-accepted token-only usage against the cost hold and budgets.
CREATE FUNCTION openmettle.gateway_backfill_legacy_request_cost_bound(
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
       AND qr.binding_id IS NULL
       AND qr.state = 'handed_off'
       AND qr.cost_fixed_micros IS NULL
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'legacy request is not eligible for cost_bound backfill'
            USING ERRCODE = '23514';
    END IF;
    IF q.run_id IS NOT NULL THEN
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
    END IF;
    SELECT * INTO h
      FROM openmettle.quota_reservations qr
     WHERE qr.gateway_request_id = q.id
       AND qr.resource_kind = 'usage_cost_micros'
       AND qr.state = 'settled'
       AND qr.settled_units = 0
       AND qr.held_units = 0
       AND qr.reserved_units::numeric
           = q.units::numeric * p_cost_micros_per_token + p_cost_fixed_micros
       FOR NO KEY UPDATE;
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
    IF h.accepted_source_revision IS NOT NULL THEN
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
END;
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_backfill_legacy_request_cost_bound(uuid,bigint,bigint) FROM PUBLIC;

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

-- Enforce settlement invariants at commit for BOTH final and non-final rows on
-- `gateway_settlements`:
--   * No newly written/advanced settlement (final or non-final) may settle an undispatched
--     unbound request except as the revision-0 `not_dispatched` sweep closure.
--   * No newly written/advanced unbound settlement (final or non-final) may accept a usage
--     report carrying caller-supplied `cost` or `unit`.
--   * Removing migration 31's `#166` carve-out, every final settlement on an unbound request
--     must close EVERY bound quota hold (`usage_tokens` AND `usage_cost_micros`), running the
--     `usage_cost_micros` fold iff a `usage_cost_micros` hold exists on the request (so large
--     unused `cost_bound` values never break token-only settlement, while unpriced legacy
--     `unreported`-swept cost holds still fail closed on late token reports until backfilled).
-- Signature, security and privileges are unchanged.
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
    IF has_not_dispatched AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NOT NULL
        OR latest.revision <> 0 OR latest.measured IS NOT NULL
        OR EXISTS (SELECT FROM openmettle.quota_accepted_gateway_reports a
                    WHERE a.request_id = latest.request_id AND a.revision <> 0)) THEN
        RAISE EXCEPTION 'a not_dispatched report needs an undispatched request without a binding'
            USING ERRCODE = '23514';
    END IF;
    IF has_other_reason AND (req.binding_id IS NOT NULL OR req.dispatched_at IS NULL) THEN
        RAISE EXCEPTION 'an incomplete report needs a dispatched request without a binding'
            USING ERRCODE = '23514';
    END IF;

    IF req.binding_id IS NULL AND req.dispatched_at IS NULL AND advanced THEN
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

    IF req.binding_id IS NULL AND advanced AND EXISTS (
        SELECT 1
          FROM openmettle.gateway_usage_reports g
         WHERE g.request_id = NEW.request_id
           AND g.revision = NEW.revision
           AND (g.cost IS NOT NULL OR g.unit IS NOT NULL)
    ) THEN
        RAISE EXCEPTION 'unbound usage report cannot supply cost'
            USING ERRCODE = '23514';
    END IF;

    IF req.binding_id IS NULL
       AND advanced
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
    IF req.binding_id IS NOT NULL THEN RETURN NULL; END IF;

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
