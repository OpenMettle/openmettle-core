-- ADR 0044: OpenMettle's own proxy replaces the provisioned third-party gateway. A run round is
-- handed off without a gateway binding, generation or policy row, and the proxy consumes the
-- round's dispatch exactly once. Everything ADR 0037 provisioned stays in place, unused.

-- Migration 23 left the handoff CHECK unnamed. Find it by the columns it constrains.
DO $$
DECLARE
    names text[];
BEGIN
    SELECT pg_catalog.array_agg(c.conname::text) INTO names
      FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'openmettle.gateway_requests'::pg_catalog.regclass AND c.contype = 'c'
       AND (SELECT pg_catalog.array_agg(a.attname::text ORDER BY a.attname::text COLLATE "C")
              FROM pg_catalog.pg_attribute a
             WHERE a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey))
           = ARRAY['binding_id','generation','policy_revision','report_source','state'];
    IF coalesce(pg_catalog.cardinality(names), 0) <> 1 THEN
        RAISE EXCEPTION 'expected one gateway_requests handoff CHECK, found %',
            coalesce(pg_catalog.cardinality(names), 0);
    END IF;
    EXECUTE pg_catalog.format('ALTER TABLE openmettle.gateway_requests DROP CONSTRAINT %I', names[1]);
END
$$;

-- A handed-off request names its report source. The binding columns are set together, and only
-- by the ADR 0037 handoff. A request handed off without a binding belongs to a run, reports
-- under its installation, and carries two digests the handoff wrote:
--   * `bearer_hash`, the SHA-256 of the bearer the worker will present to the proxy. The bearer
--     is a second random value, independent of the dispatch secret, and never reaches the
--     database. The dispatch secret stays the reserving caller's proof to the database and is
--     never a bearer: the two hashes must differ;
--   * `claim_hash`, the SHA-256 of the run claim that authorized the handoff, so a later holder
--     of the run cannot make this request dispatchable. The claim token itself is not stored:
--     the gateway role can read this table.
-- `dispatched_at` records the one dispatch the proxy allowed; it is not a state, because
-- settlement and the quota functions test `state = 'handed_off'`.
ALTER TABLE openmettle.gateway_requests
    ADD COLUMN dispatched_at timestamptz,
    ADD COLUMN bearer_hash bytea,
    ADD COLUMN claim_hash bytea,
    ADD CONSTRAINT gateway_requests_handoff_check CHECK (
        (binding_id IS NULL) = (generation IS NULL) AND (generation IS NULL) = (policy_revision IS NULL)
        AND (binding_id IS NULL OR state = 'handed_off')
        AND (state = 'handed_off') = (report_source IS NOT NULL)
        AND (binding_id IS NOT NULL OR state <> 'handed_off'
             OR (run_id IS NOT NULL AND report_source = installation))
        AND (bearer_hash IS NOT NULL) = (state = 'handed_off' AND binding_id IS NULL)
        AND (claim_hash IS NOT NULL) = (bearer_hash IS NOT NULL)
        AND (bearer_hash IS NULL OR (octet_length(bearer_hash) = 32 AND octet_length(claim_hash) = 32
                                     AND bearer_hash <> dispatch_hash))
        AND (dispatched_at IS NULL OR state = 'handed_off'));

-- Internal: whether run round `p_request` is authorized at `p_at` under run lease `p_lease`.
-- These are `gateway_handoff`'s checks of the lease, cancellation, round limit, user, approval,
-- provider revision, capabilities, project and conversation, with these differences:
--   * the approval is the root of the check, where a generation and its policy row were;
--   * the model and the required capabilities come from the run's admission snapshot. It must
--     be an `openmettle.conversation` version 1 document without a repeated key at any depth
--     (jsonb would keep only the last one), with a string model and valid capability names and
--     gates. Anything else refuses;
--   * the project role is read live, where the policy pinned a grant cycle.
-- It takes no lock and writes nothing, so it cannot wait.
CREATE FUNCTION openmettle.gateway_round_authority(p_request uuid,p_lease uuid,p_at timestamptz)
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
REVOKE ALL ON FUNCTION openmettle.gateway_round_authority(uuid,uuid,timestamptz) FROM PUBLIC;

-- `gateway_handoff` for a run round, without a binding: the holder of the round's dispatch
-- secret and of the run's lease marks it handed off, reporting under the request's installation,
-- with the binding columns left null. It stores the hash of the bearer the worker chose and of
-- the claim it holds; the bearer itself is never sent here.
-- Lock order: `gateway_handoff`'s, without the session and binding locks it no longer needs:
-- account_admin_lock, project, provider and approval, user, run, reservation, request. Removing
-- locks from an order cannot invert it. The authority is read after the last lock.
-- The caller's transaction must end with `gateway_handoff_round_confirm`.
CREATE FUNCTION openmettle.gateway_handoff_round(
    p_request uuid,p_dispatch bytea,p_lease uuid,p_bearer_hash bytea)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    -- A snapshot taken before the locks could miss a committed revocation.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway handoff requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    SELECT * INTO req FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.run_id IS NOT NULL
        AND octet_length(p_dispatch)=32 AND q.dispatch_hash=sha256(p_dispatch) AND q.state='reserved'
        AND octet_length(p_bearer_hash)=32 AND p_bearer_hash<>q.dispatch_hash
        AND pg_has_role(session_user,'openmettle_worker','USAGE');
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
           bearer_hash=p_bearer_hash,claim_hash=sha256(uuid_send(p_lease))
     WHERE q.id=p_request AND q.state='reserved';
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_handoff_round(uuid,bytea,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_handoff_round(uuid,bytea,uuid,bytea) TO openmettle_worker;

-- The last statement of a handoff transaction, after the quota commit. The quota commit and
-- the deferred handoff trigger can wait on quota locks, and an approval, a lease or a membership
-- observation can lapse during that wait. So every deferred check runs here first, and only
-- then is the authority read again on a new clock reading. That read takes no lock, and COMMIT
-- then has no deferred work left: nothing that can wait on a lock follows the last time check.
-- A round that lost its authority aborts the transaction with 42501.
CREATE FUNCTION openmettle.gateway_handoff_round_confirm(p_request uuid,p_dispatch bytea,p_lease uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway handoff requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.run_id IS NOT NULL
        AND octet_length(p_dispatch)=32 AND q.dispatch_hash=sha256(p_dispatch) AND q.state='handed_off'
        AND q.binding_id IS NULL AND q.dispatched_at IS NULL
        AND pg_has_role(session_user,'openmettle_worker','USAGE');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invalid turn handoff' USING ERRCODE = '42501';
    END IF;
    SET CONSTRAINTS ALL IMMEDIATE;
    IF NOT openmettle.gateway_round_authority(p_request,p_lease,clock_timestamp()) THEN
        RAISE EXCEPTION 'gateway handoff is no longer authorized' USING ERRCODE = '42501';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_handoff_round_confirm(uuid,bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_handoff_round_confirm(uuid,bytea,uuid) TO openmettle_worker;

-- The proxy presents the SHA-256 of the bearer its caller sent, never the bearer: a server that
-- logs statement parameters then records nothing a caller could present. The dispatch secret
-- is not a bearer: its hash matches no `bearer_hash`. The first call for a request handed off
-- without a binding, not yet settled, whose run is running, not cancelled, still held under the
-- claim that authorized the handoff and inside its lease and execution deadlines, consumes the
-- one dispatch and returns the stored routing fields. A later call with the same hash reports
-- a replay. Every other call returns no row, whether or not the request exists. A request
-- handed off under ADR 0037 has no bearer hash and is never dispatched here: its transport may
-- already have sent it.
-- The function locks only the request row, which is also settlement's first lock, and it waits
-- for that lock before deciding: a dispatch, settlement or cancellation that committed during
-- the wait is seen. The clock is read once, inside the updating statement, which by then holds
-- its relation locks: that reading is compared with the deadlines and stored. The function
-- does not write `state`, so the deferred handoff trigger does not fire.
CREATE FUNCTION openmettle.gateway_dispatch(p_request uuid,p_bearer_hash bytea)
RETURNS TABLE (replayed boolean,installation text,scope text,source text,principal text,model text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway dispatch requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.gateway_requests q WHERE q.id=p_request
        AND q.bearer_hash=p_bearer_hash AND q.state='handed_off'
        AND pg_has_role(session_user,'openmettle_gateway','USAGE') FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    RETURN QUERY
    WITH clock AS MATERIALIZED (SELECT clock_timestamp() AS t)
    UPDATE openmettle.gateway_requests q SET dispatched_at=clock.t
      FROM clock
     WHERE q.id=p_request AND q.bearer_hash=p_bearer_hash AND q.state='handed_off'
       AND q.dispatched_at IS NULL
       AND NOT EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id=q.id)
       AND EXISTS (SELECT FROM openmettle.runs r
            WHERE r.id=q.run_id AND r.state='running' AND r.cancel_reason IS NULL
              AND sha256(uuid_send(r.claim_token))=q.claim_hash
              AND r.lease_expires_at>clock.t AND r.execution_expires_at>clock.t)
    RETURNING false,q.installation::text,q.scope_id::text,q.report_source::text,
              q.actor_user_id::text,q.model;
    IF FOUND THEN RETURN; END IF;
    RETURN QUERY SELECT true,NULL::text,NULL::text,NULL::text,NULL::text,NULL::text
      FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.bearer_hash=p_bearer_hash
       AND q.dispatched_at IS NOT NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_dispatch(uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_dispatch(uuid,bytea) TO openmettle_gateway;
