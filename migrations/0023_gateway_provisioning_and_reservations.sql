-- ADR 0037 PR2. No previous writer needs a gateway row.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openmettle_gateway'
        AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
        RAISE EXCEPTION 'provision a restricted openmettle_gateway role before migration 23';
    END IF;
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO openmettle_gateway', pg_catalog.current_database());
END
$$;
GRANT USAGE ON SCHEMA openmettle TO openmettle_gateway;

CREATE TABLE openmettle.gateway_bindings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    installation uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES openmettle.users,
    principal uuid NOT NULL,
    budget uuid NOT NULL,
    desired_revision bigint NOT NULL DEFAULT 1 CHECK (desired_revision > 0),
    observed_revision bigint CHECK (observed_revision BETWEEN 1 AND desired_revision),
    state text NOT NULL DEFAULT 'provisioning' CHECK (state IN ('provisioning','ready','suspended','revoked')),
    active_generation bigint CHECK (active_generation > 0),
    CHECK (state <> 'ready' OR (active_generation IS NOT NULL AND observed_revision IS NOT NULL
                                AND observed_revision = desired_revision)),
    UNIQUE (installation,user_id), UNIQUE (installation,principal), UNIQUE (installation,budget),
    UNIQUE (id,user_id)
);
CREATE TABLE openmettle.gateway_nonces (
    key_fingerprint bytea NOT NULL CHECK (octet_length(key_fingerprint) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    PRIMARY KEY (key_fingerprint,nonce)
);
CREATE TABLE openmettle.gateway_generations (
    binding_id uuid NOT NULL REFERENCES openmettle.gateway_bindings,
    generation bigint NOT NULL CHECK (generation > 0),
    remote_key uuid NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    format smallint NOT NULL DEFAULT 1 CHECK (format = 1),
    key_id text NOT NULL CHECK (key_id COLLATE "C" ~ '^[a-zA-Z0-9_-]{1,64}$'),
    key_fingerprint bytea NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 4112),
    FOREIGN KEY (key_fingerprint,nonce) REFERENCES openmettle.gateway_nonces,
    UNIQUE (key_fingerprint,nonce),
    PRIMARY KEY (binding_id,generation)
);
ALTER TABLE openmettle.gateway_bindings ADD FOREIGN KEY (id,active_generation)
    REFERENCES openmettle.gateway_generations (binding_id,generation);

-- Confirmed policy for one identity, scope and model. The gateway writer pins the
-- current project grant cycle, and the required catalog capabilities (true = opt-in).
CREATE TABLE openmettle.gateway_policy (
    binding_id uuid NOT NULL REFERENCES openmettle.gateway_bindings,
    revision bigint NOT NULL CHECK (revision > 0),
    scope_id uuid NOT NULL REFERENCES openmettle.scopes,
    approval_id uuid NOT NULL REFERENCES openmettle.local_identity_approvals,
    model text NOT NULL CHECK (octet_length(model) BETWEEN 1 AND 128),
    report_source uuid NOT NULL,
    provider_generation bigint NOT NULL CHECK (provider_generation >= 0),
    approval_generation bigint NOT NULL CHECK (approval_generation >= 0),
    user_generation bigint NOT NULL CHECK (user_generation >= 0),
    grant_cycle uuid REFERENCES openmettle.grant_changes,
    capabilities jsonb NOT NULL CHECK (jsonb_typeof(capabilities) = 'object'
        AND octet_length(capabilities::text) <= 8192
        AND NOT jsonb_path_exists(capabilities,'$.keyvalue() ? (@.value.type() != "boolean" || !(@.key like_regex "^[a-z0-9_.-]{1,128}$"))')),
    PRIMARY KEY (binding_id,revision,scope_id,approval_id,model)
);
CREATE TABLE openmettle.gateway_intents (
    operation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    binding_id uuid NOT NULL REFERENCES openmettle.gateway_bindings,
    desired_revision bigint NOT NULL CHECK (desired_revision > 0),
    generation bigint NOT NULL CHECK (generation >= 0),
    action text NOT NULL CHECK (action IN ('principal','budget','attach','policy','issue','renew','rotate','suspend','revoke')),
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    parameters jsonb NOT NULL CHECK (jsonb_typeof(parameters) = 'object' AND octet_length(parameters::text) <= 8192),
    -- While claimed, due_at is the lease expiry and a later sweep may reclaim the intent.
    claim uuid,
    due_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(due_at)),
    complete boolean NOT NULL DEFAULT false,
    CHECK (NOT complete OR claim IS NULL),
    UNIQUE (binding_id,desired_revision,generation,action),
    UNIQUE (binding_id,desired_revision,operation_id)
);
CREATE INDEX gateway_intents_due_idx ON openmettle.gateway_intents (due_at,operation_id) WHERE NOT complete;
CREATE TABLE openmettle.gateway_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    binding_id uuid NOT NULL,
    desired_revision bigint NOT NULL,
    operation_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    step text NOT NULL CHECK (step IN ('readiness','principal','budget','policy','key','revoke','usage')),
    outcome text NOT NULL CHECK (outcome IN ('confirmed','deferred','refused','uncertain')),
    remote_handle uuid,
    remote_revision bigint CHECK (remote_revision >= 0),
    FOREIGN KEY (binding_id,desired_revision,operation_id)
        REFERENCES openmettle.gateway_intents (binding_id,desired_revision,operation_id)
);
CREATE INDEX gateway_audit_operation_idx ON openmettle.gateway_audit (operation_id,recorded_at);

-- A run owns one admission hold. Allocation to a round moves units out of
-- unallocated, so the run and its rounds never count the same units twice.
CREATE TABLE openmettle.gateway_reservations (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES openmettle.scopes,
    actor_user_id uuid NOT NULL REFERENCES openmettle.users,
    approval_id uuid NOT NULL REFERENCES openmettle.local_identity_approvals,
    run_id uuid UNIQUE,
    run_owned boolean GENERATED ALWAYS AS (run_id IS NOT NULL) STORED,
    units bigint NOT NULL CHECK (units > 0),
    allocated bigint NOT NULL DEFAULT 0 CHECK (allocated BETWEEN 0 AND units),
    FOREIGN KEY (scope_id,run_id,actor_user_id) REFERENCES openmettle.runs (scope_id,id,actor_user_id),
    UNIQUE (id,scope_id,actor_user_id,approval_id,run_owned),
    UNIQUE (scope_id,id),
    UNIQUE (id,run_id)
);
CREATE TABLE openmettle.gateway_requests (
    id uuid PRIMARY KEY,
    reservation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    approval_id uuid NOT NULL,
    run_id uuid,
    run_owned boolean GENERATED ALWAYS AS (run_id IS NOT NULL) STORED,
    round integer CHECK (round BETWEEN 1 AND 1000),
    session_id text CHECK (session_id COLLATE "C" ~ '^[a-zA-Z0-9_-]{43}$'),
    installation uuid NOT NULL,
    model text NOT NULL CHECK (octet_length(model) BETWEEN 1 AND 128),
    units bigint NOT NULL CHECK (units > 0),
    dispatch_hash bytea NOT NULL CHECK (octet_length(dispatch_hash) = 32),
    state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','released','handed_off')),
    settled_final boolean NOT NULL DEFAULT false CHECK (NOT settled_final OR state = 'handed_off'),
    binding_id uuid,
    generation bigint,
    policy_revision bigint,
    report_source uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((run_id IS NULL) = (session_id IS NOT NULL) AND (run_id IS NULL) = (round IS NULL)),
    CHECK ((state = 'handed_off') = (binding_id IS NOT NULL) AND (binding_id IS NULL) = (generation IS NULL)
           AND (generation IS NULL) = (policy_revision IS NULL) AND (generation IS NULL) = (report_source IS NULL)),
    FOREIGN KEY (reservation_id,scope_id,actor_user_id,approval_id,run_owned)
        REFERENCES openmettle.gateway_reservations (id,scope_id,actor_user_id,approval_id,run_owned),
    FOREIGN KEY (reservation_id,run_id) REFERENCES openmettle.gateway_reservations (id,run_id),
    FOREIGN KEY (binding_id,generation) REFERENCES openmettle.gateway_generations,
    FOREIGN KEY (binding_id,actor_user_id) REFERENCES openmettle.gateway_bindings (id,user_id),
    FOREIGN KEY (binding_id,policy_revision,scope_id,approval_id,model) REFERENCES openmettle.gateway_policy,
    UNIQUE (id,report_source),
    UNIQUE (scope_id,id)
);
CREATE UNIQUE INDEX gateway_requests_caller_reservation_idx
    ON openmettle.gateway_requests (reservation_id) WHERE run_id IS NULL;
CREATE UNIQUE INDEX gateway_requests_run_round_active_idx
    ON openmettle.gateway_requests (reservation_id,round) WHERE run_id IS NOT NULL AND state <> 'released';
CREATE INDEX gateway_requests_reserved_idx
    ON openmettle.gateway_requests (created_at,id) WHERE state = 'reserved';
CREATE INDEX gateway_requests_outstanding_idx
    ON openmettle.gateway_requests (created_at,id) WHERE state = 'handed_off' AND NOT settled_final;
CREATE TABLE openmettle.gateway_usage_reports (
    request_id uuid NOT NULL,
    source uuid NOT NULL,
    report_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 0),
    final boolean NOT NULL,
    prompt_tokens bigint CHECK (prompt_tokens >= 0),
    completion_tokens bigint CHECK (completion_tokens >= 0),
    reasoning_tokens bigint CHECK (reasoning_tokens >= 0),
    reasoning_included boolean,
    cost numeric CHECK (cost >= 0 AND cost < 1e18 AND scale(cost) <= 12),
    unit text CHECK (octet_length(unit) BETWEEN 1 AND 32),
    CHECK ((cost IS NULL) = (unit IS NULL)),
    CHECK (reasoning_tokens IS NULL OR reasoning_included IS NOT NULL),
    FOREIGN KEY (request_id,source) REFERENCES openmettle.gateway_requests (id,report_source),
    PRIMARY KEY (source,report_id,revision), UNIQUE (request_id,revision),
    UNIQUE (request_id,revision,final)
);
CREATE TABLE openmettle.gateway_settlements (
    request_id uuid PRIMARY KEY,
    revision bigint NOT NULL,
    final boolean NOT NULL,
    measured bigint CHECK (measured >= 0),
    outstanding bigint NOT NULL CHECK (outstanding >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (request_id,revision,final) REFERENCES openmettle.gateway_usage_reports (request_id,revision,final)
);
CREATE INDEX gateway_settlements_nonfinal_idx
    ON openmettle.gateway_settlements (updated_at,request_id) WHERE NOT final;

-- Exact replays preserve the scan position. Corrections require a newer report,
-- and only another final report can correct a final settlement.
CREATE FUNCTION openmettle.gateway_advance_settlement() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        IF NEW.revision <= OLD.revision OR (OLD.final AND NOT NEW.final) THEN
            RAISE EXCEPTION 'invalid gateway settlement revision or finality' USING ERRCODE='23514';
        END IF;
        NEW.updated_at := clock_timestamp();
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_advance_settlement() FROM PUBLIC;
CREATE TRIGGER gateway_advance_settlement BEFORE UPDATE ON openmettle.gateway_settlements
    FOR EACH ROW EXECUTE FUNCTION openmettle.gateway_advance_settlement();

-- AFTER fires only for an accepted settlement, including an upsert. No runtime
-- login can write the request marker directly.
CREATE FUNCTION openmettle.gateway_mark_settled_final() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    UPDATE openmettle.gateway_requests SET settled_final=true WHERE id=NEW.request_id AND NOT settled_final;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_mark_settled_final() FROM PUBLIC;
CREATE TRIGGER gateway_mark_settled_final AFTER INSERT OR UPDATE OF final ON openmettle.gateway_settlements
    FOR EACH ROW WHEN (NEW.final) EXECUTE FUNCTION openmettle.gateway_mark_settled_final();

-- Admission replay locks the same run as admission. An identical hold is a
-- no-op. A reused run or hold with changed ownership or units is a conflict.
CREATE FUNCTION openmettle.gateway_run_hold() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    existing openmettle.gateway_reservations%ROWTYPE;
BEGIN
    PERFORM FROM openmettle.runs r WHERE r.id=NEW.run_id AND r.actor_approval_id=NEW.approval_id
        AND r.scope_id=NEW.scope_id AND r.actor_user_id=NEW.actor_user_id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'invalid run reservation' USING ERRCODE='23503'; END IF;
    SELECT * INTO existing FROM openmettle.gateway_reservations WHERE run_id=NEW.run_id;
    IF FOUND THEN
        IF (existing.id,existing.scope_id,existing.actor_user_id,existing.approval_id,existing.units)
           = (NEW.id,NEW.scope_id,NEW.actor_user_id,NEW.approval_id,NEW.units) THEN RETURN NULL; END IF;
        RAISE EXCEPTION 'conflicting run reservation' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_run_hold() FROM PUBLIC;
CREATE TRIGGER gateway_run_hold BEFORE INSERT ON openmettle.gateway_reservations
    FOR EACH ROW WHEN (NEW.run_id IS NOT NULL) EXECUTE FUNCTION openmettle.gateway_run_hold();

CREATE FUNCTION openmettle.gateway_allocate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT pg_has_role(session_user, CASE WHEN NEW.run_id IS NULL THEN 'openmettle_api'
                                         ELSE 'openmettle_worker' END, 'USAGE') THEN
        RAISE EXCEPTION 'incorrect inference role' USING ERRCODE = '42501';
    END IF;
    UPDATE openmettle.gateway_reservations SET allocated = allocated + NEW.units
     WHERE id = NEW.reservation_id AND units - allocated >= NEW.units
       AND (NEW.run_id IS NOT NULL OR units = NEW.units);
    IF NOT FOUND THEN RAISE EXCEPTION 'reservation unavailable' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_allocate() FROM PUBLIC;
CREATE TRIGGER gateway_allocate AFTER INSERT ON openmettle.gateway_requests
    FOR EACH ROW EXECUTE FUNCTION openmettle.gateway_allocate();

-- Only the holder of the per-call random dispatch secret can release or hand off.
-- Both transitions lock the allocation before the request; neither can be repeated.
CREATE FUNCTION openmettle.gateway_release(p_request uuid,p_dispatch bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    SELECT * INTO req FROM openmettle.gateway_requests WHERE id=p_request
        AND octet_length(p_dispatch)=32 AND dispatch_hash=sha256(p_dispatch) AND state='reserved'
        AND pg_has_role(session_user, CASE WHEN run_id IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END,'USAGE');
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM FROM openmettle.gateway_reservations WHERE id=req.reservation_id FOR UPDATE;
    UPDATE openmettle.gateway_requests SET state='released' WHERE id=p_request AND state='reserved';
    IF NOT FOUND THEN RETURN false; END IF;
    -- For a run, the round's units go back to its existing admission hold. A
    -- caller-owned reservation is terminal when its only request is released.
    UPDATE openmettle.gateway_reservations SET allocated=allocated-req.units WHERE id=req.reservation_id;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_release(uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_release(uuid,bytea) TO openmettle_api, openmettle_worker;

-- The only ciphertext lookup also consumes the right to dispatch. The caller
-- may hand the result to HTTP only after acknowledgement of the transaction.
CREATE FUNCTION openmettle.gateway_handoff(p_request uuid,p_dispatch bytea,p_secret bytea,p_audience bytea,p_lease uuid)
RETURNS TABLE (installation text,actor text,binding text,principal text,generation bigint,
               key_id text,nonce bytea,ciphertext bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
    b openmettle.gateway_bindings%ROWTYPE;
    t timestamptz;
    ms bigint;
BEGIN
    SELECT * INTO req FROM openmettle.gateway_requests q WHERE q.id=p_request
        AND octet_length(p_dispatch)=32 AND q.dispatch_hash=sha256(p_dispatch) AND q.state='reserved'
        AND pg_has_role(session_user, CASE WHEN q.run_id IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END,'USAGE');
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM FROM openmettle.account_admin_lock FOR SHARE;
    PERFORM FROM openmettle.projects p WHERE p.scope_id=req.scope_id FOR SHARE;
    PERFORM FROM openmettle.login_providers p JOIN openmettle.local_identity_approvals a ON a.provider_id=p.id
        WHERE a.id=req.approval_id FOR SHARE OF p,a;
    PERFORM FROM openmettle.users u WHERE u.id=req.actor_user_id FOR SHARE;
    -- The API proves a live session. Background inference proves the current
    -- run lease; its originating session is used only for effect approvals (ADR 0035).
    PERFORM FROM openmettle.runs r WHERE r.id=req.run_id FOR SHARE;
    PERFORM FROM openmettle.local_sessions s WHERE s.id=req.session_id FOR SHARE;
    SELECT * INTO b FROM openmettle.gateway_bindings gb WHERE gb.installation=req.installation
        AND gb.user_id=req.actor_user_id AND gb.state='ready' FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM FROM openmettle.gateway_reservations WHERE id=req.reservation_id FOR SHARE;
    PERFORM FROM openmettle.gateway_requests q WHERE q.id=p_request AND q.state='reserved' FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    t := clock_timestamp();
    ms := floor(extract(epoch FROM t)*1000)::bigint;

    RETURN QUERY
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
        SELECT g.*, h.cycle_id FROM openmettle.grant_assignments g
        JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
        WHERE g.scope_id=req.scope_id AND h.decision='grant' AND g.assignment_version=1 AND g.source_kind='direct'
          AND (g.grantee_user_id=req.actor_user_id OR g.grantee_kind='project'
               OR g.grantee_oidc_group_id IN (SELECT claim_value FROM oidc_groups)
               OR EXISTS (SELECT FROM openmettle.local_groups lg JOIN openmettle.local_group_memberships lm ON lm.group_id=lg.id
                          WHERE lg.id=g.grantee_local_group_id AND lg.disabled_at IS NULL AND lm.active AND lm.user_id=req.actor_user_id))
    ), project_roles AS (
        SELECT g.* FROM actor_grants g WHERE g.target_kind='project' AND g.assignment_format='openmettle.project-role'
          AND g.assignment_key IN ('viewer','editor','owner') AND g.grantee_kind<>'project'
    ), authorized AS (
        SELECT e.*,pol.report_source FROM openmettle.gateway_generations e
        JOIN openmettle.gateway_policy pol ON pol.binding_id=e.binding_id AND pol.revision=b.observed_revision
        JOIN openmettle.local_identity_approvals a ON a.id=pol.approval_id AND a.active AND a.expires_ms>ms
        JOIN openmettle.user_identities i ON i.id=a.identity_id AND i.user_id=req.actor_user_id
        JOIN openmettle.users u ON u.id=i.user_id AND u.disabled_at IS NULL
        JOIN openmettle.login_providers p ON p.id=a.provider_id AND p.issuer=i.issuer
        JOIN LATERAL (SELECT v.revision,v.epoch FROM openmettle.login_provider_revisions v
                      WHERE v.provider_id=p.id ORDER BY v.epoch DESC LIMIT 1) current ON current.revision IS NOT NULL
        JOIN openmettle.scopes sc ON sc.id=pol.scope_id
        LEFT JOIN openmettle.local_sessions s ON s.id=req.session_id
        WHERE e.binding_id=b.id AND e.generation=b.active_generation AND e.expires_at>t
          AND (pol.provider_generation,pol.approval_generation,pol.user_generation)
               =(p.access_generation,a.access_generation,u.session_generation)
          AND (pol.approval_id,pol.scope_id,pol.model)=(req.approval_id,req.scope_id,req.model)
          AND (req.run_id IS NOT NULL OR (s.user_id=u.id AND s.approval_id=a.id AND s.identity_id=i.id
               AND s.provider_id=p.id AND NOT s.revoked AND s.created_ms<=ms AND s.expires_ms>ms
               AND s.issued_client=p.client_id AND s.provider_generation=p.access_generation
               AND s.approval_generation=a.access_generation AND s.user_generation=u.session_generation
               AND NOT EXISTS (SELECT FROM openmettle.login_provider_revisions v WHERE v.provider_id=p.id
                               AND v.epoch>s.issued_epoch AND v.revision IS NULL)))
          AND ((req.run_id IS NULL AND p_lease IS NULL AND octet_length(p_secret)=32
               AND s.secret_hash=sha256(convert_to(CASE WHEN p_audience IS NULL THEN 'openmettle/session-secret/1'
                   ELSE 'openmettle/native-session-secret/1' END,'UTF8') || decode('00','hex')
                   || int8send(43) || convert_to(s.id,'UTF8') || int8send(32) || p_secret)
               AND (p_audience IS NULL OR EXISTS (SELECT FROM openmettle.native_handoffs n
                     WHERE n.session_id=s.id AND n.sealed IS NULL AND n.audience=p_audience)))
            OR (req.run_id IS NOT NULL AND p_secret IS NULL AND p_audience IS NULL AND EXISTS (
                SELECT FROM openmettle.runs r WHERE r.id=req.run_id AND r.actor_approval_id=a.id
                  AND r.actor_user_id=u.id AND r.scope_id=sc.id AND r.claim_token=p_lease AND r.state='running'
                  AND r.cancel_reason IS NULL AND r.lease_expires_at>t AND r.execution_expires_at>t
                  AND req.round<=r.round_limit)))
          AND NOT EXISTS (SELECT FROM jsonb_each(pol.capabilities) cap
              LEFT JOIN openmettle.platform_capability_denies pd ON pd.capability=cap.key
              LEFT JOIN openmettle.user_capability_denies ud ON ud.user_id=u.id AND ud.capability=cap.key
              LEFT JOIN openmettle.user_capability_grants ug ON ug.user_id=u.id AND ug.capability=cap.key
              WHERE pd.denied OR ud.denied OR (cap.value='true'::jsonb AND NOT coalesce(ug.granted,false)))
          AND ((sc.personal_user_id=u.id AND pol.grant_cycle IS NULL) OR EXISTS (
              SELECT FROM project_roles g
              LEFT JOIN openmettle.project_settings ps ON ps.project_id=g.target_id
              WHERE g.target_id=sc.project_id AND g.cycle_id=pol.grant_cycle
                AND ps.archived_at IS NULL AND ps.deleted_at IS NULL
                AND g.assignment_key IN ('editor','owner')
                AND (req.run_id IS NULL OR EXISTS (
                    SELECT FROM openmettle.runs r JOIN openmettle.conversations c ON c.id=r.conversation_id
                    WHERE r.id=req.run_id AND (c.owner_user_id=u.id OR EXISTS (
                        SELECT FROM actor_grants share WHERE share.target_kind='conversation' AND share.target_id=c.id
                          AND share.assignment_format='openmettle.resource-grant' AND share.assignment_key='write'
                          AND (share.grantee_kind IN ('user','project') OR EXISTS (
                              SELECT FROM project_roles member WHERE member.grantee_local_group_id=share.grantee_local_group_id
                                  OR member.grantee_oidc_group_id=share.grantee_oidc_group_id))))))))
    ), handed AS (
        UPDATE openmettle.gateway_requests q SET state='handed_off',binding_id=b.id,
            generation=b.active_generation,policy_revision=b.observed_revision,report_source=authorized.report_source
        FROM authorized WHERE q.id=req.id AND q.state='reserved' RETURNING q.id
    )
    SELECT b.installation::text,b.user_id::text,b.id::text,b.principal::text,e.generation,e.key_id,e.nonce,e.ciphertext
      FROM authorized e,handed;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid) TO openmettle_api,openmettle_worker;

-- Reconciliation reads no local session credentials. Only inert authority guards are writable.
GRANT SELECT ON openmettle.gateway_bindings TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_generations TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_policy TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_intents TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_audit TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_reservations TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_requests TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_usage_reports TO openmettle_gateway;
GRANT SELECT ON openmettle.gateway_settlements TO openmettle_gateway;
GRANT SELECT ON openmettle.account_admin_lock TO openmettle_gateway;
GRANT SELECT ON openmettle.projects TO openmettle_gateway;
GRANT SELECT ON openmettle.users TO openmettle_gateway;
GRANT SELECT ON openmettle.user_identities TO openmettle_gateway;
GRANT SELECT ON openmettle.scopes TO openmettle_gateway;
GRANT SELECT ON openmettle.local_identity_approvals TO openmettle_gateway;
GRANT SELECT ON openmettle.login_providers TO openmettle_gateway;
GRANT SELECT ON openmettle.login_provider_revisions TO openmettle_gateway;
GRANT SELECT ON openmettle.grant_assignments TO openmettle_gateway;
GRANT SELECT ON openmettle.grant_changes TO openmettle_gateway;
GRANT SELECT ON openmettle.local_groups TO openmettle_gateway;
GRANT SELECT ON openmettle.local_group_memberships TO openmettle_gateway;
GRANT SELECT ON openmettle.membership_observations TO openmettle_gateway;
GRANT SELECT ON openmettle.grant_mapping_rules TO openmettle_gateway;
GRANT SELECT ON openmettle.grant_mapping_revisions TO openmettle_gateway;
GRANT SELECT ON openmettle.project_settings TO openmettle_gateway;
GRANT SELECT ON openmettle.platform_capability_denies TO openmettle_gateway;
GRANT SELECT ON openmettle.user_capability_denies TO openmettle_gateway;
GRANT SELECT ON openmettle.user_capability_grants TO openmettle_gateway;
GRANT UPDATE (lock_guard) ON openmettle.account_admin_lock TO openmettle_gateway;
GRANT UPDATE (lock_guard) ON openmettle.projects TO openmettle_gateway;
GRANT UPDATE (lock_guard) ON openmettle.users TO openmettle_gateway;
GRANT UPDATE (lock_guard) ON openmettle.login_providers TO openmettle_gateway;
GRANT UPDATE (lock_guard) ON openmettle.local_identity_approvals TO openmettle_gateway;
GRANT INSERT (key_fingerprint,nonce) ON openmettle.gateway_nonces TO openmettle_gateway;
GRANT INSERT (installation,user_id,principal,budget) ON openmettle.gateway_bindings TO openmettle_gateway;
GRANT UPDATE (desired_revision,observed_revision,state,active_generation) ON openmettle.gateway_bindings TO openmettle_gateway;
GRANT INSERT (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext) ON openmettle.gateway_generations TO openmettle_gateway;
GRANT UPDATE (expires_at,key_id,key_fingerprint,nonce,ciphertext) ON openmettle.gateway_generations TO openmettle_gateway;
GRANT INSERT (binding_id,revision,scope_id,approval_id,model,report_source,provider_generation,approval_generation,user_generation,grant_cycle,capabilities) ON openmettle.gateway_policy TO openmettle_gateway;
GRANT INSERT (binding_id,desired_revision,generation,action,expected_revision,parameters) ON openmettle.gateway_intents TO openmettle_gateway;
GRANT UPDATE (claim,due_at,complete) ON openmettle.gateway_intents TO openmettle_gateway;
GRANT INSERT (binding_id,desired_revision,operation_id,step,outcome,remote_handle,remote_revision) ON openmettle.gateway_audit TO openmettle_gateway;
GRANT INSERT (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,cost,unit) ON openmettle.gateway_usage_reports TO openmettle_gateway;
GRANT INSERT (request_id,revision,final,measured,outstanding) ON openmettle.gateway_settlements TO openmettle_gateway;
GRANT UPDATE (revision,final,measured,outstanding) ON openmettle.gateway_settlements TO openmettle_gateway;
GRANT INSERT (id,scope_id,actor_user_id,approval_id,run_id,units) ON openmettle.gateway_reservations TO openmettle_api;
GRANT INSERT (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,session_id) ON openmettle.gateway_requests TO openmettle_api;
GRANT INSERT (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round) ON openmettle.gateway_requests TO openmettle_worker;
