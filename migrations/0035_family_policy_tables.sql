-- ADR 0044 / V1-06 increment 4: family policy tables (`family_policies` and
-- `family_policy_models`), authoritative SQL evaluator (`family_policy_permits`), audit
-- vocabulary extension, and database-level enforcement on `gateway_round_authority`,
-- `gateway_handoff_round` and `gateway_dispatch`.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.

-- Current-state family schedule and override rules per user, local group or OIDC group.
-- No runtime role holds DELETE: policies deactivate via `active = false` and bump `revision`.
CREATE TABLE openmettle.family_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    grantee_kind text NOT NULL CHECK (grantee_kind IN ('user', 'local_group', 'oidc_group')),
    grantee_user_id uuid REFERENCES openmettle.users (id),
    grantee_local_group_id uuid REFERENCES openmettle.local_groups (id),
    grantee_oidc_group_id text CHECK (
        octet_length(grantee_oidc_group_id) BETWEEN 1 AND 1024
        AND grantee_oidc_group_id COLLATE "C" !~ '[[:cntrl:]]'
    ),
    active boolean NOT NULL,
    zone text NOT NULL CHECK (
        octet_length(zone) BETWEEN 1 AND 128
        AND zone COLLATE "C" ~ '^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+_.-]+$'
    ),
    quiet_start_minute smallint,
    quiet_end_minute smallint,
    study_start_minute smallint,
    study_end_minute smallint,
    override_group_schedules boolean NOT NULL DEFAULT false
        CHECK (NOT override_group_schedules OR grantee_kind = 'user'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_by_user_id uuid REFERENCES openmettle.users (id),
    CONSTRAINT family_policies_grantee_check CHECK (
        (grantee_kind = 'user' AND grantee_user_id IS NOT NULL
            AND grantee_local_group_id IS NULL AND grantee_oidc_group_id IS NULL)
        OR (grantee_kind = 'local_group' AND grantee_local_group_id IS NOT NULL
            AND grantee_user_id IS NULL AND grantee_oidc_group_id IS NULL)
        OR (grantee_kind = 'oidc_group' AND grantee_oidc_group_id IS NOT NULL
            AND grantee_user_id IS NULL AND grantee_local_group_id IS NULL)
    ),
    CONSTRAINT family_policies_quiet_window_check CHECK (
        (quiet_start_minute IS NULL AND quiet_end_minute IS NULL)
        OR (quiet_start_minute IS NOT NULL
            AND quiet_end_minute IS NOT NULL
            AND quiet_start_minute BETWEEN 0 AND 1439
            AND quiet_end_minute BETWEEN 0 AND 1439
            AND quiet_start_minute <> quiet_end_minute)
    ),
    CONSTRAINT family_policies_study_window_check CHECK (
        (study_start_minute IS NULL AND study_end_minute IS NULL)
        OR (study_start_minute IS NOT NULL
            AND study_end_minute IS NOT NULL
            AND study_start_minute BETWEEN 0 AND 1439
            AND study_end_minute BETWEEN 0 AND 1439
            AND study_start_minute <> study_end_minute)
    ),
    CONSTRAINT family_policies_grantee_unique UNIQUE NULLS NOT DISTINCT
        (grantee_kind, grantee_user_id, grantee_local_group_id, grantee_oidc_group_id)
);
CREATE INDEX family_policies_user_idx
    ON openmettle.family_policies (grantee_user_id)
    WHERE grantee_user_id IS NOT NULL;
CREATE INDEX family_policies_local_group_idx
    ON openmettle.family_policies (grantee_local_group_id)
    WHERE grantee_local_group_id IS NOT NULL;
CREATE INDEX family_policies_oidc_group_idx
    ON openmettle.family_policies (grantee_oidc_group_id)
    WHERE grantee_oidc_group_id IS NOT NULL;

CREATE FUNCTION openmettle.enforce_family_policy_timezone()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_timezone_names WHERE name = NEW.zone) THEN
        RAISE EXCEPTION 'unknown family policy timezone' USING ERRCODE = '23514';
    END IF;
    IF NEW.updated_by_user_id IS NULL
       AND NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        RAISE EXCEPTION 'family policy writes require updated_by_user_id' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.revision <= OLD.revision THEN
        RAISE EXCEPTION 'family policy revision must increase' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_family_policy_timezone() FROM PUBLIC;
CREATE TRIGGER family_policies_guard
    BEFORE INSERT OR UPDATE ON openmettle.family_policies
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.enforce_family_policy_timezone();

-- Current-state per-policy model allowlist (`study_allow`) and kill-switch (`disabled`) rows.
CREATE TABLE openmettle.family_policy_models (
    policy_id uuid NOT NULL REFERENCES openmettle.family_policies (id),
    rule_kind text NOT NULL CHECK (rule_kind IN ('study_allow', 'disabled')),
    model text NOT NULL CHECK (
        octet_length(model) BETWEEN 1 AND 256
        AND model COLLATE "C" !~ '[[:cntrl:]]'
    ),
    active boolean NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_by_user_id uuid REFERENCES openmettle.users (id),
    PRIMARY KEY (policy_id, rule_kind, model)
);

CREATE FUNCTION openmettle.enforce_family_policy_model_writer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.updated_by_user_id IS NULL
       AND NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        RAISE EXCEPTION 'family policy model writes require updated_by_user_id'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.revision <= OLD.revision THEN
        RAISE EXCEPTION 'family policy model revision must increase' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_family_policy_model_writer() FROM PUBLIC;
CREATE TRIGGER family_policy_models_guard
    BEFORE INSERT OR UPDATE ON openmettle.family_policy_models
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.enforce_family_policy_model_writer();

-- API: reads and column-scoped inserts/updates on family policy tables. No DELETE for any runtime
-- role; worker, gateway and issuance hold no table privileges on these tables.
GRANT SELECT ON openmettle.family_policies, openmettle.family_policy_models TO openmettle_api;
GRANT INSERT (
    id, grantee_kind, grantee_user_id, grantee_local_group_id, grantee_oidc_group_id,
    active, zone, quiet_start_minute, quiet_end_minute, study_start_minute, study_end_minute,
    override_group_schedules, updated_by_user_id
) ON openmettle.family_policies TO openmettle_api;
GRANT UPDATE (
    active, zone, quiet_start_minute, quiet_end_minute, study_start_minute, study_end_minute,
    override_group_schedules, revision, updated_at, updated_by_user_id
) ON openmettle.family_policies TO openmettle_api;
GRANT INSERT (policy_id, rule_kind, model, active, updated_by_user_id)
    ON openmettle.family_policy_models TO openmettle_api;
GRANT UPDATE (active, revision, updated_at, updated_by_user_id)
    ON openmettle.family_policy_models TO openmettle_api;

-- Widen `authorization_audit` CHECK constraints additively under a bounded `NOWAIT` retry loop
-- so family-policy mutations record append-only audit rows for both `'user'` and `'operator'`.
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
            LOCK TABLE openmettle.authorization_audit IN ACCESS EXCLUSIVE MODE NOWAIT;
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
            'retention.policy_update',
            'family_policy.set', 'family_policy.clear',
            'family_policy.model_study_allow', 'family_policy.model_study_revoke',
            'family_policy.model_disable', 'family_policy.model_enable')),
        DROP CONSTRAINT authorization_audit_target_kind_check,
        ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN (
            'user', 'project', 'conversation', 'artifact', 'local_group', 'capability',
            'scope', 'branch', 'quota_scope', 'retention_policy',
            'family_policy', 'oidc_group'));
END
$$;

-- Single authoritative batch evaluator shared by API admission/preview (directly) and
-- `family_policy_permits` (single-model wrapper). Evaluates OIDC/local-group membership and
-- wall-clock timezone conversion ONCE per applicable policy row using PostgreSQL's in-memory
-- timezone cache (never scanning `pg_timezone_names` per call). Takes no row locks.
CREATE FUNCTION openmettle.family_policy_filter_models(
    p_user uuid,
    p_approval uuid,
    p_models text[],
    p_at timestamptz)
RETURNS SETOF text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    ms bigint;
    has_override boolean;
    fp openmettle.family_policies%ROWTYPE;
    local_time timestamp;
    m integer;
    v_policy_ids uuid[] := '{}'::uuid[];
    v_study_policy_ids uuid[] := '{}'::uuid[];
BEGIN
    IF p_user IS NULL OR p_approval IS NULL OR p_models IS NULL OR p_at IS NULL THEN
        RETURN;
    END IF;
    ms := floor(extract(epoch FROM p_at) * 1000)::bigint;

    SELECT EXISTS (
        SELECT 1
          FROM openmettle.family_policies f
         WHERE f.grantee_kind = 'user'
           AND f.grantee_user_id = p_user
           AND f.active
           AND f.override_group_schedules
    ) INTO has_override;

    -- OIDC-group fail-closed rule: any membership observation on `(p_approval, p_user)` whose
    -- enrolled mapping revision OR latest mapping revision targets an active `oidc_group` family
    -- policy must be enabled, on the current enabled group revision, at the provider's latest
    -- non-retired epoch, matching current generations, unexpired, and `'present'` or `'absent'`
    -- (with `'present'` validated against `grant_changes`), unless an active user policy sets
    -- `override_group_schedules = true`.
    IF NOT has_override AND EXISTS (
        SELECT 1
          FROM openmettle.membership_observations mo
          JOIN openmettle.local_identity_approvals a ON a.id = mo.approval_id
          JOIN openmettle.user_identities i ON i.id = a.identity_id AND i.user_id = p_user
          JOIN openmettle.users u ON u.id = i.user_id
          LEFT JOIN openmettle.grant_mapping_rules r ON r.id = mo.rule_id
          LEFT JOIN openmettle.grant_mapping_revisions v_enrolled
            ON v_enrolled.rule_id = mo.rule_id AND v_enrolled.revision = mo.rule_revision
          LEFT JOIN openmettle.grant_mapping_revisions v_latest
            ON v_latest.rule_id = r.id AND v_latest.revision = r.last_revision
          LEFT JOIN openmettle.grant_assignments g
            ON g.scope_id = mo.scope_id
           AND g.project_id = mo.project_id
           AND g.grantee_user_id = u.id
           AND g.mapping_rule_id = r.id
           AND g.assignment_key = a.id::text
           AND g.assignment_format = 'openmettle.project-member'
           AND g.assignment_version = 1
          LEFT JOIN openmettle.grant_changes h
            ON h.assignment_id = g.id AND h.revision = g.last_revision
          LEFT JOIN LATERAL (
              SELECT pr.epoch, pr.revision
                FROM openmettle.login_provider_revisions pr
               WHERE pr.provider_id = a.provider_id
               ORDER BY pr.epoch DESC
               LIMIT 1
          ) e ON true
         WHERE mo.approval_id = p_approval
           AND (
               ((r.id IS NULL OR v_enrolled.rule_id IS NULL OR v_latest.rule_id IS NULL)
                AND EXISTS (
                   SELECT 1
                     FROM openmettle.family_policies ofp
                    WHERE ofp.grantee_kind = 'oidc_group'
                      AND ofp.active
               ))
               OR (v_enrolled.selector_kind = 'group' AND EXISTS (
                   SELECT 1
                     FROM openmettle.family_policies ofp
                    WHERE ofp.grantee_kind = 'oidc_group'
                      AND ofp.grantee_oidc_group_id = v_enrolled.claim_value
                      AND ofp.active
               ))
               OR (v_latest.selector_kind = 'group' AND EXISTS (
                   SELECT 1
                     FROM openmettle.family_policies ofp
                    WHERE ofp.grantee_kind = 'oidc_group'
                      AND ofp.grantee_oidc_group_id = v_latest.claim_value
                      AND ofp.active
               ))
           )
           AND (
               CASE
                   WHEN NOT mo.enabled
                        OR NOT a.active OR a.expires_ms <= ms OR u.disabled_at IS NOT NULL
                        OR r.id IS NULL OR v_enrolled.rule_id IS NULL OR v_latest.rule_id IS NULL
                        OR r.provider_config_id <> a.provider_id OR r.issuer <> i.issuer
                        OR r.last_revision <> mo.rule_revision
                        OR NOT v_enrolled.enabled
                        OR v_enrolled.selector_kind <> 'group'
                        OR v_enrolled.binding_format <> 'openmettle.project-member'
                        OR v_enrolled.binding_version <> 1
                        OR v_enrolled.binding <> convert_to(mo.project_id::text, 'UTF8')
                        OR e.revision IS NULL
                        OR h.id IS DISTINCT FROM (mo.observation).change_id THEN 'failed'
                   WHEN mo.issued_ms IS NULL THEN 'missing'
                   WHEN mo.epoch IS DISTINCT FROM e.epoch
                        OR mo.approval_generation IS DISTINCT FROM a.access_generation
                        OR mo.user_generation IS DISTINCT FROM u.session_generation THEN 'failed'
                   WHEN ms < mo.issued_ms
                        OR ms >= least(mo.expires_ms,
                                       mo.issued_ms + 1000::bigint * mo.max_age_seconds) THEN 'stale'
                   WHEN (mo.observation).state = 'present'
                        AND (h.id IS NULL
                             OR h.decision IS DISTINCT FROM 'grant'
                             OR h.cycle_id IS DISTINCT FROM h.id
                             OR h.mapping_revision IS DISTINCT FROM mo.rule_revision) THEN 'failed'
                   WHEN (mo.observation).state = 'absent'
                        AND h.id IS NOT NULL
                        AND h.decision IS DISTINCT FROM 'revoke' THEN 'failed'
                   ELSE (mo.observation).state
               END
           ) NOT IN ('present', 'absent')
    ) THEN
        RETURN;
    END IF;

    FOR fp IN
        WITH present_oidc_groups AS (
            SELECT v.claim_value
              FROM openmettle.membership_observations mo
              JOIN openmettle.local_identity_approvals a ON a.id = mo.approval_id
              JOIN openmettle.user_identities i ON i.id = a.identity_id AND i.user_id = p_user
              JOIN openmettle.users u ON u.id = i.user_id AND u.disabled_at IS NULL
              JOIN openmettle.grant_mapping_rules r
                ON r.id = mo.rule_id
               AND r.last_revision = mo.rule_revision
               AND r.provider_config_id = a.provider_id
               AND r.issuer = i.issuer
              JOIN openmettle.grant_mapping_revisions v
                ON v.rule_id = r.id AND v.revision = mo.rule_revision
              JOIN openmettle.grant_assignments g
                ON g.scope_id = mo.scope_id
               AND g.project_id = mo.project_id
               AND g.grantee_user_id = u.id
               AND g.mapping_rule_id = r.id
               AND g.assignment_key = a.id::text
               AND g.assignment_format = 'openmettle.project-member'
               AND g.assignment_version = 1
              JOIN openmettle.grant_changes h
                ON h.assignment_id = g.id AND h.revision = g.last_revision
              JOIN LATERAL (
                  SELECT pr.epoch, pr.revision
                    FROM openmettle.login_provider_revisions pr
                   WHERE pr.provider_id = a.provider_id
                   ORDER BY pr.epoch DESC
                   LIMIT 1
              ) e ON e.revision IS NOT NULL
             WHERE NOT has_override
               AND mo.approval_id = p_approval
               AND mo.enabled
               AND a.active
               AND a.expires_ms > ms
               AND v.enabled
               AND v.selector_kind = 'group'
               AND v.binding_format = 'openmettle.project-member'
               AND v.binding_version = 1
               AND v.binding = convert_to(mo.project_id::text, 'UTF8')
               AND mo.issued_ms IS NOT NULL
               AND mo.epoch = e.epoch
               AND mo.approval_generation = a.access_generation
               AND mo.user_generation = u.session_generation
               AND (mo.observation).state = 'present'
               AND h.id = (mo.observation).change_id
               AND h.decision = 'grant'
               AND h.cycle_id = h.id
               AND h.mapping_revision = mo.rule_revision
               AND mo.issued_ms <= ms
               AND least(mo.expires_ms, mo.issued_ms + 1000::bigint * mo.max_age_seconds) > ms
        )
        SELECT f.*
          FROM openmettle.family_policies f
         WHERE f.active
           AND (
               (has_override AND f.grantee_kind = 'user' AND f.grantee_user_id = p_user
                AND f.override_group_schedules)
               OR (NOT has_override AND (
                   (f.grantee_kind = 'user' AND f.grantee_user_id = p_user)
                   OR (f.grantee_kind = 'local_group' AND EXISTS (
                       SELECT 1
                         FROM openmettle.local_group_memberships lm
                         JOIN openmettle.local_groups lg ON lg.id = lm.group_id
                        WHERE lm.group_id = f.grantee_local_group_id
                          AND lm.user_id = p_user
                          AND lm.active
                          AND lg.disabled_at IS NULL
                   ))
                   OR (f.grantee_kind = 'oidc_group'
                       AND f.grantee_oidc_group_id IN (SELECT claim_value FROM present_oidc_groups))
               ))
           )
    LOOP
        BEGIN
            local_time := p_at AT TIME ZONE fp.zone;
        EXCEPTION
            WHEN invalid_parameter_value THEN
                RETURN;
        END;
        m := extract(hour FROM local_time)::int * 60 + extract(minute FROM local_time)::int;
        IF fp.quiet_start_minute IS NOT NULL AND (
            (fp.quiet_start_minute < fp.quiet_end_minute
                AND m >= fp.quiet_start_minute AND m < fp.quiet_end_minute)
            OR (fp.quiet_start_minute > fp.quiet_end_minute
                AND (m >= fp.quiet_start_minute OR m < fp.quiet_end_minute))
        ) THEN
            RETURN;
        END IF;
        v_policy_ids := array_append(v_policy_ids, fp.id);
        IF fp.study_start_minute IS NOT NULL AND (
            (fp.study_start_minute < fp.study_end_minute
                AND m >= fp.study_start_minute AND m < fp.study_end_minute)
            OR (fp.study_start_minute > fp.study_end_minute
                AND (m >= fp.study_start_minute OR m < fp.study_end_minute))
        ) THEN
            v_study_policy_ids := array_append(v_study_policy_ids, fp.id);
        END IF;
    END LOOP;

    RETURN QUERY
    SELECT DISTINCT cand.model
      FROM unnest(p_models) AS cand(model)
     WHERE cand.model IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
             FROM openmettle.family_policy_models r
            WHERE r.policy_id = ANY(v_policy_ids)
              AND r.rule_kind = 'disabled'
              AND r.active
              AND r.model = cand.model
       )
       AND NOT EXISTS (
           SELECT 1
             FROM unnest(v_study_policy_ids) AS sp(policy_id)
            WHERE NOT EXISTS (
                SELECT 1
                  FROM openmettle.family_policy_models r
                 WHERE r.policy_id = sp.policy_id
                   AND r.rule_kind = 'study_allow'
                   AND r.active
                   AND r.model = cand.model
            )
       );
END;
$$;
REVOKE ALL ON FUNCTION openmettle.family_policy_filter_models(uuid,uuid,text[],timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.family_policy_filter_models(uuid,uuid,text[],timestamptz)
    TO openmettle_api;

-- Single-model wrapper over `family_policy_filter_models` shared by API admission/preview,
-- worker claim/recheck, `gateway_round_authority` and `gateway_dispatch`. Takes no row locks.
CREATE FUNCTION openmettle.family_policy_permits(
    p_user uuid,
    p_approval uuid,
    p_model text,
    p_at timestamptz)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT p_model IS NOT NULL
       AND EXISTS (
           SELECT 1
             FROM openmettle.family_policy_filter_models(p_user, p_approval, ARRAY[p_model], p_at)
       );
$$;
REVOKE ALL ON FUNCTION openmettle.family_policy_permits(uuid,uuid,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.family_policy_permits(uuid,uuid,text,timestamptz)
    TO openmettle_api, openmettle_worker;

-- Extend migration 34's internal authority check with live family-policy evaluation.
-- Signature, security and privileges are unchanged.
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
          AND openmettle.family_policy_permits(req.actor_user_id, req.approval_id, req.model, p_at)
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

-- Keep the exact canonical handoff lock prefix (`account_admin_lock -> projects ->
-- login_providers/approvals -> users -> runs -> gateway_reservations -> gateway_requests`).
-- Local-group and family-policy writers all acquire `account_admin_lock FOR UPDATE`, so
-- `account_admin_lock FOR SHARE` (here and in `quota_lock_turn_handoff_prefix`) serializes
-- every local-group membership and family-policy mutation with round handoff cleanly.
-- Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.gateway_handoff_round(
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

-- Enforce live family policy at proxy dispatch after acquiring canonical shared authorization
-- locks (`account_admin_lock -> login_providers/approvals -> users -> runs -> gateway_requests`)
-- so concurrent policy/group writes, approval withdrawals and user disables serialize before
-- spending the bearer (`401`, nothing sent upstream; worker sweep closes as `not_dispatched`).
-- Wrong bearers still take zero locks. Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.gateway_dispatch(p_request uuid,p_bearer_hash bytea)
RETURNS TABLE (replayed boolean,installation text,scope text,source text,principal text,model text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_run uuid;
    v_approval uuid;
    v_actor uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway dispatch requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    SELECT q.run_id, q.approval_id, q.actor_user_id
      INTO v_run, v_approval, v_actor
      FROM openmettle.gateway_requests q
     WHERE q.id = p_request
       AND q.bearer_hash = p_bearer_hash
       AND pg_has_role(session_user, 'openmettle_gateway', 'USAGE');
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM FROM openmettle.account_admin_lock FOR SHARE;
    PERFORM FROM openmettle.login_providers p
       JOIN openmettle.local_identity_approvals a ON a.provider_id = p.id
      WHERE a.id = v_approval
        FOR SHARE OF p, a;
    PERFORM FROM openmettle.users u WHERE u.id = v_actor FOR SHARE;
    PERFORM FROM openmettle.runs r WHERE r.id = v_run FOR SHARE;
    PERFORM FROM openmettle.gateway_requests q WHERE q.id = p_request
        AND q.bearer_hash = p_bearer_hash AND q.state = 'handed_off'
        AND pg_has_role(session_user, 'openmettle_gateway', 'USAGE') FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    RETURN QUERY
    WITH clock AS MATERIALIZED (SELECT clock_timestamp() AS t)
    UPDATE openmettle.gateway_requests q SET dispatched_at = clock.t
      FROM clock
     WHERE q.id = p_request AND q.bearer_hash = p_bearer_hash AND q.state = 'handed_off'
       AND q.dispatched_at IS NULL
       AND NOT EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id = q.id)
       AND EXISTS (SELECT FROM openmettle.runs r
            WHERE r.id = q.run_id AND r.state = 'running' AND r.cancel_reason IS NULL
              AND r.actor_user_id = q.actor_user_id AND r.actor_approval_id = q.approval_id
              AND sha256(uuid_send(r.claim_token)) = q.claim_hash
              AND r.lease_expires_at > clock.t AND r.execution_expires_at > clock.t)
       AND EXISTS (SELECT FROM openmettle.local_identity_approvals a
             JOIN openmettle.user_identities i ON i.id = a.identity_id AND i.user_id = q.actor_user_id
             JOIN openmettle.users u ON u.id = i.user_id AND u.disabled_at IS NULL
             JOIN openmettle.login_providers p ON p.id = a.provider_id AND p.issuer = i.issuer
             JOIN LATERAL (
                 SELECT pr.revision
                   FROM openmettle.login_provider_revisions pr
                  WHERE pr.provider_id = p.id
                  ORDER BY pr.epoch DESC
                  LIMIT 1
             ) current ON current.revision IS NOT NULL
            WHERE a.id = q.approval_id
              AND a.active
              AND a.expires_ms > floor(extract(epoch FROM clock.t) * 1000)::bigint)
       AND openmettle.family_policy_permits(q.actor_user_id, q.approval_id, q.model, clock.t)
    RETURNING false, q.installation::text, q.scope_id::text, q.report_source::text,
              q.actor_user_id::text, q.model;
    IF FOUND THEN RETURN; END IF;
    RETURN QUERY SELECT true, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text
      FROM openmettle.gateway_requests q WHERE q.id = p_request AND q.bearer_hash = p_bearer_hash
       AND q.dispatched_at IS NOT NULL;
END
$$;
