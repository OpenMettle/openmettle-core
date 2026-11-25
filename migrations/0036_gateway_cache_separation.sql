-- ADR 0044 (V1-06 increment 5): gateway prefix-cache separation (`cache_salt`).
-- Adds `openmettle.gateway_dispatch_scoped(uuid, bytea)` returning the routing fields plus
-- `cache_owner` (NULL for personal scopes and effectively shared project conversations under
-- ADR 0027; `conversations.owner_user_id::text` for private/unshared project conversations) and
-- delegates 6-column `openmettle.gateway_dispatch(uuid, bytea)` to it so zero dispatch SQL is
-- duplicated.

CREATE FUNCTION openmettle.gateway_dispatch_scoped(p_request uuid, p_bearer_hash bytea)
RETURNS TABLE (
    replayed boolean,
    installation text,
    scope text,
    source text,
    principal text,
    model text,
    cache_owner text
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_run uuid;
    v_scope uuid;
    v_approval uuid;
    v_actor uuid;
    v_conversation uuid;
    v_collabs uuid[];
    v_locked_providers uuid[];
    v_locked_approvals uuid[];
    v_locked_observations uuid[];
    v_locked_rules uuid[];
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'gateway dispatch requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    SELECT q.run_id, q.scope_id, q.approval_id, q.actor_user_id, r.conversation_id
      INTO v_run, v_scope, v_approval, v_actor, v_conversation
      FROM openmettle.gateway_requests q
      JOIN openmettle.runs r ON r.id = q.run_id
     WHERE q.id = p_request
       AND q.bearer_hash = p_bearer_hash
       AND pg_has_role(session_user, 'openmettle_gateway', 'USAGE');
    IF NOT FOUND THEN RETURN; END IF;

    -- Acquire canonical shared authorization locks in ADR 0040 / ADR 0021 / migration 35 order
    -- (`account_admin_lock -> projects -> login_providers -> local_identity_approvals -> users ->
    -- membership_observations -> grant_mapping_rules -> runs -> gateway_requests`), covering both
    -- the acting principal and any direct-user share recipients on the conversation (whose share
    -- rows cannot change once `projects FOR SHARE` is held), and record the exact provider,
    -- approval, observation and rule IDs locked so rows inserted after the lock scan cannot be
    -- counted unlocked in the final `READ COMMITTED` `UPDATE`.
    PERFORM FROM openmettle.account_admin_lock FOR SHARE;
    PERFORM FROM openmettle.projects p WHERE p.scope_id = v_scope FOR SHARE;

    SELECT coalesce(array_agg(DISTINCT ga.grantee_user_id), ARRAY[]::uuid[])
      INTO v_collabs
      FROM openmettle.scopes sc
      JOIN openmettle.conversations c ON c.id = v_conversation AND c.scope_id = sc.id
      JOIN openmettle.grant_assignments ga
        ON ga.scope_id = sc.id
       AND ga.target_kind = 'conversation'
       AND ga.target_id = c.id
       AND ga.grantee_kind = 'user'
       AND ga.grantee_user_id <> c.owner_user_id
       AND ga.assignment_format = 'openmettle.resource-grant'
       AND ga.assignment_version = 1
       AND ga.assignment_key IN ('read', 'write')
       AND ga.source_kind = 'direct'
      JOIN openmettle.grant_changes gh
        ON gh.assignment_id = ga.id
       AND gh.revision = ga.last_revision
       AND gh.decision = 'grant'
     WHERE sc.id = v_scope
       AND sc.kind = 'project'
       AND sc.project_id IS NOT NULL;

    SELECT coalesce(array_agg(locked.id), ARRAY[]::uuid[])
      INTO v_locked_providers
      FROM (
          SELECT p.id
            FROM openmettle.login_providers p
           WHERE EXISTS (
               SELECT 1
                 FROM openmettle.local_identity_approvals a
                 JOIN openmettle.user_identities i ON i.id = a.identity_id
                WHERE a.provider_id = p.id
                  AND (a.id = v_approval OR i.user_id = ANY(v_collabs))
           )
           ORDER BY p.id
             FOR SHARE
      ) locked;
    SELECT coalesce(array_agg(locked.id), ARRAY[]::uuid[])
      INTO v_locked_approvals
      FROM (
          SELECT a.id
            FROM openmettle.local_identity_approvals a
           WHERE a.id = v_approval
              OR EXISTS (
                  SELECT 1
                    FROM openmettle.user_identities i
                   WHERE i.id = a.identity_id
                     AND i.user_id = ANY(v_collabs)
              )
           ORDER BY a.id
             FOR SHARE
      ) locked;
    PERFORM u.id
      FROM openmettle.users u
     WHERE u.id = v_actor OR u.id = ANY(v_collabs)
     ORDER BY u.id
       FOR SHARE;
    SELECT coalesce(array_agg(locked.approval_id), ARRAY[]::uuid[])
      INTO v_locked_observations
      FROM (
          SELECT m.approval_id
            FROM openmettle.membership_observations m
           WHERE m.approval_id = ANY(v_locked_approvals)
           ORDER BY m.approval_id
             FOR SHARE
      ) locked;
    SELECT coalesce(array_agg(locked.id), ARRAY[]::uuid[])
      INTO v_locked_rules
      FROM (
          SELECT mr.id
            FROM openmettle.grant_mapping_rules mr
           WHERE EXISTS (
               SELECT 1
                 FROM openmettle.membership_observations m
                WHERE m.approval_id = ANY(v_locked_observations)
                  AND m.rule_id = mr.id
           )
           ORDER BY mr.id
             FOR SHARE
      ) locked;
    PERFORM FROM openmettle.runs r WHERE r.id = v_run FOR SHARE;
    PERFORM FROM openmettle.gateway_requests q
      WHERE q.id = p_request
        AND q.bearer_hash = p_bearer_hash
        AND q.state = 'handed_off'
        AND pg_has_role(session_user, 'openmettle_gateway', 'USAGE')
        FOR NO KEY UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    RETURN QUERY
    WITH clock_raw AS MATERIALIZED (
        SELECT clock_timestamp() AS t
    ), clock AS MATERIALIZED (
        SELECT t, floor(extract(epoch FROM t) * 1000)::bigint AS ms
          FROM clock_raw
    )
    UPDATE openmettle.gateway_requests q
       SET dispatched_at = clock.t
      FROM clock
      JOIN openmettle.scopes sc ON sc.id = v_scope
      JOIN openmettle.runs r ON r.id = v_run AND r.scope_id = sc.id
      JOIN openmettle.conversations c ON c.id = r.conversation_id AND c.scope_id = sc.id
      CROSS JOIN LATERAL (
          SELECT sc.kind = 'project'
             AND sc.project_id IS NOT NULL
             AND EXISTS (
                 SELECT 1
                   FROM openmettle.grant_assignments ga
                   JOIN openmettle.grant_changes gh
                     ON gh.assignment_id = ga.id AND gh.revision = ga.last_revision
                  WHERE ga.scope_id = sc.id
                    AND ga.target_kind = 'conversation'
                    AND ga.target_id = c.id
                    AND ga.assignment_format = 'openmettle.resource-grant'
                    AND ga.assignment_version = 1
                    AND ga.assignment_key IN ('read', 'write')
                    AND ga.source_kind = 'direct'
                    AND gh.decision = 'grant'
                    AND (
                        ga.grantee_kind = 'project'
                        OR (ga.grantee_kind = 'local_group' AND EXISTS (
                            SELECT 1
                              FROM openmettle.local_groups lg
                              JOIN openmettle.grant_assignments pg
                                ON pg.scope_id = sc.id
                               AND pg.target_kind = 'project'
                               AND pg.target_id = sc.project_id
                               AND pg.grantee_kind = 'local_group'
                               AND pg.grantee_local_group_id = lg.id
                               AND pg.assignment_format = 'openmettle.project-role'
                               AND pg.assignment_version = 1
                               AND pg.assignment_key IN ('viewer', 'editor', 'owner')
                               AND pg.source_kind = 'direct'
                              JOIN openmettle.grant_changes pgh
                                ON pgh.assignment_id = pg.id AND pgh.revision = pg.last_revision
                             WHERE lg.id = ga.grantee_local_group_id
                               AND lg.disabled_at IS NULL
                               AND pgh.decision = 'grant'
                        ))
                        OR (ga.grantee_kind = 'oidc_group' AND EXISTS (
                            SELECT 1
                              FROM openmettle.grant_assignments pg
                              JOIN openmettle.grant_changes pgh
                                ON pgh.assignment_id = pg.id AND pgh.revision = pg.last_revision
                             WHERE pg.scope_id = sc.id
                               AND pg.target_kind = 'project'
                               AND pg.target_id = sc.project_id
                               AND pg.grantee_kind = 'oidc_group'
                               AND pg.grantee_oidc_group_id = ga.grantee_oidc_group_id
                               AND pg.assignment_format = 'openmettle.project-role'
                               AND pg.assignment_version = 1
                               AND pg.assignment_key IN ('viewer', 'editor', 'owner')
                               AND pg.source_kind = 'direct'
                               AND pgh.decision = 'grant'
                        ))
                        OR (ga.grantee_kind = 'user'
                            AND ga.grantee_user_id <> c.owner_user_id
                            AND ga.grantee_user_id = ANY(v_collabs)
                            AND EXISTS (
                                SELECT 1
                                  FROM openmettle.users gu
                                  JOIN openmettle.user_identities i2
                                    ON i2.user_id = gu.id
                                  JOIN openmettle.local_identity_approvals a2
                                    ON a2.identity_id = i2.id
                                   AND a2.id = ANY(v_locked_approvals)
                                  JOIN openmettle.login_providers p2
                                    ON p2.id = a2.provider_id
                                   AND p2.issuer = i2.issuer
                                   AND p2.id = ANY(v_locked_providers)
                                  JOIN LATERAL (
                                      SELECT pr2.epoch, pr2.revision
                                        FROM openmettle.login_provider_revisions pr2
                                       WHERE pr2.provider_id = p2.id
                                       ORDER BY pr2.epoch DESC
                                       LIMIT 1
                                  ) current_pr2 ON current_pr2.revision IS NOT NULL
                                 WHERE gu.id = ga.grantee_user_id
                                   AND gu.disabled_at IS NULL
                                   AND a2.active
                                   AND a2.expires_ms > clock.ms
                                   AND (
                                       EXISTS (
                                           SELECT 1
                                             FROM openmettle.grant_assignments pg2
                                             JOIN openmettle.grant_changes pgh2
                                               ON pgh2.assignment_id = pg2.id
                                              AND pgh2.revision = pg2.last_revision
                                            WHERE pg2.scope_id = sc.id
                                              AND pg2.target_kind = 'project'
                                              AND pg2.target_id = sc.project_id
                                              AND pg2.grantee_kind = 'user'
                                              AND pg2.grantee_user_id = gu.id
                                              AND pg2.assignment_format = 'openmettle.project-role'
                                              AND pg2.assignment_version = 1
                                              AND pg2.assignment_key IN ('viewer', 'editor', 'owner')
                                              AND pg2.source_kind = 'direct'
                                              AND pgh2.decision = 'grant'
                                       )
                                       OR EXISTS (
                                           SELECT 1
                                             FROM openmettle.local_group_memberships lm2
                                             JOIN openmettle.local_groups lg2
                                               ON lg2.id = lm2.group_id AND lg2.disabled_at IS NULL
                                             JOIN openmettle.grant_assignments pg2
                                               ON pg2.scope_id = sc.id
                                              AND pg2.target_kind = 'project'
                                              AND pg2.target_id = sc.project_id
                                              AND pg2.grantee_kind = 'local_group'
                                              AND pg2.grantee_local_group_id = lg2.id
                                              AND pg2.assignment_format = 'openmettle.project-role'
                                              AND pg2.assignment_version = 1
                                              AND pg2.assignment_key IN ('viewer', 'editor', 'owner')
                                              AND pg2.source_kind = 'direct'
                                             JOIN openmettle.grant_changes pgh2
                                               ON pgh2.assignment_id = pg2.id
                                              AND pgh2.revision = pg2.last_revision
                                            WHERE lm2.user_id = gu.id
                                              AND lm2.active
                                              AND pgh2.decision = 'grant'
                                       )
                                       OR EXISTS (
                                           SELECT 1
                                             FROM openmettle.membership_observations m2
                                             JOIN openmettle.grant_mapping_rules r2
                                               ON r2.id = m2.rule_id
                                              AND r2.id = ANY(v_locked_rules)
                                              AND r2.last_revision = m2.rule_revision
                                              AND r2.provider_config_id = a2.provider_id
                                              AND r2.issuer = i2.issuer
                                             JOIN openmettle.grant_mapping_revisions v2
                                               ON v2.rule_id = r2.id AND v2.revision = m2.rule_revision
                                             JOIN openmettle.grant_assignments mg2
                                               ON mg2.scope_id = m2.scope_id
                                              AND mg2.project_id = m2.project_id
                                              AND mg2.target_kind = 'project'
                                              AND mg2.grantee_kind = 'user'
                                              AND mg2.grantee_user_id = gu.id
                                              AND mg2.mapping_rule_id = r2.id
                                              AND mg2.assignment_key = a2.id::text
                                              AND mg2.assignment_format = 'openmettle.project-member'
                                              AND mg2.assignment_version = 1
                                              AND mg2.source_kind = 'mapped'
                                             JOIN openmettle.grant_changes mh2
                                               ON mh2.assignment_id = mg2.id
                                              AND mh2.revision = mg2.last_revision
                                            WHERE m2.approval_id = a2.id
                                              AND m2.approval_id = ANY(v_locked_observations)
                                              AND m2.enabled
                                              AND v2.enabled
                                              AND v2.binding_format = 'openmettle.project-member'
                                              AND v2.binding_version = 1
                                              AND v2.binding = convert_to(m2.project_id::text, 'UTF8')
                                              AND m2.issued_ms IS NOT NULL
                                              AND m2.epoch = current_pr2.epoch
                                              AND m2.approval_generation = a2.access_generation
                                              AND m2.user_generation = gu.session_generation
                                              AND (m2.observation).state = 'present'
                                              AND mh2.id = (m2.observation).change_id
                                              AND mh2.decision = 'grant'
                                              AND mh2.cycle_id = mh2.id
                                              AND mh2.mapping_revision = m2.rule_revision
                                              AND m2.issued_ms <= clock.ms
                                              AND least(m2.expires_ms,
                                                        m2.issued_ms + 1000::bigint * m2.max_age_seconds) > clock.ms
                                              AND (
                                                  (m2.scope_id = sc.id AND m2.project_id = sc.project_id)
                                                  OR (v2.selector_kind = 'group' AND EXISTS (
                                                      SELECT 1
                                                        FROM openmettle.grant_assignments pg2
                                                        JOIN openmettle.grant_changes pgh2
                                                          ON pgh2.assignment_id = pg2.id
                                                         AND pgh2.revision = pg2.last_revision
                                                       WHERE pg2.scope_id = sc.id
                                                         AND pg2.target_kind = 'project'
                                                         AND pg2.target_id = sc.project_id
                                                         AND pg2.grantee_kind = 'oidc_group'
                                                         AND pg2.grantee_oidc_group_id = v2.claim_value
                                                         AND pg2.assignment_format = 'openmettle.project-role'
                                                         AND pg2.assignment_version = 1
                                                         AND pg2.assignment_key IN ('viewer', 'editor', 'owner')
                                                         AND pg2.source_kind = 'direct'
                                                         AND pgh2.decision = 'grant'
                                                  ))
                                              )
                                       )
                                   )
                            ))
                    )
             ) AS effective
      ) share
     WHERE q.id = p_request
       AND q.bearer_hash = p_bearer_hash
       AND q.state = 'handed_off'
       AND q.dispatched_at IS NULL
       AND sc.id = q.scope_id
       AND r.id = q.run_id
       AND r.claim_token IS NOT NULL
       AND sha256(uuid_send(r.claim_token)) = q.claim_hash
       AND NOT EXISTS (
           SELECT FROM openmettle.gateway_settlements s
            WHERE s.request_id = q.id
       )
       AND openmettle.gateway_round_authority(q.id, r.claim_token, clock.t)
    RETURNING
        false,
        q.installation::text,
        q.scope_id::text,
        q.report_source::text,
        q.actor_user_id::text,
        q.model,
        CASE
            WHEN sc.kind = 'personal' OR share.effective THEN NULL::text
            ELSE c.owner_user_id::text
        END;

    IF FOUND THEN RETURN; END IF;
    RETURN QUERY
    SELECT true, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text
      FROM openmettle.gateway_requests q
     WHERE q.id = p_request
       AND q.bearer_hash = p_bearer_hash
       AND q.dispatched_at IS NOT NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.gateway_dispatch_scoped(uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.gateway_dispatch_scoped(uuid, bytea) TO openmettle_gateway;

-- Thin 6-column compatibility wrapper delegating to `gateway_dispatch_scoped`.
-- Signature, security and privileges are unchanged.
CREATE OR REPLACE FUNCTION openmettle.gateway_dispatch(p_request uuid, p_bearer_hash bytea)
RETURNS TABLE (replayed boolean, installation text, scope text, source text, principal text, model text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    RETURN QUERY
    SELECT d.replayed, d.installation, d.scope, d.source, d.principal, d.model
      FROM openmettle.gateway_dispatch_scoped(p_request, p_bearer_hash) d;
END
$$;
