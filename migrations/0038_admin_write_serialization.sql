-- V1-05 migration 38 (issue #160): serialize retention policy changes with approval withdrawal,
-- provider retirement, user disablement and post-lock approval expiry, and clean up the redundant
-- early unlocked administrator check in quota_lock_override. Released migrations are immutable.
-- Runs once per release as openmettle_owner in one transaction with search_path
-- pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Canonical lock order (ADR 0027):
--   account_admin_lock -> projects -> login_providers -> local_identity_approvals ->
--   users (ascending id when locking two rows) -> storage_volume_control -> run_dispatch_lock ->
--   storage_accounts | quota_budgets | retention_policy -> runs.
--
-- Compatibility (ADR 0003):
-- - openmettle.quota_lock_override keeps its signature, invoker security, search_path and
--   privileges, so previous-release API binaries calling quota_upsert_scope_override and
--   quota_revoke_scope_override continue working unchanged.
-- - openmettle.retention_set_grace(uuid, integer, text, text) has no route or runtime caller in
--   any prior release; it is replaced by the 5-argument form requiring the caller's exact
--   local_identity_approvals UUID (p_approval).

CREATE OR REPLACE FUNCTION openmettle.quota_lock_override(p_scope uuid,p_actor uuid,p_resource text)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE sc openmettle.scopes%ROWTYPE;
BEGIN
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR NO KEY UPDATE;
    SELECT * INTO sc FROM openmettle.scopes WHERE id=p_scope;
    -- sessions::disable_user locks only the user row: hold the actor's row FOR SHARE (or FOR NO
    -- KEY UPDATE when targeting the actor's own personal scope) in canonical ascending users.id
    -- order, and recheck under it. Non-admin callers still receive 42501 before missing-scope
    -- P0002.
    IF FOUND AND sc.kind='project' THEN
        PERFORM FROM openmettle.projects WHERE id=sc.project_id FOR NO KEY UPDATE;
        PERFORM FROM openmettle.users WHERE id=p_actor FOR SHARE;
    ELSIF FOUND THEN
        IF sc.personal_user_id=p_actor THEN
            PERFORM FROM openmettle.users WHERE id=p_actor FOR NO KEY UPDATE;
        ELSIF sc.personal_user_id<p_actor THEN
            PERFORM FROM openmettle.users WHERE id=sc.personal_user_id FOR NO KEY UPDATE;
            PERFORM FROM openmettle.users WHERE id=p_actor FOR SHARE;
        ELSE
            PERFORM FROM openmettle.users WHERE id=p_actor FOR SHARE;
            PERFORM FROM openmettle.users WHERE id=sc.personal_user_id FOR NO KEY UPDATE;
        END IF;
    ELSE
        PERFORM FROM openmettle.users WHERE id=p_actor FOR SHARE;
    END IF;
    PERFORM FROM openmettle.account_admins a JOIN openmettle.users u ON u.id=a.user_id
     WHERE a.user_id=p_actor AND a.active AND u.disabled_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE='42501';
    END IF;
    IF sc.id IS NULL THEN
        RAISE EXCEPTION 'scope not found' USING ERRCODE='P0002';
    END IF;
    IF p_resource IN ('executing_runs_per_actor','executing_runs_per_scope') THEN
        PERFORM FROM openmettle.run_dispatch_lock WHERE id FOR NO KEY UPDATE;
    END IF;
    IF p_resource='storage_bytes' THEN
        INSERT INTO openmettle.storage_accounts (scope_id) VALUES(p_scope) ON CONFLICT DO NOTHING;
        PERFORM FROM openmettle.storage_accounts WHERE scope_id=p_scope FOR UPDATE;
    ELSE
        PERFORM FROM openmettle.quota_budgets WHERE scope_id=p_scope AND resource_kind=p_resource
            ORDER BY window_start,id FOR NO KEY UPDATE;
    END IF;
    RETURN sc.kind;
END
$$;
REVOKE ALL ON FUNCTION openmettle.quota_lock_override(uuid,uuid,text) FROM PUBLIC;

-- Replace the unexposed 4-argument retention_set_grace with the approval-bound 5-argument form.
-- Locks account_admin_lock -> login_providers -> local_identity_approvals -> users ->
-- retention_policy, checks authority at post-lock clock_timestamp(), and re-verifies approval
-- expiry after waiting on retention_policy.
DROP FUNCTION openmettle.retention_set_grace(uuid, integer, text, text);

CREATE FUNCTION openmettle.retention_set_grace(
    p_actor uuid,
    p_approval uuid,
    p_grace_seconds integer,
    p_reason text,
    p_request_key text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    prior openmettle.retention_policy%ROWTYPE;
    rev bigint;
    now_ms bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'retention policy changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR UPDATE;
    PERFORM FROM openmettle.login_providers p
     WHERE p.id = (SELECT a.provider_id FROM openmettle.local_identity_approvals a
                    WHERE a.id = p_approval)
       FOR SHARE;
    PERFORM FROM openmettle.local_identity_approvals a
     WHERE a.id = p_approval
       FOR SHARE;
    PERFORM FROM openmettle.users u
     WHERE u.id = p_actor
       FOR SHARE;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    PERFORM FROM openmettle.users u
      JOIN openmettle.scopes sc ON sc.personal_user_id = u.id AND sc.kind = 'personal'
      JOIN openmettle.account_admins adm ON adm.user_id = u.id AND adm.active
      JOIN openmettle.local_identity_approvals a ON a.id = p_approval
      JOIN openmettle.user_identities i ON i.id = a.identity_id AND i.user_id = u.id
      JOIN openmettle.login_providers p ON p.id = a.provider_id AND p.issuer = i.issuer
      JOIN LATERAL (
          SELECT pr.revision
            FROM openmettle.login_provider_revisions pr
           WHERE pr.provider_id = p.id
           ORDER BY pr.epoch DESC
           LIMIT 1
      ) e ON e.revision IS NOT NULL
     WHERE u.id = p_actor
       AND u.disabled_at IS NULL
       AND a.active
       AND a.expires_ms > now_ms;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO STRICT prior FROM openmettle.retention_policy WHERE id FOR UPDATE;
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF NOT EXISTS (
        SELECT FROM openmettle.local_identity_approvals a
         WHERE a.id = p_approval AND a.active AND a.expires_ms > now_ms
    ) THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE = '42501';
    END IF;
    UPDATE openmettle.retention_policy SET grace_seconds = p_grace_seconds WHERE id
        RETURNING revision INTO STRICT rev;
    INSERT INTO openmettle.authorization_audit
        (actor_user_id, action, target_kind, target_id, request_key, reason, details)
    VALUES (p_actor, 'retention.policy_update', 'retention_policy', 'instance', p_request_key, p_reason,
            jsonb_build_object('old_grace_seconds', prior.grace_seconds,
                               'new_grace_seconds', p_grace_seconds, 'revision', rev));
    RETURN rev;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_set_grace(uuid, uuid, integer, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.retention_set_grace(uuid, uuid, integer, text, text) TO openmettle_api;
