-- V1-05 migration 30: quota overrides serialize with disabling the acting administrator.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- quota_lock_override (migration 24) checked the actor without a row lock, and
-- sessions::disable_user locks only the user row, not account_admin_lock. An override decided
-- while such a disable was in flight could commit after it. This replaces only that function,
-- with the same signature, owner, invoker security, search_path and privileges; its callers
-- quota_upsert_scope_override and quota_revoke_scope_override (migration 26) are unchanged.
--
-- Lock order of an override write: account_admin_lock -> storage_volume_control FOR SHARE (the
-- caller) -> run_dispatch_lock (executing-run resources) -> projects | the personal owner's
-- users row -> the actor's users row FOR SHARE (new) -> storage_accounts | quota_budgets. The
-- actor's row follows the scope row as in run admission (project, then actor, without
-- account_admin_lock) and the gateway handoff prefixes (account_admin_lock -> projects ->
-- approvals -> users), so no wait cycle is added; sessions::disable_user waits on nothing while
-- it holds the user row.

CREATE OR REPLACE FUNCTION openmettle.quota_lock_override(p_scope uuid,p_actor uuid,p_resource text)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE sc openmettle.scopes%ROWTYPE;
BEGIN
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR NO KEY UPDATE;
    IF NOT EXISTS (SELECT FROM openmettle.account_admins a JOIN openmettle.users u ON u.id=a.user_id
        WHERE a.user_id=p_actor AND a.active AND u.disabled_at IS NULL) THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE='42501';
    END IF;
    IF p_resource IN ('executing_runs_per_actor','executing_runs_per_scope') THEN
        PERFORM FROM openmettle.run_dispatch_lock WHERE id FOR NO KEY UPDATE;
    END IF;
    SELECT * INTO STRICT sc FROM openmettle.scopes WHERE id=p_scope;
    IF sc.kind='project' THEN PERFORM FROM openmettle.projects WHERE id=sc.project_id FOR NO KEY UPDATE;
    ELSE PERFORM FROM openmettle.users WHERE id=sc.personal_user_id FOR NO KEY UPDATE; END IF;
    -- sessions::disable_user locks only the user row: hold the actor's row FOR SHARE, after the
    -- scope locks, and recheck under it, so a disable in flight is waited for and seen, and a
    -- later one waits for this change to commit.
    PERFORM FROM openmettle.account_admins a JOIN openmettle.users u ON u.id=a.user_id
     WHERE a.user_id=p_actor AND a.active AND u.disabled_at IS NULL FOR SHARE OF u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE='42501';
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
