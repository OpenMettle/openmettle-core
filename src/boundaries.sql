-- Read-only database boundary check (ADR 0003). openmettle-migrate runs it before SQLx creates
-- any schema or history object, and again after migrations. It returns one row per violation.
-- $1: the highest successfully applied migration version (0 before migration 1). Migration 1
-- revokes the PUBLIC database/public-schema defaults, which are tolerated only before that.
-- Version 23 adds gateway reconciliation, request holds and one-call inference grants.
-- Each version's explicit grants are allowed only once that version is recorded as applied.
-- Principals are openmettle_api, openmettle_issuance, openmettle_worker, openmettle_gateway, every role that is
-- directly or indirectly a member of one of them (for example their login roles), and PUBLIC.
-- They may hold only the privileges in `contract`, CONNECT on the database and USAGE on schema
-- openmettle. openmettle_issuance (ADR 0030) is required from version 18; before that an
-- existing one has an empty contract, and version 18 moves the session issuance writes to it.
WITH RECURSIVE
privilege_roles AS (
    SELECT oid FROM pg_roles
    WHERE rolname IN ('openmettle_api', 'openmettle_issuance', 'openmettle_worker', 'openmettle_gateway')
),
owner_role AS (
    SELECT oid FROM pg_roles WHERE rolname = 'openmettle_owner'
),
application (oid, base) AS (
    SELECT oid, oid FROM privilege_roles
    UNION
    SELECT m.member, a.base FROM pg_auth_members AS m JOIN application AS a ON m.roleid = a.oid
),
principals (oid) AS (
    SELECT oid FROM application
    UNION
    SELECT 0::oid
),
effect_columns (relation, attribute, role, privilege) AS (
    SELECT relation, attribute, role, privilege FROM (VALUES
        ('runs','openmettle_api','INSERT',ARRAY['execution_mode','originating_session_id','admission_evidence']),
        ('runs','openmettle_worker','UPDATE',ARRAY['approval_wait_id']),
        ('operations','openmettle_worker','INSERT',ARRAY['approval_id']),
        ('run_approvals','openmettle_worker','INSERT',ARRAY['scope_id','run_id','actor_user_id','logical_key',
            'tool_id','tool_version','canonical_arguments','destination','authority_evidence','binding_digest',
            'approval_expires_at','resume_execution_expires_at']),
        ('run_approval_decisions','openmettle_api','INSERT',ARRAY['approval_id','scope_id','run_id','actor_user_id',
            'deciding_session_id','binding_digest','decision','request_key']),
        ('local_sessions','openmettle_worker','SELECT',ARRAY['id','user_id','approval_id','provider_id','identity_id',
            'issued_client','issued_epoch','provider_generation','approval_generation','user_generation',
            'created_ms','expires_ms','revoked'])
    ) AS t(relation,role,privilege,columns), unnest(columns) attribute WHERE $1 >= 22
    UNION ALL SELECT 'operations',attribute,'openmettle_worker',privilege FROM (VALUES
        ('dispatched_attempts','INSERT'),('dispatched_attempts','UPDATE'),('effective_expires_us','INSERT')
    ) t(attribute,privilege) WHERE $1 >= 25
),
quota_columns (relation,attribute,role,privilege) AS (
    SELECT 'storage_reservations', attribute, role, privilege FROM (VALUES
        ('INSERT',ARRAY['lease_expires_at','stage_claimed']),
        ('UPDATE',ARRAY['lease_expires_at','adoption_unverified','stage_claimed','payload_ino',
            'publish_pending','reclaim_state','reclaim_claim_token','reclaim_lease_until'])) t(privilege,columns),
        unnest(columns) attribute, unnest(ARRAY['openmettle_api','openmettle_worker']) role WHERE $1 >= 24
    UNION ALL SELECT 'artifact_revisions','purge_stage','openmettle_worker','UPDATE' WHERE $1 >= 24
),
quota_tables (relation,role,privilege) AS (
    SELECT relation,role,'SELECT' FROM unnest(ARRAY['quota_defaults','quota_enforcement','quota_overrides',
        'quota_reservations','quota_budgets','quota_reservation_charges','quota_reconciliations','quota_warning_events',
        'storage_volume_control']) relation, unnest(ARRAY['openmettle_api','openmettle_worker','openmettle_gateway']) role
    WHERE $1 >= 24 AND (relation<>'storage_volume_control' OR role<>'openmettle_gateway')
),
gateway_columns (relation,attribute,role,privilege) AS (
    SELECT relation, attribute, role, privilege FROM (VALUES
        ('account_admin_lock','openmettle_gateway','UPDATE',ARRAY['lock_guard']),
        ('projects','openmettle_gateway','UPDATE',ARRAY['lock_guard']),
        ('users','openmettle_gateway','UPDATE',ARRAY['lock_guard']),
        ('login_providers','openmettle_gateway','UPDATE',ARRAY['lock_guard']),
        ('local_identity_approvals','openmettle_gateway','UPDATE',ARRAY['lock_guard']),
        ('gateway_nonces','openmettle_gateway','INSERT',ARRAY['key_fingerprint','nonce']),
        ('gateway_bindings','openmettle_gateway','INSERT',ARRAY['installation','user_id','principal','budget']),
        ('gateway_bindings','openmettle_gateway','UPDATE',ARRAY['desired_revision','observed_revision','state','active_generation']),
        ('gateway_generations','openmettle_gateway','INSERT',ARRAY['binding_id','generation','remote_key','expires_at','key_id','key_fingerprint','nonce','ciphertext']),
        ('gateway_generations','openmettle_gateway','UPDATE',ARRAY['expires_at','key_id','key_fingerprint','nonce','ciphertext']),
        ('gateway_policy','openmettle_gateway','INSERT',ARRAY['binding_id','revision','scope_id','approval_id','model','report_source','provider_generation','approval_generation','user_generation','grant_cycle','capabilities']),
        ('gateway_intents','openmettle_gateway','INSERT',ARRAY['binding_id','desired_revision','generation','action','expected_revision','parameters']),
        ('gateway_intents','openmettle_gateway','UPDATE',ARRAY['claim','due_at','complete']),
        ('gateway_audit','openmettle_gateway','INSERT',ARRAY['binding_id','desired_revision','operation_id','step','outcome','remote_handle','remote_revision']),
        ('gateway_usage_reports','openmettle_gateway','INSERT',ARRAY['request_id','source','report_id','revision','final','prompt_tokens','completion_tokens','reasoning_tokens','reasoning_included','cost','unit']),
        ('gateway_settlements','openmettle_gateway','INSERT',ARRAY['request_id','revision','final','measured','outstanding']),
        ('gateway_settlements','openmettle_gateway','UPDATE',ARRAY['revision','final','measured','outstanding']),
        ('gateway_reservations','openmettle_api','INSERT',ARRAY['id','scope_id','actor_user_id','approval_id','run_id','units']),
        ('gateway_requests','openmettle_api','INSERT',ARRAY['id','reservation_id','scope_id','actor_user_id','approval_id','installation','model','units','dispatch_hash','session_id']),
        ('gateway_requests','openmettle_worker','INSERT',ARRAY['id','reservation_id','scope_id','actor_user_id','approval_id','installation','model','units','dispatch_hash','run_id','round'])
    ) AS t(relation,role,privilege,columns), unnest(columns) attribute WHERE $1 >= 23
),
runtime_functions(signature,definer,roles) AS (
    SELECT * FROM (VALUES
        ('openmettle.record_accepted_gateway_settlement()',true,ARRAY[]::text[]),
        ('openmettle.quota_take_warnings(integer)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.enforce_quota_reservation_gateway_binding()',true,ARRAY[]::text[]),
        ('openmettle.enforce_cost_denomination_immutability()',false,ARRAY[]::text[]),
        ('openmettle.enforce_gateway_report_cost_unit()',true,ARRAY[]::text[]),
        ('openmettle.enforce_quota_enforcement_write_once()',false,ARRAY[]::text[]),
        ('openmettle.enforce_gateway_handoff_holds()',true,ARRAY[]::text[]),
        ('openmettle.quota_lock_gateway_request_for_settlement(uuid)',true,ARRAY['openmettle_gateway']::text[]),
        ('openmettle.enforce_tool_spill_reservation_binding()',false,ARRAY[]::text[]),
        ('openmettle.storage_lock_pinned_volume()',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.storage_pin_volume_id(uuid)',true,ARRAY['openmettle_api']::text[]),
        ('openmettle.enforce_runtime_storage_volume_pinned()',false,ARRAY[]::text[]),
        ('openmettle.enforce_storage_reservation_monotonic_guards()',false,ARRAY[]::text[]),
        ('openmettle.enforce_storage_override()',false,ARRAY[]::text[]),
        ('openmettle.quota_limit(uuid,text,text)',false,ARRAY[]::text[]),
        ('openmettle.quota_warn(text,uuid,text,timestamptz,numeric,numeric,bigint,smallint,smallint,bigint,bigint)',false,ARRAY[]::text[]),
        ('openmettle.quota_reserve(uuid,uuid,text,bigint,text,uuid,uuid,bytea,timestamptz)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_cost_ceiling(uuid,uuid)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_allocate_round(uuid,bytea,uuid,text,bigint)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_commit_handoff(uuid,bytea)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_gateway_fold(uuid,text,bigint,bigint)',false,ARRAY[]::text[]),
        ('openmettle.quota_adjust(uuid,numeric,numeric)',false,ARRAY[]::text[]),
        ('openmettle.quota_settle_gateway_usage(uuid,uuid,uuid,bigint)',true,ARRAY['openmettle_gateway']::text[]),
        ('openmettle.quota_unwind_hold(uuid,text)',false,ARRAY[]::text[]),
        ('openmettle.quota_unwind_request(uuid,text)',false,ARRAY[]::text[]),
        ('openmettle.quota_recover_lost_handoff(uuid,bytea,uuid,uuid,uuid)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_unwind_superseded_round(uuid,uuid,uuid,integer)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_release_orphan_gateway_requests(interval,timestamptz,uuid,timestamptz,uuid,integer)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_renew_lease(uuid,uuid,uuid,timestamptz)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_follow_run_deadline()',true,ARRAY[]::text[]),
        ('openmettle.quota_release_unsent(uuid,bytea,boolean)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_commit_device_handoff(uuid,uuid,uuid,uuid,uuid)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_lock_override(uuid,uuid,text)',false,ARRAY[]::text[]),
        ('openmettle.quota_record_storage_warning(uuid,bigint)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_verify_accounting_drift()',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_release_device_slot(uuid,uuid)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_commit_handoff(uuid,uuid)',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_bump_config_revision()',false,ARRAY[]::text[])) AS f WHERE $1 >= 24
    UNION ALL SELECT * FROM (VALUES
        ('openmettle.quota_ensure_legacy_run_holds(uuid,uuid,uuid)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_upsert_scope_override(uuid,uuid,text,bigint,timestamptz,text)',true,ARRAY['openmettle_api']::text[]),
        ('openmettle.quota_revoke_scope_override(uuid,uuid,text,text)',true,ARRAY['openmettle_api']::text[])) AS f WHERE $1 BETWEEN 24 AND 25
    UNION ALL SELECT signature,definer,ARRAY[]::text[] FROM (VALUES
        ('openmettle.guard_operation_dispatch()',false),
        ('openmettle.fail_abandoned_reads(uuid,uuid)',false),
        ('openmettle.resolve_abandoned_repeatable_reads()',true)
    ) t(signature,definer) WHERE $1 >= 25
    UNION ALL SELECT * FROM (VALUES
        ('openmettle.storage_lock_not_adopting()',true,ARRAY['openmettle_api']::text[]),
        ('openmettle.quota_ensure_legacy_run_holds(uuid,uuid,uuid,bigint,bigint,boolean,boolean)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_run_round_cost_slice(uuid,uuid,uuid)',true,ARRAY['openmettle_worker']::text[]),
        ('openmettle.quota_release_terminal_runs(uuid[])',true,ARRAY['openmettle_api','openmettle_worker']::text[]),
        ('openmettle.quota_upsert_scope_override(uuid,uuid,text,bigint,timestamptz,text,text,jsonb)',true,ARRAY['openmettle_api']::text[]),
        ('openmettle.quota_revoke_scope_override(uuid,uuid,text,text,text,jsonb)',true,ARRAY['openmettle_api']::text[])) AS f WHERE $1 >= 26
),
gateway_functions (signature,definer,inference) AS (
    SELECT * FROM (VALUES ('openmettle.gateway_allocate()',true,false), ('openmettle.gateway_run_hold()',true,false),
        ('openmettle.gateway_advance_settlement()',false,false),
        ('openmettle.gateway_mark_settled_final()',true,false),
        ('openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid)',true,true),
        ('openmettle.gateway_release(uuid,bytea)',true,true)) AS f WHERE $1 >= 23
),
contract (relation, role, privilege) AS (
    VALUES
        ('users', 'openmettle_api', 'SELECT'),
        ('users', 'openmettle_api', 'INSERT'),
        ('user_identities', 'openmettle_api', 'SELECT'),
        ('user_identities', 'openmettle_api', 'INSERT'),
        ('scopes', 'openmettle_api', 'SELECT'),
        ('scopes', 'openmettle_api', 'INSERT'),
        ('projects', 'openmettle_api', 'SELECT'),
        ('projects', 'openmettle_api', 'INSERT'),
        ('conversations', 'openmettle_api', 'SELECT'),
        ('conversations', 'openmettle_api', 'INSERT'),
        ('messages', 'openmettle_api', 'SELECT'),
        ('messages', 'openmettle_api', 'INSERT'),
        ('users', 'openmettle_worker', 'SELECT'),
        ('scopes', 'openmettle_worker', 'SELECT'),
        ('projects', 'openmettle_worker', 'SELECT'),
        ('conversations', 'openmettle_worker', 'SELECT'),
        ('messages', 'openmettle_worker', 'SELECT'),
        ('messages', 'openmettle_worker', 'INSERT')
    UNION ALL
    SELECT * FROM (VALUES
        ('conversation_branches', 'openmettle_api', 'SELECT'),
        ('conversation_branches', 'openmettle_api', 'INSERT'),
        ('conversation_branches', 'openmettle_worker', 'SELECT'),
        ('runs', 'openmettle_api', 'SELECT'),
        ('runs', 'openmettle_worker', 'SELECT'),
        ('run_events', 'openmettle_api', 'SELECT'), ('run_events', 'openmettle_api', 'INSERT'),
        ('run_events', 'openmettle_worker', 'SELECT'), ('run_events', 'openmettle_worker', 'INSERT'),
        ('operations', 'openmettle_api', 'SELECT'),
        ('operations', 'openmettle_worker', 'SELECT')
    ) AS durable(relation, role, privilege) WHERE $1 >= 3
    UNION ALL
    SELECT relation, role, privilege FROM (VALUES
        ('storage_instance'), ('storage_accounts'), ('artifacts'), ('storage_reservations'),
        ('artifact_revisions')
    ) AS storage(relation),
    (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role),
    (VALUES ('SELECT')) AS p(privilege)
    WHERE $1 >= 4
    UNION ALL
    SELECT relation, role, 'SELECT' FROM (VALUES
        ('grant_mapping_rules'), ('grant_mapping_revisions'),
        ('grant_assignments'), ('grant_changes')
    ) AS g(relation), (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role)
    WHERE $1 >= 5
    UNION ALL
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('login_transactions'), ('login_nonce_reservations')
    ) AS login(relation) WHERE $1 >= 6
    UNION ALL
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('login_providers'), ('login_provider_revisions')
    ) AS authority(relation) WHERE $1 >= 7
    UNION ALL
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('local_identity_approvals'), ('local_sessions')
    ) AS sessions(relation) WHERE $1 >= 8
    UNION ALL
    -- ADR 0030: the reads of the session issuance transaction.
    SELECT relation, 'openmettle_issuance', 'SELECT' FROM (VALUES
        ('login_transactions'), ('login_providers'), ('login_provider_revisions'),
        ('user_identities'), ('users'), ('scopes'), ('local_identity_approvals'),
        ('local_sessions'), ('membership_observations'), ('grant_mapping_rules'),
        ('grant_mapping_revisions'), ('grant_assignments'), ('grant_changes')
    ) AS issuance(relation) WHERE $1 >= 18
    UNION ALL
    SELECT 'login_admission', 'openmettle_api', 'SELECT' WHERE $1 >= 9
    UNION ALL
    SELECT 'membership_observations', 'openmettle_api', 'SELECT' WHERE $1 >= 11
    UNION ALL
    SELECT 'native_handoffs', 'openmettle_api', 'SELECT' WHERE $1 >= 14
    UNION ALL
    -- V1-05 (ADR 0027): authorization state for the API, recheck reads for the worker.
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('project_settings'), ('local_groups'), ('local_group_memberships'),
        ('account_admin_lock'), ('account_admins'), ('platform_capability_denies'),
        ('user_capability_denies'), ('user_capability_grants'), ('authorization_audit')
    ) AS authz(relation) WHERE $1 >= 15
    UNION ALL
    SELECT relation, 'openmettle_worker', 'SELECT' FROM (VALUES
        ('membership_observations'), ('local_identity_approvals'), ('login_providers'),
        ('login_provider_revisions'), ('user_identities'), ('local_groups'),
        ('local_group_memberships'), ('platform_capability_denies'),
        ('user_capability_denies'), ('user_capability_grants')
    ) AS recheck(relation) WHERE $1 >= 15
    UNION ALL
    -- V1-10 (ADR 0032): the claim's dispatch lock row.
    SELECT 'run_dispatch_lock', 'openmettle_worker', 'SELECT' WHERE $1 >= 19
    UNION ALL
    SELECT relation, role, 'SELECT' FROM (VALUES ('branch_heads'), ('message_parts')) AS g(relation),
        (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role) WHERE $1 >= 21
    UNION ALL
    SELECT 'message_turns', 'openmettle_worker', 'SELECT' WHERE $1 >= 21
    UNION ALL
    SELECT relation, role, 'SELECT' FROM (VALUES ('run_approvals'), ('run_approval_decisions')) AS g(relation),
        (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role) WHERE $1 >= 22

    UNION ALL
    SELECT unnest(ARRAY[
        'gateway_bindings','gateway_generations','gateway_policy','gateway_intents',
        'gateway_audit','gateway_reservations','gateway_requests','gateway_usage_reports',
        'gateway_settlements','account_admin_lock','projects','users',
        'user_identities','scopes','local_identity_approvals','login_providers',
        'login_provider_revisions','grant_assignments','grant_changes','local_groups',
        'local_group_memberships','membership_observations','grant_mapping_rules','grant_mapping_revisions',
        'project_settings','platform_capability_denies','user_capability_denies','user_capability_grants']), 'openmettle_gateway', 'SELECT' WHERE $1 >= 23
    UNION ALL SELECT * FROM quota_tables
),
column_contract (relation, attribute, role, privilege) AS (
    VALUES ('users', 'disabled_at', 'openmettle_api', 'UPDATE')
    UNION ALL
    SELECT relation, attribute, role, privilege FROM (VALUES
        ('login_providers','lock_guard','UPDATE'),
        ('local_identity_approvals','lock_guard','UPDATE')
    ) AS locks(relation,attribute,privilege),
    (VALUES ('openmettle_api', 8), ('openmettle_issuance', 18)) AS r(role, since)
    WHERE $1 >= r.since
    UNION ALL
    SELECT relation, attribute, 'openmettle_api', privilege FROM (VALUES
        ('users','session_generation','UPDATE'),
        ('local_sessions','revoked','UPDATE')
    ) AS sessions(relation,attribute,privilege) WHERE $1 >= 8
    UNION ALL
    -- Writes only session issuance performs: the API's before version 18, then only the
    -- issuance role's (ADR 0030). Native delivery rows are written once by issuance.
    SELECT relation, attribute,
           CASE WHEN $1 < 18 THEN 'openmettle_api' ELSE 'openmettle_issuance' END, privilege
    FROM (VALUES
        ('login_transactions','session_issued','UPDATE', 8),
        ('local_sessions','id','INSERT', 8), ('local_sessions','secret_hash','INSERT', 8),
        ('local_sessions','login_id','INSERT', 8), ('local_sessions','provider_id','INSERT', 8),
        ('local_sessions','identity_id','INSERT', 8), ('local_sessions','approval_id','INSERT', 8),
        ('local_sessions','user_id','INSERT', 8), ('local_sessions','issued_client','INSERT', 8),
        ('local_sessions','issued_epoch','INSERT', 8), ('local_sessions','issued_revision','INSERT', 8),
        ('local_sessions','provider_generation','INSERT', 8),
        ('local_sessions','approval_generation','INSERT', 8),
        ('local_sessions','user_generation','INSERT', 8),
        ('local_sessions','created_ms','INSERT', 8), ('local_sessions','expires_ms','INSERT', 8),
        ('membership_observations','issued_ms','UPDATE', 11),
        ('membership_observations','expires_ms','UPDATE', 11),
        ('membership_observations','observation','UPDATE', 11),
        ('membership_observations','epoch','UPDATE', 11),
        ('membership_observations','approval_generation','UPDATE', 11),
        ('membership_observations','user_generation','UPDATE', 11),
        ('native_handoffs','session_id','INSERT', 14), ('native_handoffs','code_hash','INSERT', 14),
        ('native_handoffs','registration','INSERT', 14), ('native_handoffs','audience','INSERT', 14),
        ('native_handoffs','challenge','INSERT', 14), ('native_handoffs','sealed','INSERT', 14),
        ('native_handoffs','expires_ms','INSERT', 14)
    ) AS issuance(relation,attribute,privilege,since) WHERE $1 >= since
    UNION ALL
    SELECT 'branch_heads', attribute, 'openmettle_api', 'INSERT' FROM unnest(ARRAY[
        'scope_id','conversation_id','branch_id','parent_branch_id','head_message_id']) attribute WHERE $1 >= 21
    UNION ALL
    SELECT 'branch_heads', 'head_message_id', role, 'UPDATE' FROM
        (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role) WHERE $1 >= 21
    UNION ALL
    SELECT 'message_parts', attribute, role, 'INSERT' FROM unnest(ARRAY[
        'scope_id','conversation_id','message_id','ordinal','kind','text_value','artifact_revision_id']) attribute,
        (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role) WHERE $1 >= 21
    UNION ALL
    SELECT 'message_turns', attribute, role, privilege FROM (VALUES
        ('openmettle_api', 'SELECT', ARRAY['scope_id','conversation_id','message_id','author_user_id',
            'run_id','reasoning_bytes','input_count','output_count']),
        ('openmettle_api', 'INSERT', ARRAY['scope_id','conversation_id','message_id','author_user_id']),
        ('openmettle_worker', 'INSERT', ARRAY['scope_id','conversation_id','message_id','run_id',
            'reasoning_blocks','reasoning_bytes','input_count','output_count'])
    ) AS t(role,privilege,columns), unnest(columns) attribute WHERE $1 >= 21
    UNION ALL
    SELECT * FROM quota_columns
    UNION ALL
    SELECT * FROM gateway_columns
    UNION ALL
    SELECT * FROM effect_columns
    UNION ALL
    -- Migration 18's inert guards for the issuance role's row locks.
    SELECT relation, 'lock_guard', 'openmettle_issuance', 'UPDATE' FROM (VALUES
        ('users'), ('grant_mapping_rules')
    ) AS guards(relation) WHERE $1 >= 18
    UNION ALL
    SELECT 'login_admission', 'lock_guard', 'openmettle_api', 'UPDATE' WHERE $1 >= 9
    UNION ALL
    -- A native delivery row's envelope is cleared once by the token exchange.
    SELECT 'native_handoffs', 'sealed', 'openmettle_api', 'UPDATE' WHERE $1 >= 14
    UNION ALL
    -- V1-05: inserts never name generated IDs, times, revisions or audit operator actors;
    -- updates never change an ownership or key column.
    SELECT relation, attribute, 'openmettle_api', privilege FROM (VALUES
        ('project_settings','project_id','INSERT'), ('project_settings','scope_id','INSERT'),
        ('project_settings','name','INSERT'), ('project_settings','instructions','INSERT'),
        ('project_settings','defaults','INSERT'), ('project_settings','updated_by_user_id','INSERT'),
        ('project_settings','name','UPDATE'), ('project_settings','instructions','UPDATE'),
        ('project_settings','defaults','UPDATE'), ('project_settings','revision','UPDATE'),
        ('project_settings','archived_at','UPDATE'), ('project_settings','deleted_at','UPDATE'),
        ('project_settings','updated_at','UPDATE'), ('project_settings','updated_by_user_id','UPDATE'),
        ('local_groups','id','INSERT'), ('local_groups','name','INSERT'),
        ('local_groups','created_by_user_id','INSERT'), ('local_groups','updated_by_user_id','INSERT'),
        ('local_groups','name','UPDATE'), ('local_groups','revision','UPDATE'),
        ('local_groups','disabled_at','UPDATE'), ('local_groups','updated_at','UPDATE'),
        ('local_groups','updated_by_user_id','UPDATE'),
        ('local_group_memberships','group_id','INSERT'), ('local_group_memberships','user_id','INSERT'),
        ('local_group_memberships','active','INSERT'),
        ('local_group_memberships','updated_by_user_id','INSERT'),
        ('local_group_memberships','active','UPDATE'), ('local_group_memberships','revision','UPDATE'),
        ('local_group_memberships','updated_at','UPDATE'),
        ('local_group_memberships','updated_by_user_id','UPDATE'),
        ('account_admin_lock','lock_guard','UPDATE'),
        ('account_admins','user_id','INSERT'), ('account_admins','active','INSERT'),
        ('account_admins','updated_by_user_id','INSERT'),
        ('account_admins','active','UPDATE'), ('account_admins','revision','UPDATE'),
        ('account_admins','updated_at','UPDATE'), ('account_admins','updated_by_user_id','UPDATE'),
        ('platform_capability_denies','capability','INSERT'),
        ('platform_capability_denies','denied','INSERT'),
        ('platform_capability_denies','updated_by_user_id','INSERT'),
        ('platform_capability_denies','denied','UPDATE'),
        ('platform_capability_denies','revision','UPDATE'),
        ('platform_capability_denies','updated_at','UPDATE'),
        ('platform_capability_denies','updated_by_user_id','UPDATE'),
        ('user_capability_denies','user_id','INSERT'), ('user_capability_denies','capability','INSERT'),
        ('user_capability_denies','denied','INSERT'),
        ('user_capability_denies','updated_by_user_id','INSERT'),
        ('user_capability_denies','denied','UPDATE'), ('user_capability_denies','revision','UPDATE'),
        ('user_capability_denies','updated_at','UPDATE'),
        ('user_capability_denies','updated_by_user_id','UPDATE'),
        ('user_capability_grants','user_id','INSERT'), ('user_capability_grants','capability','INSERT'),
        ('user_capability_grants','granted','INSERT'),
        ('user_capability_grants','updated_by_user_id','INSERT'),
        ('user_capability_grants','granted','UPDATE'), ('user_capability_grants','revision','UPDATE'),
        ('user_capability_grants','updated_at','UPDATE'),
        ('user_capability_grants','updated_by_user_id','UPDATE'),
        ('authorization_audit','actor_user_id','INSERT'), ('authorization_audit','action','INSERT'),
        ('authorization_audit','target_kind','INSERT'), ('authorization_audit','target_id','INSERT'),
        ('authorization_audit','request_key','INSERT'), ('authorization_audit','reason','INSERT'),
        ('authorization_audit','details','INSERT')
    ) AS authz(relation, attribute, privilege) WHERE $1 >= 15
    UNION ALL
    -- Run state transitions by revocation, cancellation and the authorization recheck.
    SELECT 'runs', attribute, role, 'UPDATE'
    FROM (VALUES ('state'), ('wait_reason')) AS lifecycle(attribute),
         (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role)
    WHERE $1 >= 15
    UNION ALL
    -- V1-05 PR4a: group and project-wide grantees, and the inert project row lock. The
    -- issuance role's mapped grant writer names the grantee columns from version 18.
    SELECT 'grant_assignments', attribute, role, 'INSERT' FROM (VALUES
        ('grantee_kind'), ('grantee_local_group_id'), ('grantee_oidc_group_id')
    ) AS grantees(attribute),
    (VALUES ('openmettle_api', 16), ('openmettle_issuance', 18)) AS r(role, since)
    WHERE $1 >= r.since
    UNION ALL
    SELECT 'projects', 'lock_guard', 'openmettle_api', 'UPDATE' WHERE $1 >= 16
    UNION ALL
    SELECT * FROM (VALUES
        ('runs', 'lease_expires_at', 'openmettle_worker', 'UPDATE'),
        ('runs', 'execution_expires_at', 'openmettle_worker', 'UPDATE'),
        ('runs', 'cancel_reason', 'openmettle_worker', 'UPDATE'),
        ('runs', 'cancel_reason', 'openmettle_api', 'UPDATE')
    ) AS leases(relation, attribute, role, privilege) WHERE $1 >= 20
    UNION ALL
    -- V1-10 (ADR 0032): admission decisions are inserted once with the run by the API; only
    -- the worker records a claim and locks the dispatch row.
    SELECT * FROM (VALUES
        ('runs', 'actor_approval_id', 'openmettle_api', 'INSERT'),
        ('runs', 'round_limit', 'openmettle_api', 'INSERT'),
        ('runs', 'queue_expires_at', 'openmettle_api', 'INSERT'),
        ('runs', 'claim_token', 'openmettle_worker', 'UPDATE'),
        ('runs', 'claimed_at', 'openmettle_worker', 'UPDATE'),
        ('run_dispatch_lock', 'lock_guard', 'openmettle_worker', 'UPDATE')
    ) AS queue(relation, attribute, role, privilege) WHERE $1 >= 19
    UNION ALL
    -- V1-15 (ADR 0031): the optional display name `settle` writes with each revision.
    SELECT 'artifact_revisions', 'display_name', role, 'INSERT'
    FROM (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role)
    WHERE $1 >= 17
    UNION ALL
    SELECT relation, attribute, 'openmettle_api', privilege FROM (VALUES
        ('login_nonce_reservations','key_id','INSERT'),
        ('login_nonce_reservations','nonce','INSERT'),
        ('login_transactions','id','INSERT'),
        ('login_transactions','binding','INSERT'),
        ('login_transactions','expires_ms','INSERT'),
        ('login_transactions','state_hash','INSERT'),
        ('login_transactions','nonce_hash','INSERT'),
        ('login_transactions','caller_hash','INSERT'),
        ('login_transactions','key_id','INSERT'),
        ('login_transactions','nonce','INSERT'),
        ('login_transactions','ciphertext','INSERT'),
        ('login_transactions','consumed','UPDATE'),
        ('login_transactions','ciphertext','UPDATE')
    ) AS login(relation,attribute,privilege) WHERE $1 >= 6
    UNION ALL
    SELECT * FROM (VALUES
        ('runs', 'id', 'openmettle_api', 'INSERT'),
        ('runs', 'scope_id', 'openmettle_api', 'INSERT'),
        ('runs', 'actor_user_id', 'openmettle_api', 'INSERT'),
        ('runs', 'conversation_id', 'openmettle_api', 'INSERT'),
        ('runs', 'branch_id', 'openmettle_api', 'INSERT'),
        ('runs', 'input_message_id', 'openmettle_api', 'INSERT'),
        ('runs', 'idempotency_key', 'openmettle_api', 'INSERT'),
        ('runs', 'snapshot_format', 'openmettle_api', 'INSERT'),
        ('runs', 'snapshot_version', 'openmettle_api', 'INSERT'),
        ('runs', 'input_snapshot', 'openmettle_api', 'INSERT'),
        ('runs', 'config_snapshot', 'openmettle_api', 'INSERT'),
        ('runs', 'request_identity', 'openmettle_api', 'INSERT'),
        ('runs', 'request_digest', 'openmettle_api', 'INSERT'),
        ('operations', 'id', 'openmettle_worker', 'INSERT'),
        ('operations', 'scope_id', 'openmettle_worker', 'INSERT'),
        ('operations', 'run_id', 'openmettle_worker', 'INSERT'),
        ('operations', 'logical_key', 'openmettle_worker', 'INSERT'),
        ('operations', 'target', 'openmettle_worker', 'INSERT'),
        ('operations', 'capability', 'openmettle_worker', 'INSERT'),
        ('operations', 'format', 'openmettle_worker', 'INSERT'),
        ('operations', 'format_version', 'openmettle_worker', 'INSERT'),
        ('operations', 'request', 'openmettle_worker', 'INSERT'),
        ('operations', 'request_identity', 'openmettle_worker', 'INSERT'),
        ('operations', 'request_digest', 'openmettle_worker', 'INSERT'),
        ('runs', 'last_event_sequence', 'openmettle_api', 'UPDATE'),
        ('runs', 'last_event_sequence', 'openmettle_worker', 'UPDATE'),
        ('operations', 'outcome', 'openmettle_worker', 'UPDATE'),
        ('operations', 'revision', 'openmettle_worker', 'UPDATE'),
        ('operations', 'downstream_handle', 'openmettle_worker', 'UPDATE'),
        ('operations', 'observation_format', 'openmettle_worker', 'UPDATE'),
        ('operations', 'observation_version', 'openmettle_worker', 'UPDATE'),
        ('operations', 'evidence', 'openmettle_worker', 'UPDATE')
    ) AS durable(relation, attribute, role, privilege) WHERE $1 >= 3
    UNION ALL
    SELECT relation, attribute, role, privilege FROM (VALUES
        ('storage_instance', 'active_bytes', 'UPDATE'),
        ('storage_instance', 'retained_bytes', 'UPDATE'),
        ('storage_instance', 'reserved_bytes', 'UPDATE'),
        ('storage_accounts', 'active_bytes', 'UPDATE'),
        ('storage_accounts', 'retained_bytes', 'UPDATE'),
        ('storage_accounts', 'reserved_bytes', 'UPDATE'),
        ('storage_accounts', 'scope_id', 'INSERT'),
        ('artifacts', 'id', 'INSERT'),
        ('artifacts', 'scope_id', 'INSERT'),
        ('artifacts', 'scope_kind', 'INSERT'),
        ('artifacts', 'owner_user_id', 'INSERT'),
        ('artifacts', 'last_revision', 'UPDATE'),
        ('storage_reservations', 'id', 'INSERT'),
        ('storage_reservations', 'scope_id', 'INSERT'),
        ('storage_reservations', 'actor_user_id', 'INSERT'),
        ('storage_reservations', 'idempotency_key', 'INSERT'),
        ('storage_reservations', 'artifact_id', 'INSERT'),
        ('storage_reservations', 'max_bytes', 'INSERT'),
        ('storage_reservations', 'run_id', 'INSERT'),
        ('storage_reservations', 'operation_id', 'INSERT'),
        ('storage_reservations', 'request_identity', 'INSERT'),
        ('storage_reservations', 'request_digest', 'INSERT'),
        ('storage_reservations', 'state', 'UPDATE'),
        ('storage_reservations', 'settled_bytes', 'UPDATE'),
        ('storage_reservations', 'closed_at', 'UPDATE'),
        ('artifact_revisions', 'id', 'INSERT'),
        ('artifact_revisions', 'scope_id', 'INSERT'),
        ('artifact_revisions', 'artifact_id', 'INSERT'),
        ('artifact_revisions', 'revision', 'INSERT'),
        ('artifact_revisions', 'reservation_id', 'INSERT'),
        ('artifact_revisions', 'size_bytes', 'INSERT'),
        ('artifact_revisions', 'content_digest', 'INSERT'),
        ('artifact_revisions', 'media_type', 'INSERT'),
        ('artifact_revisions', 'created_by_user_id', 'INSERT'),
        ('artifact_revisions', 'state', 'UPDATE')
    ) AS storage(relation, attribute, privilege),
    (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role)
    WHERE $1 >= 4
    UNION ALL
    SELECT * FROM (VALUES
        ('artifact_revisions', 'retained_at', 'openmettle_api', 'UPDATE'),
        ('artifact_revisions', 'purge_after', 'openmettle_api', 'UPDATE'),
        ('artifact_revisions', 'purging_at', 'openmettle_worker', 'UPDATE'),
        ('artifact_revisions', 'purged_at', 'openmettle_worker', 'UPDATE')
    ) AS retention(relation, attribute, role, privilege) WHERE $1 >= 4
    UNION ALL
    SELECT * FROM (VALUES
        ('grant_mapping_rules', 'id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'provider_config_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'issuer', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'created_by_user_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'last_revision', 'openmettle_api', 'UPDATE'),
        ('grant_mapping_revisions', 'rule_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'revision', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'actor_user_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'request_key', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'enabled', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'selector_kind', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'claim_name', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'claim_value', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'binding_format', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'binding_version', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'binding', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'request_identity', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'request_digest', 'openmettle_api', 'INSERT')
    ) AS rules(relation, attribute, role, privilege) WHERE $1 >= 5
    UNION ALL
    -- The grant writer (grants::change_grant). From version 18 the issuance role runs its
    -- mapped-membership path inside session issuance (ADR 0030).
    SELECT relation, attribute, role, privilege FROM (VALUES
        ('grant_assignments', 'scope_id', 'INSERT'),
        ('grant_assignments', 'target_kind', 'INSERT'),
        ('grant_assignments', 'project_id', 'INSERT'),
        ('grant_assignments', 'conversation_id', 'INSERT'),
        ('grant_assignments', 'artifact_id', 'INSERT'),
        ('grant_assignments', 'grantee_user_id', 'INSERT'),
        ('grant_assignments', 'assignment_format', 'INSERT'),
        ('grant_assignments', 'assignment_version', 'INSERT'),
        ('grant_assignments', 'assignment_key', 'INSERT'),
        ('grant_assignments', 'source_kind', 'INSERT'),
        ('grant_assignments', 'mapping_rule_id', 'INSERT'),
        ('grant_assignments', 'created_by_user_id', 'INSERT'),
        ('grant_assignments', 'last_revision', 'UPDATE'),
        ('grant_changes', 'id', 'INSERT'),
        ('grant_changes', 'scope_id', 'INSERT'),
        ('grant_changes', 'assignment_id', 'INSERT'),
        ('grant_changes', 'revision', 'INSERT'),
        ('grant_changes', 'source_kind', 'INSERT'),
        ('grant_changes', 'mapping_rule_id', 'INSERT'),
        ('grant_changes', 'mapping_revision', 'INSERT'),
        ('grant_changes', 'actor_user_id', 'INSERT'),
        ('grant_changes', 'request_key', 'INSERT'),
        ('grant_changes', 'decision', 'INSERT'),
        ('grant_changes', 'cycle_id', 'INSERT'),
        ('grant_changes', 'request_identity', 'INSERT'),
        ('grant_changes', 'request_digest', 'INSERT')
    ) AS writer(relation, attribute, privilege),
    (VALUES ('openmettle_api', 5), ('openmettle_issuance', 18)) AS r(role, since)
    WHERE $1 >= r.since
),
user_schemas AS (
    SELECT oid, nspname, nspowner, nspacl FROM pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema')
      AND nspname NOT LIKE 'pg\_toast%'
      AND nspname NOT LIKE 'pg\_temp\_%'
),
grants (target, kind, schema_name, object_name, column_name, grantee, privilege, is_grantable) AS (
    SELECT 'the database', 'database', NULL::name, NULL::name, NULL::name,
           a.grantee, a.privilege_type, a.is_grantable
    FROM pg_database AS d,
         aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) AS a
    WHERE d.datname = current_database()
    UNION ALL
    SELECT 'schema ' || s.nspname, 'schema', s.nspname, NULL, NULL,
           a.grantee, a.privilege_type, a.is_grantable
    FROM user_schemas AS s,
         aclexplode(coalesce(s.nspacl, acldefault('n', s.nspowner))) AS a
    UNION ALL
    SELECT s.nspname || '.' || c.relname, 'relation', s.nspname, c.relname, NULL,
           a.grantee, a.privilege_type, a.is_grantable
    FROM pg_class AS c
    JOIN user_schemas AS s ON s.oid = c.relnamespace,
         aclexplode(coalesce(c.relacl, acldefault(
             CASE c.relkind WHEN 'S' THEN 's'::"char" ELSE 'r'::"char" END, c.relowner))) AS a
    UNION ALL
    SELECT s.nspname || '.' || c.relname || '.' || t.attname, 'column', s.nspname, c.relname,
           t.attname, a.grantee, a.privilege_type, a.is_grantable
    FROM pg_attribute AS t
    JOIN pg_class AS c ON c.oid = t.attrelid
    JOIN user_schemas AS s ON s.oid = c.relnamespace,
         aclexplode(t.attacl) AS a
    WHERE t.attnum > 0 AND NOT t.attisdropped AND t.attacl IS NOT NULL
    UNION ALL
    SELECT 'function ' || p.oid::regprocedure::text, 'function', s.nspname, p.proname, NULL,
           a.grantee, a.privilege_type, a.is_grantable
    FROM pg_proc AS p
    JOIN user_schemas AS s ON s.oid = p.pronamespace,
         aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) AS a
    WHERE s.nspname = 'openmettle'
),
violations (violation) AS (
    -- Identity: SQLx must not bootstrap anything under another login or database owner.
    SELECT format('migrations must log in as openmettle_owner, not %s', session_user)
    WHERE session_user <> 'openmettle_owner' OR current_user <> 'openmettle_owner'
    UNION ALL
    SELECT 'the database must be owned by openmettle_owner'
    FROM pg_database
    WHERE datname = current_database() AND pg_get_userbyid(datdba) <> 'openmettle_owner'
    UNION ALL
    SELECT format('role %s is missing', r)
    FROM unnest(ARRAY['openmettle_owner', 'openmettle_api', 'openmettle_worker',
                      CASE WHEN $1 >= 18 THEN 'openmettle_issuance' END, CASE WHEN $1 >= 23 THEN 'openmettle_gateway' END]) AS r
    WHERE r IS NOT NULL AND NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r)
    UNION ALL
    -- Role attributes of the owner and every application principal.
    SELECT format('role %s must not be superuser or hold CREATEROLE, CREATEDB, REPLICATION '
                  'or BYPASSRLS', rolname)
    FROM pg_roles
    WHERE (oid IN (SELECT oid FROM application) OR oid IN (SELECT oid FROM owner_role))
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    UNION ALL
    -- Memberships: any membership, inherited or only assumable with SET ROLE, can carry
    -- privileges (for example pg_write_all_data) outside the contract.
    SELECT format('role %s must not be a member of %s',
                  pg_get_userbyid(m.member), pg_get_userbyid(m.roleid))
    FROM pg_auth_members AS m
    WHERE m.member IN (SELECT oid FROM privilege_roles UNION ALL SELECT oid FROM owner_role)
    UNION ALL
    SELECT format('role %s, a member of an application role, must not be a member of %s',
                  pg_get_userbyid(m.member), pg_get_userbyid(m.roleid))
    FROM pg_auth_members AS m
    WHERE m.member IN (SELECT oid FROM application)
      AND m.member NOT IN (SELECT oid FROM privilege_roles)
      AND m.roleid NOT IN (SELECT oid FROM application)
    UNION ALL
    -- Disjoint login roles: each reaches at most one application role.
    SELECT format('role %s reaches more than one of openmettle_api, openmettle_issuance, '
                  'openmettle_worker and openmettle_gateway', pg_get_userbyid(oid))
    FROM application
    GROUP BY oid
    HAVING count(DISTINCT base) > 1
    UNION ALL
    -- Object privileges held by principals outside the contract.
    SELECT format('%s has %s on %s',
                  CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END,
                  g.privilege, g.target)
    FROM grants AS g
    WHERE (g.grantee IN (SELECT oid FROM principals)
           OR ($1 >= 23 AND g.schema_name='openmettle' AND g.kind IN ('relation','column')
               AND (g.object_name LIKE 'gateway\_%' OR ($1>=24 AND
                    (g.object_name LIKE 'quota\_%' OR g.object_name='storage_volume_control')))
               AND g.grantee NOT IN (SELECT oid FROM owner_role)))
      AND NOT (g.kind = 'database' AND g.grantee <> 0 AND g.privilege = 'CONNECT')
      AND NOT (g.kind = 'database' AND g.grantee = 0 AND $1 < 1
               AND g.privilege IN ('CONNECT', 'TEMPORARY'))
      AND NOT (g.kind = 'schema' AND g.schema_name = 'openmettle' AND g.privilege = 'USAGE'
               AND g.grantee IN (SELECT oid FROM privilege_roles))
      AND NOT (g.kind = 'schema' AND g.schema_name = 'public' AND g.grantee = 0 AND $1 < 1
               AND g.privilege = 'USAGE')
      AND NOT (g.kind = 'relation' AND g.schema_name = 'openmettle'
               AND (g.object_name::text, pg_get_userbyid(g.grantee)::text, g.privilege)
                   IN (SELECT relation, role, privilege FROM contract))
      -- Exactly one redemption signature per version: the code-less function exists only at
      -- version 12, and from version 13 only the function that requires the invitation code.
      -- Version 14 replaces that function's body and keeps its signature and grant. Version 18
      -- moves the grant from openmettle_api to openmettle_issuance (ADR 0030).
      AND NOT (g.kind = 'function' AND g.privilege = 'EXECUTE'
               AND g.grantee = (SELECT oid FROM pg_roles WHERE rolname
                                = CASE WHEN $1 < 18 THEN 'openmettle_api'
                                       ELSE 'openmettle_issuance' END)
               AND (($1 = 12 AND g.target
                        = 'function openmettle.redeem_home_invitation(uuid,text,text,text,bigint)')
                    OR ($1 >= 13 AND g.target
                        = 'function openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)')))
      AND NOT (g.kind='function' AND g.privilege='EXECUTE'
               AND pg_get_userbyid(g.grantee) IN ('openmettle_api','openmettle_worker')
               AND EXISTS (SELECT FROM gateway_functions f WHERE f.inference AND g.target='function ' || f.signature))
      AND NOT (g.kind='function' AND g.privilege='EXECUTE' AND EXISTS (SELECT FROM runtime_functions f
               WHERE g.target='function ' || to_regprocedure(f.signature)::text AND pg_get_userbyid(g.grantee)=ANY(f.roles)))
      AND NOT (g.kind = 'column' AND g.schema_name = 'openmettle'
               AND (g.object_name::text, g.column_name::text,
                    pg_get_userbyid(g.grantee)::text, g.privilege)
                   IN (SELECT relation, attribute, role, privilege FROM column_contract))
    UNION ALL
    SELECT format('%s lacks %s on openmettle.%s.%s', c.role, c.privilege, c.relation, c.attribute)
    FROM (SELECT * FROM effect_columns UNION ALL SELECT * FROM gateway_columns UNION ALL SELECT * FROM quota_columns) c WHERE NOT EXISTS (
        SELECT FROM grants g WHERE g.kind='column' AND g.schema_name='openmettle'
          AND g.object_name=c.relation AND g.column_name=c.attribute
          AND pg_get_userbyid(g.grantee)=c.role AND g.privilege=c.privilege)
    UNION ALL
    SELECT format('%s lacks SELECT on openmettle.%s', c.role, c.relation) FROM contract c
    WHERE (c.relation IN (SELECT relation FROM quota_tables) OR c.role='openmettle_gateway' OR c.relation IN ('run_approvals','run_approval_decisions')) AND NOT EXISTS (
        SELECT FROM grants g WHERE g.kind='relation' AND g.schema_name='openmettle'
          AND g.object_name=c.relation AND pg_get_userbyid(g.grantee)=c.role AND g.privilege=c.privilege)
    UNION ALL
    SELECT format('unsafe or missing gateway function %s', f.signature)
    FROM gateway_functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
    WHERE p.oid IS NULL OR p.prosecdef <> f.definer OR pg_get_userbyid(p.proowner)<>'openmettle_owner'
       OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']
       OR EXISTS (SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                  WHERE a.grantee<>p.proowner AND (NOT f.inference OR a.is_grantable OR
                    a.grantee NOT IN (SELECT oid FROM pg_roles WHERE rolname IN ('openmettle_api','openmettle_worker'))))
       OR (f.inference AND EXISTS (SELECT FROM pg_roles r WHERE r.rolname IN ('openmettle_api','openmettle_worker')
            AND NOT has_function_privilege(r.oid,p.oid,'EXECUTE')))
    UNION ALL
    SELECT format('unsafe or missing quota function %s',f.signature)
    FROM runtime_functions f LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
    WHERE p.oid IS NULL OR p.prosecdef<>f.definer OR pg_get_userbyid(p.proowner)<>'openmettle_owner'
       OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']
       OR EXISTS (SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
             WHERE a.grantee<>p.proowner AND (a.is_grantable OR NOT(pg_get_userbyid(a.grantee)=ANY(f.roles))))
       OR EXISTS (SELECT FROM unnest(f.roles) role WHERE NOT has_function_privilege(role,p.oid,'EXECUTE'))
    UNION ALL
    SELECT 'openmettle_gateway lacks CONNECT or schema USAGE'
    FROM pg_roles r WHERE $1>=23 AND r.rolname='openmettle_gateway'
      AND (NOT has_database_privilege(r.oid,current_database(),'CONNECT')
           OR NOT has_schema_privilege(r.oid,'openmettle','USAGE'))
    UNION ALL
    -- Even permitted privileges must not be delegable to another application principal.
    SELECT format('%s has grant option for %s on %s',
                  CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END,
                  g.privilege, g.target)
    FROM grants AS g
    WHERE g.grantee IN (SELECT oid FROM principals) AND g.is_grantable
    UNION ALL
    -- Default privileges would grant future migration objects outside the contract.
    SELECT format('default privileges of openmettle_owner%s grant %s on new %s to %s',
                  coalesce(' in schema ' || s.nspname, ''), a.privilege_type,
                  CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences'
                      WHEN 'f' THEN 'functions' WHEN 'T' THEN 'types'
                      WHEN 'n' THEN 'schemas' ELSE 'objects' END,
                  CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END)
    FROM pg_default_acl AS d
    LEFT JOIN pg_namespace AS s ON s.oid = d.defaclnamespace,
         aclexplode(d.defaclacl) AS a
    WHERE d.defaclrole IN (SELECT oid FROM owner_role)
      AND a.grantee IN (SELECT oid FROM principals)
    UNION ALL
    -- Ownership grants DDL; principals own nothing and the owner owns schema openmettle.
    SELECT format('%s owns schema %s', pg_get_userbyid(nspowner), nspname)
    FROM user_schemas
    WHERE nspowner IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('%s owns %s.%s', pg_get_userbyid(c.relowner), s.nspname, c.relname)
    FROM pg_class AS c
    JOIN pg_namespace AS s ON s.oid = c.relnamespace
    WHERE c.relowner IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('%s owns function %s', pg_get_userbyid(proowner), oid::regprocedure)
    FROM pg_proc
    WHERE proowner IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('%s owns type %s', pg_get_userbyid(typowner), oid::regtype)
    FROM pg_type
    WHERE typowner IN (SELECT oid FROM application) AND typrelid = 0
    UNION ALL
    SELECT 'schema openmettle must be owned by openmettle_owner'
    FROM pg_namespace
    WHERE nspname = 'openmettle' AND pg_get_userbyid(nspowner) <> 'openmettle_owner'
    UNION ALL
    SELECT format('openmettle.%s must be owned by openmettle_owner', c.relname)
    FROM pg_class AS c
    JOIN pg_namespace AS s ON s.oid = c.relnamespace
    WHERE s.nspname = 'openmettle' AND pg_get_userbyid(c.relowner) <> 'openmettle_owner'
)
SELECT DISTINCT violation FROM violations ORDER BY violation LIMIT 20
