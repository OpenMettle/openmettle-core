-- V1-30 migration 45 (ADR 0046, issue #27): maintenance-window coordinated backup capture,
-- backup run ledger, deadlock-free admission/drain gate, RPO overdue tracking, and worker
-- telemetry observation for openmettle.backup.runs.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (deadlock-free pure sink relative to all runtime tables):
--   - Runtime mutating transactions (openmettle_api, openmettle_worker, openmettle_issuance)
--     call openmettle.backup_maintenance_lock_open(), taking FOR SHARE on
--     openmettle.backup_maintenance_gate (and raising OMM01 when maintenance_active).
--   - Owner maintenance/capture transitions and worker telemetry observation lock ONLY
--     openmettle.backup_maintenance_gate (FIRST, FOR UPDATE) -> openmettle.backup_runs
--     (SECOND) -> openmettle.authorization_audit (INSERT only), committing immediately and
--     never locking any runtime table (runs, storage_reservations, projects, users, sessions,
--     external_connections, restore_reconciliation_gate, etc.).
--
-- Role boundaries (verified by src/boundaries.sql):
--   - Zero table or column privileges on backup_maintenance_gate or backup_runs for any
--     runtime role or PUBLIC.
--   - openmettle.backup_maintenance_is_active() SECURITY DEFINER: EXECUTE for
--     openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway.
--   - openmettle.backup_maintenance_lock_open() SECURITY DEFINER: EXECUTE for
--     openmettle_api, openmettle_worker, openmettle_issuance.
--   - openmettle.backup_observe_telemetry() SECURITY DEFINER: EXECUTE for openmettle_worker.
--   - All maintenance, RPO, capture lifecycle, and trigger functions are owner-only with
--     PUBLIC EXECUTE revoked.

-- Acquire ACCESS EXCLUSIVE on the only pre-existing table modified by migration 45 in one
-- bounded NOWAIT retry loop at the top of the transaction so concurrent writers cannot
-- deadlock with DDL.
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
            LOCK TABLE openmettle.authorization_audit
                IN ACCESS EXCLUSIVE MODE NOWAIT;
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
END
$$;

-- Append-only ledger of coordinated backup capture attempts and verified cryptographic metadata.
CREATE TABLE openmettle.backup_runs (
    id uuid PRIMARY KEY,
    request_key text NOT NULL UNIQUE
        CHECK (
            octet_length(request_key) BETWEEN 1 AND 128
            AND btrim(request_key) = request_key
            AND request_key COLLATE "C" !~ '[[:cntrl:]]'
        ),
    operator_id uuid NOT NULL,
    state text NOT NULL
        CHECK (state IN ('draining', 'capturing', 'succeeded', 'failed', 'incomplete')),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_until timestamptz,
    quiesced_at timestamptz,
    completed_at timestamptz,
    destination_domain text NOT NULL
        CHECK (
            octet_length(destination_domain) BETWEEN 1 AND 128
            AND btrim(destination_domain) = destination_domain
            AND destination_domain COLLATE "C" ~ '^[A-Za-z0-9._:/-]+$'
        ),
    encryption_key_id text
        CHECK (
            encryption_key_id IS NULL
            OR (
                octet_length(encryption_key_id) BETWEEN 1 AND 64
                AND encryption_key_id COLLATE "C" ~ '^[A-Za-z0-9._-]+$'
            )
        ),
    bundle_digest bytea
        CHECK (bundle_digest IS NULL OR octet_length(bundle_digest) = 32),
    manifest_digest bytea
        CHECK (manifest_digest IS NULL OR octet_length(manifest_digest) = 32),
    journal_origin_us bigint
        CHECK (journal_origin_us IS NULL OR journal_origin_us >= 0),
    journal_seq bigint
        CHECK (journal_seq IS NULL OR journal_seq >= 0),
    journal_chain_digest bytea
        CHECK (journal_chain_digest IS NULL OR octet_length(journal_chain_digest) = 32),
    lifecycle_origin_us bigint
        CHECK (lifecycle_origin_us IS NULL OR lifecycle_origin_us >= 0),
    lifecycle_baseline_digest bytea
        CHECK (
            lifecycle_baseline_digest IS NULL
            OR octet_length(lifecycle_baseline_digest) = 32
        ),
    connection_origin_us bigint
        CHECK (connection_origin_us IS NULL OR connection_origin_us >= 0),
    failure_code text
        CHECK (
            failure_code IS NULL
            OR (
                octet_length(failure_code) BETWEEN 1 AND 64
                AND failure_code COLLATE "C" ~ '^[a-z0-9_]+$'
            )
        ),
    telemetry_observed boolean NOT NULL DEFAULT false,
    manifest_summary jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (
            jsonb_typeof(manifest_summary) = 'object'
            AND octet_length(manifest_summary::text) <= 16384
        ),
    CONSTRAINT backup_runs_lifecycle_check CHECK (
        (
            state = 'draining'
            AND lease_until IS NOT NULL
            AND quiesced_at IS NULL
            AND completed_at IS NULL
            AND failure_code IS NULL
            AND bundle_digest IS NULL
            AND manifest_digest IS NULL
            AND NOT telemetry_observed
        )
        OR (
            state = 'capturing'
            AND lease_until IS NOT NULL
            AND quiesced_at IS NOT NULL
            AND completed_at IS NULL
            AND failure_code IS NULL
            AND bundle_digest IS NULL
            AND manifest_digest IS NULL
            AND NOT telemetry_observed
        )
        OR (
            state = 'succeeded'
            AND lease_until IS NULL
            AND quiesced_at IS NOT NULL
            AND completed_at IS NOT NULL
            AND completed_at >= quiesced_at
            AND failure_code IS NULL
            AND encryption_key_id IS NOT NULL
            AND bundle_digest IS NOT NULL
            AND manifest_digest IS NOT NULL
            AND journal_origin_us IS NOT NULL
            AND journal_seq IS NOT NULL
            AND journal_chain_digest IS NOT NULL
        )
        OR (
            state IN ('failed', 'incomplete')
            AND lease_until IS NULL
            AND completed_at IS NOT NULL
            AND failure_code IS NOT NULL
        )
    )
);
REVOKE ALL ON TABLE openmettle.backup_runs FROM PUBLIC;

CREATE INDEX backup_runs_active_lease_idx
    ON openmettle.backup_runs (lease_until)
    WHERE state IN ('draining', 'capturing');

CREATE INDEX backup_runs_unobserved_terminal_idx
    ON openmettle.backup_runs (completed_at)
    WHERE state IN ('succeeded', 'failed', 'incomplete') AND NOT telemetry_observed;

CREATE INDEX backup_runs_succeeded_completed_idx
    ON openmettle.backup_runs (completed_at DESC)
    WHERE state = 'succeeded';

-- Enforce monotonic state transitions and terminal immutability on backup_runs.
CREATE FUNCTION openmettle.enforce_backup_runs_transitions()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'backup_runs records are append-only' USING ERRCODE = '42501';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.request_key IS DISTINCT FROM OLD.request_key
       OR NEW.operator_id IS DISTINCT FROM OLD.operator_id
       OR NEW.started_at IS DISTINCT FROM OLD.started_at
       OR NEW.destination_domain IS DISTINCT FROM OLD.destination_domain THEN
        RAISE EXCEPTION 'backup_runs identity fields are immutable' USING ERRCODE = '22023';
    END IF;

    IF OLD.telemetry_observed AND NOT NEW.telemetry_observed THEN
        RAISE EXCEPTION 'telemetry_observed cannot revert to false' USING ERRCODE = 'OMB01';
    END IF;

    IF OLD.quiesced_at IS NOT NULL AND NEW.quiesced_at IS DISTINCT FROM OLD.quiesced_at THEN
        RAISE EXCEPTION 'backup_runs quiesced_at is immutable once set' USING ERRCODE = 'OMB01';
    END IF;

    IF OLD.state IN ('succeeded', 'failed', 'incomplete') THEN
        IF NOT (
            NOT OLD.telemetry_observed
            AND NEW.telemetry_observed
            AND NEW.state IS NOT DISTINCT FROM OLD.state
            AND NEW.lease_until IS NOT DISTINCT FROM OLD.lease_until
            AND NEW.quiesced_at IS NOT DISTINCT FROM OLD.quiesced_at
            AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at
            AND NEW.encryption_key_id IS NOT DISTINCT FROM OLD.encryption_key_id
            AND NEW.bundle_digest IS NOT DISTINCT FROM OLD.bundle_digest
            AND NEW.manifest_digest IS NOT DISTINCT FROM OLD.manifest_digest
            AND NEW.journal_origin_us IS NOT DISTINCT FROM OLD.journal_origin_us
            AND NEW.journal_seq IS NOT DISTINCT FROM OLD.journal_seq
            AND NEW.journal_chain_digest IS NOT DISTINCT FROM OLD.journal_chain_digest
            AND NEW.lifecycle_origin_us IS NOT DISTINCT FROM OLD.lifecycle_origin_us
            AND NEW.lifecycle_baseline_digest IS NOT DISTINCT FROM OLD.lifecycle_baseline_digest
            AND NEW.connection_origin_us IS NOT DISTINCT FROM OLD.connection_origin_us
            AND NEW.failure_code IS NOT DISTINCT FROM OLD.failure_code
            AND NEW.manifest_summary IS NOT DISTINCT FROM OLD.manifest_summary
        ) THEN
            RAISE EXCEPTION 'terminal backup_runs rows are immutable except telemetry_observed'
                USING ERRCODE = 'OMB01';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'draining'
       AND NEW.state NOT IN ('draining', 'capturing', 'failed', 'incomplete') THEN
        RAISE EXCEPTION 'draining backup run cannot transition directly to %', NEW.state
            USING ERRCODE = 'OMB01';
    END IF;

    IF OLD.state = 'capturing'
       AND NEW.state NOT IN ('capturing', 'succeeded', 'failed', 'incomplete') THEN
        RAISE EXCEPTION 'capturing backup run cannot transition to %', NEW.state
            USING ERRCODE = 'OMB01';
    END IF;

    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_backup_runs_transitions() FROM PUBLIC;

CREATE TRIGGER backup_runs_enforce_transitions
    BEFORE UPDATE OR DELETE
    ON openmettle.backup_runs
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.enforce_backup_runs_transitions();

-- Singleton maintenance-window gate and RPO tracking state.
CREATE TABLE openmettle.backup_maintenance_gate (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    maintenance_active boolean NOT NULL DEFAULT false,
    backup_run_id uuid REFERENCES openmettle.backup_runs (id),
    entered_at timestamptz,
    entered_by_operator_id uuid,
    reason text,
    quiesced_at timestamptz,
    rpo_target_seconds integer NOT NULL DEFAULT 86400
        CHECK (rpo_target_seconds BETWEEN 3600 AND 604800),
    rpo_tracking_armed_at timestamptz,
    last_overdue_observed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT backup_maintenance_gate_state_check CHECK (
        (
            NOT maintenance_active
            AND backup_run_id IS NULL
            AND entered_at IS NULL
            AND entered_by_operator_id IS NULL
            AND reason IS NULL
            AND quiesced_at IS NULL
        )
        OR (
            maintenance_active
            AND entered_at IS NOT NULL
            AND entered_by_operator_id IS NOT NULL
            AND reason IS NOT NULL
            AND openmettle.capacity_valid_name(reason, 512)
            AND (quiesced_at IS NULL OR quiesced_at >= entered_at)
        )
    )
);
REVOKE ALL ON TABLE openmettle.backup_maintenance_gate FROM PUBLIC;

INSERT INTO openmettle.backup_maintenance_gate (id) VALUES (true);

-- Widen authorization_audit constraints additively for operator backup coordination actions.
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
        'retention.policy_update', 'retention.deadlines_apply',
        'retention.status_read', 'retention.deadlines_preview',
        'artifact.delete', 'artifact_revision.delete', 'artifact_revision.restore',
        'family_policy.set', 'family_policy.clear',
        'family_policy.model_study_allow', 'family_policy.model_study_revoke',
        'family_policy.model_disable', 'family_policy.model_enable',
        'restore.accept_coverage_gap',
        'connection.created', 'connection.authorized',
        'connection.shared', 'connection.share_revoked',
        'connection.refreshed', 'connection.reauth_required',
        'connection.disconnected', 'vault.rotated',
        'storage.declare_payload_lost',
        'backup.maintenance_entered', 'backup.capture_succeeded',
        'backup.capture_failed', 'backup.maintenance_released',
        'backup.rpo_armed')),
    DROP CONSTRAINT authorization_audit_target_kind_check,
    ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN (
        'user', 'project', 'conversation', 'artifact', 'local_group', 'capability',
        'scope', 'branch', 'quota_scope', 'retention_policy',
        'family_policy', 'oidc_group', 'restore_gate',
        'external_connection', 'vault', 'artifact_revision',
        'backup_maintenance', 'backup_run')),
    ADD CONSTRAINT authorization_audit_backup_check CHECK (
        (
            action IN (
                'backup.maintenance_entered',
                'backup.maintenance_released',
                'backup.rpo_armed'
            )
            AND target_kind = 'backup_maintenance'
            AND actor_kind = 'operator'
            AND actor_user_id IS NULL
            AND operator_id IS NOT NULL
        )
        OR (
            action IN ('backup.capture_succeeded', 'backup.capture_failed')
            AND target_kind = 'backup_run'
            AND actor_kind = 'operator'
            AND actor_user_id IS NULL
            AND operator_id IS NOT NULL
        )
        OR (
            action NOT IN (
                'backup.maintenance_entered',
                'backup.maintenance_released',
                'backup.rpo_armed',
                'backup.capture_succeeded',
                'backup.capture_failed'
            )
            AND target_kind NOT IN ('backup_maintenance', 'backup_run')
        )
    );

-- Runtime helper: non-locking read of maintenance state (fail-closed if singleton missing).
CREATE FUNCTION openmettle.backup_maintenance_is_active()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(
        (SELECT maintenance_active FROM openmettle.backup_maintenance_gate WHERE id),
        true
    );
$$;
REVOKE ALL ON FUNCTION openmettle.backup_maintenance_is_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.backup_maintenance_is_active()
    TO openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway;

-- Runtime admission fence: acquires FOR SHARE on backup_maintenance_gate and raises OMM01 when
-- maintenance is active. Deadlock-free because owner maintenance functions never lock runtime
-- tables in the same transaction.
CREATE FUNCTION openmettle.backup_maintenance_lock_open()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_active boolean;
BEGIN
    SELECT maintenance_active
      INTO STRICT v_active
      FROM openmettle.backup_maintenance_gate
     WHERE id
       FOR SHARE;
    IF v_active THEN
        RAISE EXCEPTION 'service is in maintenance window' USING ERRCODE = 'OMM01';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_maintenance_lock_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.backup_maintenance_lock_open()
    TO openmettle_api, openmettle_worker, openmettle_issuance;

-- Worker telemetry observer for openmettle.backup.runs (ADR 0028 / ADR 0046).
-- Canonical lock order: backup_maintenance_gate (FOR UPDATE SKIP LOCKED) -> backup_runs.
CREATE FUNCTION openmettle.backup_observe_telemetry()
RETURNS TABLE(
    succeeded_count bigint,
    failed_count bigint,
    incomplete_count bigint,
    overdue_count bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    v_now timestamptz;
    v_anchor timestamptz;
    v_succeeded bigint := 0;
    v_failed bigint := 0;
    v_incomplete bigint := 0;
    v_overdue bigint := 0;
BEGIN
    SELECT *
      INTO g
      FROM openmettle.backup_maintenance_gate
     WHERE id
       FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 0::bigint, 0::bigint, 0::bigint, 0::bigint;
        RETURN;
    END IF;

    v_now := pg_catalog.clock_timestamp();

    -- 1. Mark any draining/capturing backup runs whose lease expired as incomplete.
    --    Maintenance intentionally remains active for explicit operator recovery.
    WITH expired AS (
        SELECT r.id
          FROM openmettle.backup_runs r
         WHERE r.state IN ('draining', 'capturing')
           AND r.lease_until <= v_now
         ORDER BY r.id
           FOR UPDATE SKIP LOCKED
    )
    UPDATE openmettle.backup_runs r
       SET state = 'incomplete',
           completed_at = v_now,
           lease_until = NULL,
           failure_code = 'lease_expired'
      FROM expired e
     WHERE r.id = e.id;

    -- 2. Atomically claim unobserved terminal runs for worker counter emission.
    WITH due AS (
        SELECT r.id
          FROM openmettle.backup_runs r
         WHERE r.state IN ('succeeded', 'failed', 'incomplete')
           AND NOT r.telemetry_observed
         ORDER BY r.id
           FOR UPDATE SKIP LOCKED
    ),
    marked AS (
        UPDATE openmettle.backup_runs r
           SET telemetry_observed = true
          FROM due d
         WHERE r.id = d.id
     RETURNING r.state
    )
    SELECT count(*) FILTER (WHERE state = 'succeeded'),
           count(*) FILTER (WHERE state = 'failed'),
           count(*) FILTER (WHERE state = 'incomplete')
      INTO v_succeeded, v_failed, v_incomplete
      FROM marked;

    -- 3. Evaluate RPO overdue state once tracking has been armed.
    IF g.rpo_tracking_armed_at IS NOT NULL THEN
        SELECT coalesce(max(r.completed_at), g.rpo_tracking_armed_at)
          INTO v_anchor
          FROM openmettle.backup_runs r
         WHERE r.state = 'succeeded';
        v_now := pg_catalog.clock_timestamp();
        IF v_now - v_anchor > pg_catalog.make_interval(secs => g.rpo_target_seconds)
           AND (
               g.last_overdue_observed_at IS NULL
               OR g.last_overdue_observed_at < v_anchor
               OR v_now - g.last_overdue_observed_at >= interval '1 hour'
           ) THEN
            UPDATE openmettle.backup_maintenance_gate
               SET last_overdue_observed_at = v_now,
                   updated_at = v_now
             WHERE id;
            v_overdue := 1;
        END IF;
    END IF;

    RETURN QUERY SELECT
        coalesce(v_succeeded, 0::bigint),
        coalesce(v_failed, 0::bigint),
        coalesce(v_incomplete, 0::bigint),
        coalesce(v_overdue, 0::bigint);
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_observe_telemetry() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.backup_observe_telemetry() TO openmettle_worker;

-- Owner only: idempotently enter maintenance window. Locks ONLY backup_maintenance_gate and
-- inserts into authorization_audit (never any runtime table).
CREATE FUNCTION openmettle.backup_enter_maintenance(
    p_operator_id uuid,
    p_request_key text,
    p_reason text)
RETURNS TABLE(
    entered boolean,
    entered_at timestamptz)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    v_existing record;
    v_now timestamptz;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup maintenance entry requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may enter backup maintenance' USING ERRCODE = '42501';
    END IF;
    IF p_operator_id IS NULL
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR NOT openmettle.capacity_valid_name(p_reason, 512) THEN
        RAISE EXCEPTION 'invalid backup maintenance parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;

    SELECT a.operator_id, a.action, a.target_kind, a.target_id, a.reason
      INTO v_existing
      FROM openmettle.authorization_audit a
     WHERE a.actor_kind = 'operator'
       AND a.operator_id = p_operator_id
       AND a.request_key = p_request_key
     LIMIT 1;
    IF FOUND THEN
        IF v_existing.action = 'backup.maintenance_entered'
           AND v_existing.target_kind = 'backup_maintenance'
           AND v_existing.target_id = 'singleton'
           AND v_existing.reason = p_reason THEN
            RETURN QUERY SELECT false, g.entered_at;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;

    v_now := pg_catalog.clock_timestamp();
    IF g.maintenance_active THEN
        INSERT INTO openmettle.authorization_audit
            (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
             request_key, reason, details)
        VALUES
            ('operator', NULL, p_operator_id, 'backup.maintenance_entered', 'backup_maintenance',
             'singleton', p_request_key, p_reason, jsonb_build_object('already_active', true));
        RETURN QUERY SELECT false, g.entered_at;
        RETURN;
    END IF;

    UPDATE openmettle.backup_maintenance_gate
       SET maintenance_active = true,
           entered_at = v_now,
           entered_by_operator_id = p_operator_id,
           reason = p_reason,
           quiesced_at = NULL,
           updated_at = v_now
     WHERE id;

    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
         request_key, reason, details)
    VALUES
        ('operator', NULL, p_operator_id, 'backup.maintenance_entered', 'backup_maintenance',
         'singleton', p_request_key, p_reason, jsonb_build_object('already_active', false));

    RETURN QUERY SELECT true, v_now;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_enter_maintenance(uuid, text, text) FROM PUBLIC;

-- Owner only: explicit audited maintenance release. Refuses if any backup_runs row currently
-- holds a live draining/capturing lease unless p_abort_active_run = true.
CREATE FUNCTION openmettle.backup_release_maintenance(
    p_operator_id uuid,
    p_request_key text,
    p_reason text,
    p_abort_active_run boolean DEFAULT false)
RETURNS TABLE(
    released boolean,
    aborted_run_id uuid)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    v_existing record;
    v_now timestamptz;
    v_live_count bigint := 0;
    v_aborted uuid := NULL;
    r openmettle.backup_runs%ROWTYPE;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup maintenance release requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may release backup maintenance' USING ERRCODE = '42501';
    END IF;
    IF p_operator_id IS NULL
       OR p_abort_active_run IS NULL
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR NOT openmettle.capacity_valid_name(p_reason, 512) THEN
        RAISE EXCEPTION 'invalid backup maintenance release parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;

    SELECT a.operator_id, a.action, a.target_kind, a.target_id, a.reason, a.details
      INTO v_existing
      FROM openmettle.authorization_audit a
     WHERE a.actor_kind = 'operator'
       AND a.operator_id = p_operator_id
       AND a.request_key = p_request_key
     LIMIT 1;
    IF FOUND THEN
        IF v_existing.action = 'backup.maintenance_released'
           AND v_existing.target_kind = 'backup_maintenance'
           AND v_existing.target_id = 'singleton'
           AND v_existing.reason = p_reason
           AND coalesce((v_existing.details->>'abort_active_run')::boolean, false) = p_abort_active_run THEN
            RETURN QUERY SELECT false, (v_existing.details->>'aborted_run_id')::uuid;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;

    v_now := pg_catalog.clock_timestamp();

    FOR r IN
        SELECT *
          FROM openmettle.backup_runs
         WHERE state IN ('draining', 'capturing')
         ORDER BY id
           FOR UPDATE
    LOOP
        IF r.lease_until > v_now THEN
            v_live_count := v_live_count + 1;
            IF NOT p_abort_active_run THEN
                RAISE EXCEPTION 'active backup run % holds a live lease; pass --abort-active-run to mark it incomplete',
                    r.id USING ERRCODE = 'OMB02';
            END IF;
            UPDATE openmettle.backup_runs
               SET state = 'incomplete',
                   completed_at = v_now,
                   lease_until = NULL,
                   failure_code = 'operator_aborted'
             WHERE id = r.id;
            IF v_aborted IS NULL OR r.id = g.backup_run_id THEN
                v_aborted := r.id;
            END IF;
        ELSE
            UPDATE openmettle.backup_runs
               SET state = 'incomplete',
                   completed_at = v_now,
                   lease_until = NULL,
                   failure_code = 'lease_expired'
             WHERE id = r.id;
            IF v_aborted IS NULL OR r.id = g.backup_run_id THEN
                v_aborted := r.id;
            END IF;
        END IF;
    END LOOP;

    IF g.maintenance_active THEN
        UPDATE openmettle.backup_maintenance_gate
           SET maintenance_active = false,
               backup_run_id = NULL,
               entered_at = NULL,
               entered_by_operator_id = NULL,
               reason = NULL,
               quiesced_at = NULL,
               updated_at = v_now
         WHERE id;
    END IF;

    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
         request_key, reason, details)
    VALUES
        ('operator', NULL, p_operator_id, 'backup.maintenance_released', 'backup_maintenance',
         'singleton', p_request_key, p_reason,
         jsonb_build_object(
             'was_active', g.maintenance_active,
             'abort_active_run', p_abort_active_run,
             'aborted_run_id', v_aborted,
             'aborted_live_leases', v_live_count
         ));

    RETURN QUERY SELECT g.maintenance_active, v_aborted;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_release_maintenance(uuid, text, text, boolean) FROM PUBLIC;

-- Owner only: arm RPO overdue tracking and optionally configure rpo_target_seconds.
CREATE FUNCTION openmettle.backup_arm_rpo(
    p_operator_id uuid,
    p_request_key text,
    p_reason text,
    p_rpo_seconds integer DEFAULT 86400)
RETURNS TABLE(
    rpo_target_seconds integer,
    rpo_tracking_armed_at timestamptz)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    v_existing record;
    v_now timestamptz;
    v_armed_at timestamptz;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup arm-rpo requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may arm backup RPO tracking' USING ERRCODE = '42501';
    END IF;
    IF p_operator_id IS NULL
       OR p_rpo_seconds IS NULL
       OR p_rpo_seconds NOT BETWEEN 3600 AND 604800
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR NOT openmettle.capacity_valid_name(p_reason, 512) THEN
        RAISE EXCEPTION 'invalid backup arm-rpo parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;

    SELECT a.operator_id, a.action, a.target_kind, a.target_id, a.reason, a.details
      INTO v_existing
      FROM openmettle.authorization_audit a
     WHERE a.actor_kind = 'operator'
       AND a.operator_id = p_operator_id
       AND a.request_key = p_request_key
     LIMIT 1;
    IF FOUND THEN
        IF v_existing.action = 'backup.rpo_armed'
           AND v_existing.target_kind = 'backup_maintenance'
           AND v_existing.target_id = 'singleton'
           AND v_existing.reason = p_reason
           AND (v_existing.details->>'rpo_target_seconds')::integer = p_rpo_seconds THEN
            RETURN QUERY SELECT g.rpo_target_seconds, g.rpo_tracking_armed_at;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;

    v_now := pg_catalog.clock_timestamp();
    v_armed_at := coalesce(g.rpo_tracking_armed_at, v_now);

    UPDATE openmettle.backup_maintenance_gate
       SET rpo_target_seconds = p_rpo_seconds,
           rpo_tracking_armed_at = v_armed_at,
           updated_at = v_now
     WHERE id;

    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
         request_key, reason, details)
    VALUES
        ('operator', NULL, p_operator_id, 'backup.rpo_armed', 'backup_maintenance',
         'singleton', p_request_key, p_reason,
         jsonb_build_object(
             'rpo_target_seconds', p_rpo_seconds,
             'rpo_tracking_armed_at', v_armed_at
         ));

    RETURN QUERY SELECT p_rpo_seconds, v_armed_at;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_arm_rpo(uuid, text, text, integer) FROM PUBLIC;

-- Owner only: start a coordinated backup capture run, entering maintenance if not already active
-- and arming RPO tracking if unset. Locks ONLY backup_maintenance_gate -> backup_runs.
CREATE FUNCTION openmettle.backup_start_capture(
    p_operator_id uuid,
    p_request_key text,
    p_reason text,
    p_destination_domain text,
    p_lease_seconds integer DEFAULT 300)
RETURNS TABLE(
    backup_run_id uuid,
    entered_at timestamptz,
    lease_until timestamptz,
    rpo_target_seconds integer)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    r openmettle.backup_runs%ROWTYPE;
    v_now timestamptz;
    v_run_id uuid;
    v_entered_at timestamptz;
    v_lease_until timestamptz;
    v_enter_key text;
    v_enter_bytes bytea;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup capture start requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may start backup capture' USING ERRCODE = '42501';
    END IF;
    IF p_operator_id IS NULL
       OR p_lease_seconds IS NULL
       OR p_lease_seconds NOT BETWEEN 30 AND 3600
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR p_destination_domain IS NULL
       OR octet_length(p_destination_domain) NOT BETWEEN 1 AND 128
       OR btrim(p_destination_domain) <> p_destination_domain
       OR p_destination_domain COLLATE "C" !~ '^[A-Za-z0-9._:/-]+$'
       OR NOT openmettle.capacity_valid_name(p_reason, 512) THEN
        RAISE EXCEPTION 'invalid backup capture start parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;

    IF EXISTS (SELECT 1 FROM openmettle.backup_runs br WHERE br.request_key = p_request_key)
       OR EXISTS (
           SELECT 1
             FROM openmettle.authorization_audit a
            WHERE a.actor_kind = 'operator'
              AND a.operator_id = p_operator_id
              AND a.request_key = p_request_key
       ) THEN
        RAISE EXCEPTION 'backup capture request key already used' USING ERRCODE = '23505';
    END IF;

    v_now := pg_catalog.clock_timestamp();

    FOR r IN
        SELECT *
          FROM openmettle.backup_runs
         WHERE state IN ('draining', 'capturing')
         ORDER BY id
           FOR UPDATE
    LOOP
        IF r.lease_until > v_now THEN
            RAISE EXCEPTION 'backup run % already holds an active lease', r.id
                USING ERRCODE = 'OMB02';
        END IF;
        UPDATE openmettle.backup_runs
           SET state = 'incomplete',
               completed_at = v_now,
               lease_until = NULL,
               failure_code = 'lease_expired'
         WHERE id = r.id;
    END LOOP;

    v_run_id := pg_catalog.gen_random_uuid();
    v_lease_until := v_now + pg_catalog.make_interval(secs => p_lease_seconds);

    INSERT INTO openmettle.backup_runs (
        id, request_key, operator_id, state, started_at, lease_until, destination_domain
    )
    VALUES (
        v_run_id, p_request_key, p_operator_id, 'draining', v_now, v_lease_until,
        p_destination_domain
    );

    IF NOT g.maintenance_active THEN
        v_entered_at := v_now;
        UPDATE openmettle.backup_maintenance_gate
           SET maintenance_active = true,
               backup_run_id = v_run_id,
               entered_at = v_now,
               entered_by_operator_id = p_operator_id,
               reason = p_reason,
               quiesced_at = NULL,
               rpo_tracking_armed_at = coalesce(rpo_tracking_armed_at, v_now),
               updated_at = v_now
         WHERE id;

        v_enter_bytes := CASE
            WHEN pg_catalog.getdatabaseencoding() = 'SQL_ASCII'
                THEN pg_catalog.convert_to('backup.capture.enter:' || p_request_key, 'SQL_ASCII')
            ELSE pg_catalog.convert_to('backup.capture.enter:' || p_request_key, 'UTF8')
        END;
        v_enter_key := encode(pg_catalog.sha256(v_enter_bytes), 'hex');

        INSERT INTO openmettle.authorization_audit
            (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
             request_key, reason, details)
        VALUES
            ('operator', NULL, p_operator_id, 'backup.maintenance_entered', 'backup_maintenance',
             'singleton', v_enter_key, p_reason,
             jsonb_build_object(
                 'already_active', false,
                 'backup_run_id', v_run_id,
                 'destination_domain', p_destination_domain
             ));
    ELSE
        v_entered_at := g.entered_at;
        UPDATE openmettle.backup_maintenance_gate
           SET backup_run_id = v_run_id,
               quiesced_at = NULL,
               rpo_tracking_armed_at = coalesce(rpo_tracking_armed_at, v_now),
               updated_at = v_now
         WHERE id;
    END IF;

    RETURN QUERY SELECT v_run_id, v_entered_at, v_lease_until, g.rpo_target_seconds;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_start_capture(uuid, text, text, text, integer) FROM PUBLIC;

-- Owner only: renew an active backup capture lease while draining or capturing.
CREATE FUNCTION openmettle.backup_renew_lease(
    p_backup_run_id uuid,
    p_lease_seconds integer DEFAULT 300)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    r openmettle.backup_runs%ROWTYPE;
    v_now timestamptz;
    v_new_lease timestamptz;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup lease renewal requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may renew a backup lease' USING ERRCODE = '42501';
    END IF;
    IF p_backup_run_id IS NULL
       OR p_lease_seconds IS NULL
       OR p_lease_seconds NOT BETWEEN 30 AND 3600 THEN
        RAISE EXCEPTION 'invalid backup lease renewal parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;
    IF NOT g.maintenance_active OR g.backup_run_id IS DISTINCT FROM p_backup_run_id THEN
        RAISE EXCEPTION 'backup run % does not own the maintenance window', p_backup_run_id
            USING ERRCODE = 'OMB02';
    END IF;

    SELECT * INTO r FROM openmettle.backup_runs WHERE id = p_backup_run_id FOR UPDATE;
    v_now := pg_catalog.clock_timestamp();
    IF NOT FOUND
       OR r.state NOT IN ('draining', 'capturing')
       OR r.lease_until IS NULL
       OR r.lease_until <= v_now THEN
        RAISE EXCEPTION 'backup run % lease is not active', p_backup_run_id
            USING ERRCODE = 'OMB02';
    END IF;

    v_new_lease := greatest(r.lease_until, v_now + pg_catalog.make_interval(secs => p_lease_seconds));
    UPDATE openmettle.backup_runs
       SET lease_until = v_new_lease
     WHERE id = p_backup_run_id;

    RETURN v_new_lease;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_renew_lease(uuid, integer) FROM PUBLIC;

-- Owner only: transition a draining backup run to capturing once all quiesce checks pass.
CREATE FUNCTION openmettle.backup_mark_quiesced(
    p_backup_run_id uuid,
    p_lease_seconds integer DEFAULT 300)
RETURNS TABLE(
    quiesced_at timestamptz,
    lease_until timestamptz)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    r openmettle.backup_runs%ROWTYPE;
    v_now timestamptz;
    v_new_lease timestamptz;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup quiesce transition requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may mark backup quiesced' USING ERRCODE = '42501';
    END IF;
    IF p_backup_run_id IS NULL
       OR p_lease_seconds IS NULL
       OR p_lease_seconds NOT BETWEEN 30 AND 3600 THEN
        RAISE EXCEPTION 'invalid backup quiesce parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;
    IF NOT g.maintenance_active OR g.backup_run_id IS DISTINCT FROM p_backup_run_id THEN
        RAISE EXCEPTION 'backup run % does not own the maintenance window', p_backup_run_id
            USING ERRCODE = 'OMB02';
    END IF;

    SELECT * INTO r FROM openmettle.backup_runs WHERE id = p_backup_run_id FOR UPDATE;
    v_now := pg_catalog.clock_timestamp();
    IF NOT FOUND
       OR r.state <> 'draining'
       OR r.lease_until IS NULL
       OR r.lease_until <= v_now THEN
        RAISE EXCEPTION 'backup run % is not draining with a live lease', p_backup_run_id
            USING ERRCODE = 'OMB02';
    END IF;

    v_now := greatest(v_now, g.entered_at);
    v_new_lease := greatest(r.lease_until, v_now + pg_catalog.make_interval(secs => p_lease_seconds));

    UPDATE openmettle.backup_runs
       SET state = 'capturing',
           quiesced_at = v_now,
           lease_until = v_new_lease
     WHERE id = p_backup_run_id;

    UPDATE openmettle.backup_maintenance_gate
       SET quiesced_at = v_now,
           updated_at = v_now
     WHERE id;

    RETURN QUERY SELECT v_now, v_new_lease;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_mark_quiesced(uuid, integer) FROM PUBLIC;

-- Owner only: record verified backup bundle completion and audit backup.capture_succeeded.
-- Maintenance remains active until an explicit backup_release_maintenance call.
CREATE FUNCTION openmettle.backup_complete_capture(
    p_backup_run_id uuid,
    p_encryption_key_id text,
    p_bundle_digest bytea,
    p_manifest_digest bytea,
    p_journal_origin_us bigint,
    p_journal_seq bigint,
    p_journal_chain_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL,
    p_manifest_summary jsonb DEFAULT '{}'::jsonb,
    p_reason text DEFAULT 'coordinated backup capture completed')
RETURNS timestamptz
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    r openmettle.backup_runs%ROWTYPE;
    v_now timestamptz;
    v_details jsonb;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup capture completion requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may complete backup capture' USING ERRCODE = '42501';
    END IF;
    IF p_backup_run_id IS NULL
       OR p_encryption_key_id IS NULL
       OR octet_length(p_encryption_key_id) NOT BETWEEN 1 AND 64
       OR p_encryption_key_id COLLATE "C" !~ '^[A-Za-z0-9._-]+$'
       OR p_bundle_digest IS NULL OR octet_length(p_bundle_digest) <> 32
       OR p_manifest_digest IS NULL OR octet_length(p_manifest_digest) <> 32
       OR p_journal_origin_us IS NULL OR p_journal_origin_us < 0
       OR p_journal_seq IS NULL OR p_journal_seq < 0
       OR p_journal_chain_digest IS NULL OR octet_length(p_journal_chain_digest) <> 32
       OR (p_lifecycle_origin_us IS NOT NULL AND p_lifecycle_origin_us < 0)
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32)
       OR (p_connection_origin_us IS NOT NULL AND p_connection_origin_us < 0)
       OR p_manifest_summary IS NULL
       OR jsonb_typeof(p_manifest_summary) <> 'object'
       OR octet_length(p_manifest_summary::text) > 16384
       OR NOT openmettle.capacity_valid_name(p_reason, 512) THEN
        RAISE EXCEPTION 'invalid backup completion parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;
    IF NOT g.maintenance_active OR g.backup_run_id IS DISTINCT FROM p_backup_run_id THEN
        RAISE EXCEPTION 'backup run % no longer owns the maintenance window', p_backup_run_id
            USING ERRCODE = 'OMB02';
    END IF;

    SELECT * INTO r FROM openmettle.backup_runs WHERE id = p_backup_run_id FOR UPDATE;
    v_now := pg_catalog.clock_timestamp();
    IF NOT FOUND
       OR r.state <> 'capturing'
       OR r.lease_until IS NULL
       OR r.lease_until <= v_now THEN
        RAISE EXCEPTION 'backup run % is not capturing with a live lease', p_backup_run_id
            USING ERRCODE = 'OMB02';
    END IF;

    v_now := greatest(v_now, r.quiesced_at);

    UPDATE openmettle.backup_runs
       SET state = 'succeeded',
           completed_at = v_now,
           lease_until = NULL,
           encryption_key_id = p_encryption_key_id,
           bundle_digest = p_bundle_digest,
           manifest_digest = p_manifest_digest,
           journal_origin_us = p_journal_origin_us,
           journal_seq = p_journal_seq,
           journal_chain_digest = p_journal_chain_digest,
           lifecycle_origin_us = p_lifecycle_origin_us,
           lifecycle_baseline_digest = p_lifecycle_baseline_digest,
           connection_origin_us = p_connection_origin_us,
           manifest_summary = p_manifest_summary
     WHERE id = p_backup_run_id;

    UPDATE openmettle.backup_maintenance_gate
       SET updated_at = v_now
     WHERE id;

    v_details := jsonb_build_object(
        'destination_domain', r.destination_domain,
        'encryption_key_id', p_encryption_key_id,
        'bundle_digest', encode(p_bundle_digest, 'hex'),
        'manifest_digest', encode(p_manifest_digest, 'hex'),
        'journal_origin_us', p_journal_origin_us,
        'journal_seq', p_journal_seq
    );
    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
         request_key, reason, details)
    VALUES
        ('operator', NULL, r.operator_id, 'backup.capture_succeeded', 'backup_run',
         p_backup_run_id::text, r.request_key, p_reason, v_details);

    RETURN v_now;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_complete_capture(
    uuid, text, bytea, bytea, bigint, bigint, bytea, bigint, bytea, bigint, jsonb, text
) FROM PUBLIC;

-- Owner only: mark a draining/capturing backup run failed and audit backup.capture_failed.
-- Always keeps backup_maintenance_gate.maintenance_active = true for explicit operator recovery.
CREATE FUNCTION openmettle.backup_fail_capture(
    p_backup_run_id uuid,
    p_failure_code text,
    p_reason text DEFAULT 'coordinated backup capture failed')
RETURNS timestamptz
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.backup_maintenance_gate%ROWTYPE;
    r openmettle.backup_runs%ROWTYPE;
    v_now timestamptz;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'backup capture failure recording requires READ COMMITTED'
            USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may fail backup capture' USING ERRCODE = '42501';
    END IF;
    IF p_backup_run_id IS NULL
       OR p_failure_code IS NULL
       OR octet_length(p_failure_code) NOT BETWEEN 1 AND 64
       OR p_failure_code COLLATE "C" !~ '^[a-z0-9_]+$'
       OR NOT openmettle.capacity_valid_name(p_reason, 512) THEN
        RAISE EXCEPTION 'invalid backup failure parameters' USING ERRCODE = '22023';
    END IF;

    SELECT * INTO STRICT g FROM openmettle.backup_maintenance_gate WHERE id FOR UPDATE;
    SELECT * INTO r FROM openmettle.backup_runs WHERE id = p_backup_run_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'backup run not found' USING ERRCODE = 'P0002';
    END IF;
    IF r.state IN ('succeeded', 'failed', 'incomplete') THEN
        RETURN r.completed_at;
    END IF;

    v_now := pg_catalog.clock_timestamp();

    UPDATE openmettle.backup_runs
       SET state = 'failed',
           completed_at = v_now,
           lease_until = NULL,
           failure_code = p_failure_code
     WHERE id = p_backup_run_id;

    UPDATE openmettle.backup_maintenance_gate
       SET updated_at = v_now
     WHERE id;

    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
         request_key, reason, details)
    VALUES
        ('operator', NULL, r.operator_id, 'backup.capture_failed', 'backup_run',
         p_backup_run_id::text, r.request_key, p_reason,
         jsonb_build_object(
             'failure_code', p_failure_code,
             'destination_domain', r.destination_domain
         ));

    RETURN v_now;
END
$$;
REVOKE ALL ON FUNCTION openmettle.backup_fail_capture(uuid, text, text) FROM PUBLIC;
