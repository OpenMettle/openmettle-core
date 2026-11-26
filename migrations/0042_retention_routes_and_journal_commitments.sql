-- V1-16 migration 42 (ADR 0041 PR3): journaled deadline commitments and pre-expiry restores,
-- extended restore-gate guards on artifact_revisions, least-privilege API restore-gate helper
-- execution, idempotent retention_set_grace, audited account_admin deadline preview/apply, and
-- read-only admin_retention_status projection. Released migrations are immutable.
-- Runs once per release as openmettle_owner in one transaction with search_path
-- pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (ADR 0005, ADR 0027, ADR 0040, ADR 0041):
--   account_admin_lock -> projects -> login_providers -> local_identity_approvals ->
--   users (ascending id) -> runs -> storage_reservations -> artifacts ->
--   artifact_revisions (scope_id, id) -> restore_reconciliation_gate (FOR SHARE) ->
--   storage_volume_control -> storage_accounts -> storage_instance ->
--   retention_policy -> deletion_journal_head (deferred at commit).
--
-- Upgrade from 41: existing deletion_journal rows (all 'artifact_revision.purged') keep
-- retained_at = NULL and preserve their exact openmettle.deletion_journal/1 chain digest.
-- New lifecycle transitions ('artifact_revision.retained', 'artifact_revision.deadline_adjusted',
-- 'artifact_revision.restored') append domain-separated openmettle.deletion_journal/2 records on
-- the same monotonic hash chain.

-- Acquire ACCESS EXCLUSIVE on every pre-existing table modified by migration 42 in one atomic
-- bounded NOWAIT retry loop at the top of the transaction so concurrent 0041 writers cannot
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
            LOCK TABLE openmettle.artifact_revisions,
                       openmettle.authorization_audit,
                       openmettle.retention_policy,
                       openmettle.deletion_journal,
                       openmettle.deletion_journal_head,
                       openmettle.restore_reconciliation_gate
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

-- Extend deletion_journal to record disassociations (active -> retained), explicit admin
-- deadline adjustments on retained revisions, and pre-expiry restores (retained -> active)
-- alongside terminal purges. A revision may be retained, restored before expiry, and retained
-- again, so uniqueness on (event_kind, entity_id) applies only to terminal purges.
ALTER TABLE openmettle.deletion_journal
    ADD COLUMN retained_at timestamptz,
    ALTER COLUMN original_purge_after DROP NOT NULL,
    ALTER COLUMN purged_at DROP NOT NULL,
    DROP CONSTRAINT deletion_journal_event_kind_check,
    DROP CONSTRAINT deletion_journal_entity_key,
    ADD CONSTRAINT deletion_journal_event_kind_check CHECK (event_kind IN (
        'artifact_revision.purged',
        'artifact_revision.retained',
        'artifact_revision.deadline_adjusted',
        'artifact_revision.restored'
    )),
    ADD CONSTRAINT deletion_journal_fields_check CHECK (
        (
            event_kind = 'artifact_revision.purged'
            AND original_purge_after IS NOT NULL
            AND purged_at IS NOT NULL
            AND retained_at IS NULL
        )
        OR (
            event_kind IN ('artifact_revision.retained', 'artifact_revision.deadline_adjusted')
            AND retained_at IS NOT NULL
            AND original_purge_after IS NOT NULL
            AND original_purge_after >= retained_at
            AND purged_at IS NULL
        )
        OR (
            event_kind = 'artifact_revision.restored'
            AND retained_at IS NULL
            AND original_purge_after IS NULL
            AND purged_at IS NULL
        )
    );

CREATE UNIQUE INDEX deletion_journal_purged_entity_idx
    ON openmettle.deletion_journal (event_kind, entity_id)
    WHERE event_kind = 'artifact_revision.purged';

-- Preserve migration 28/41 openmettle.deletion_journal/1 digest for purged records so upgraded
-- chains verify identically, and use domain-separated openmettle.deletion_journal/2 for retained,
-- deadline_adjusted and restored commitments (which include retained_at and nullable timestamps).
CREATE OR REPLACE FUNCTION openmettle.deletion_journal_digest(
    p_previous bytea,
    e openmettle.deletion_journal)
RETURNS bytea LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT CASE
        WHEN e.event_kind = 'artifact_revision.purged' THEN
            sha256(p_previous || convert_to(concat_ws('|',
                'openmettle.deletion_journal/1', e.journal_seq, e.event_kind, e.entity_id, e.scope_id,
                (extract(epoch FROM e.recorded_at) * 1000000)::bigint,
                (extract(epoch FROM e.original_purge_after) * 1000000)::bigint,
                (extract(epoch FROM e.purged_at) * 1000000)::bigint,
                encode(e.content_digest, 'hex'), coalesce(e.policy_revision::text, '')), 'UTF8'))
        ELSE
            sha256(p_previous || convert_to(concat_ws('|',
                'openmettle.deletion_journal/2', e.journal_seq, e.event_kind, e.entity_id, e.scope_id,
                (extract(epoch FROM e.recorded_at) * 1000000)::bigint,
                coalesce(((extract(epoch FROM e.retained_at) * 1000000)::bigint)::text, ''),
                coalesce(((extract(epoch FROM e.original_purge_after) * 1000000)::bigint)::text, ''),
                coalesce(((extract(epoch FROM e.purged_at) * 1000000)::bigint)::text, ''),
                encode(e.content_digest, 'hex'), coalesce(e.policy_revision::text, '')), 'UTF8'))
    END
$$;

-- Keep migration 28's deadline stamping for all normal disassociations while letting owner
-- deletion_journal_replay preserve exact journaled retained_at, purge_after and policy_revision
-- without restarting the grace window.
DROP TRIGGER artifact_revisions_retention_deadline ON openmettle.artifact_revisions;
CREATE TRIGGER artifact_revisions_retention_deadline
    BEFORE UPDATE OF state ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (
        OLD.state = 'active'
        AND NEW.state = 'retained'
        AND pg_catalog.has_column_privilege('openmettle.artifact_revisions', 'purge_after', 'UPDATE')
        AND NOT (
            pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
            AND pg_catalog.current_setting('openmettle.replaying_deletion_journal', true) IS NOT DISTINCT FROM 'on'
        )
    )
    EXECUTE FUNCTION openmettle.retention_stamp_deadline();

-- Extend the restore-gate guard on artifact_revisions so no application role can mutate state,
-- retained_at, purge_after or retention_policy_revision while restore_reconciliation_gate is
-- closed (OMR02). Alphabetical trigger order keeps artifact_revisions_restore_gate before
-- artifact_revisions_retention_deadline and artifact_revisions_runtime_volume_pin_guard.
DROP TRIGGER artifact_revisions_restore_gate ON openmettle.artifact_revisions;
CREATE TRIGGER artifact_revisions_restore_gate
    BEFORE UPDATE OF state, retained_at, purge_after, retention_policy_revision
    ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (
        (
            NEW.state IS DISTINCT FROM OLD.state
            OR NEW.retained_at IS DISTINCT FROM OLD.retained_at
            OR NEW.purge_after IS DISTINCT FROM OLD.purge_after
            OR NEW.retention_policy_revision IS DISTINCT FROM OLD.retention_policy_revision
        )
        AND NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    )
    EXECUTE FUNCTION openmettle.restore_gate_guard_purge();

-- Update purge append trigger function for the 11-column deletion_journal rowtype.
CREATE OR REPLACE FUNCTION openmettle.deletion_journal_append_purge()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    head openmettle.deletion_journal_head%ROWTYPE;
    e openmettle.deletion_journal%ROWTYPE;
BEGIN
    IF EXISTS (SELECT FROM openmettle.deletion_journal
                WHERE event_kind = 'artifact_revision.purged' AND entity_id = NEW.id) THEN
        RETURN NULL;
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    e.journal_seq := head.journal_seq + 1;
    e.recorded_at := clock_timestamp();
    e.event_kind := 'artifact_revision.purged';
    e.entity_id := NEW.id;
    e.scope_id := NEW.scope_id;
    e.original_purge_after := NEW.purge_after;
    e.purged_at := NEW.purged_at;
    e.content_digest := NEW.content_digest;
    e.policy_revision := NEW.retention_policy_revision;
    e.retained_at := NULL;
    e.chain_digest := openmettle.deletion_journal_digest(head.chain_digest, e);
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head SET journal_seq = e.journal_seq, chain_digest = e.chain_digest
     WHERE id;
    RETURN NULL;
END
$$;

-- Deferred append trigger for retained, deadline_adjusted and restored lifecycle commitments.
-- Fires at commit so deletion_journal_head is always locked last and rolled-back savepoints or
-- transactions append nothing. Skipped during owner deletion_journal_replay via the trigger WHEN
-- guard evaluated at statement execution time.
CREATE FUNCTION openmettle.deletion_journal_append_lifecycle()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    head openmettle.deletion_journal_head%ROWTYPE;
    e openmettle.deletion_journal%ROWTYPE;
BEGIN
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    e.journal_seq := head.journal_seq + 1;
    e.recorded_at := clock_timestamp();
    e.entity_id := NEW.id;
    e.scope_id := NEW.scope_id;
    e.content_digest := NEW.content_digest;
    e.purged_at := NULL;
    IF OLD.state = 'active' AND NEW.state = 'retained' THEN
        e.event_kind := 'artifact_revision.retained';
        e.retained_at := NEW.retained_at;
        e.original_purge_after := NEW.purge_after;
        e.policy_revision := NEW.retention_policy_revision;
    ELSIF OLD.state = 'retained' AND NEW.state = 'retained' AND NEW.purge_after IS DISTINCT FROM OLD.purge_after THEN
        e.event_kind := 'artifact_revision.deadline_adjusted';
        e.retained_at := NEW.retained_at;
        e.original_purge_after := NEW.purge_after;
        e.policy_revision := NEW.retention_policy_revision;
    ELSIF OLD.state = 'retained' AND NEW.state = 'active' THEN
        e.event_kind := 'artifact_revision.restored';
        e.retained_at := NULL;
        e.original_purge_after := NULL;
        e.policy_revision := NULL;
    ELSE
        RETURN NULL;
    END IF;
    e.chain_digest := openmettle.deletion_journal_digest(head.chain_digest, e);
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head SET journal_seq = e.journal_seq, chain_digest = e.chain_digest
     WHERE id;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.deletion_journal_append_lifecycle() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER artifact_revisions_lifecycle_journal
    AFTER UPDATE OF state, purge_after ON openmettle.artifact_revisions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (
        (
            (OLD.state = 'active' AND NEW.state = 'retained')
            OR (OLD.state = 'retained' AND NEW.state = 'retained' AND NEW.purge_after IS DISTINCT FROM OLD.purge_after)
            OR (OLD.state = 'retained' AND NEW.state = 'active')
        )
        AND NOT (
            pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
            AND pg_catalog.current_setting('openmettle.replaying_deletion_journal', true) IS NOT DISTINCT FROM 'on'
        )
    )
    EXECUTE FUNCTION openmettle.deletion_journal_append_lifecycle();

-- Owner only: replay any of the four deletion_journal event kinds in strict journal_seq order.
-- Replaces migration 41's 10-arg form with an 11-arg form whose trailing p_retained_us defaults
-- to NULL so 10-arg purged callers remain valid.
DROP FUNCTION openmettle.deletion_journal_replay(bigint, bigint, text, uuid, uuid, bigint, bigint,
    bytea, bigint, bytea);

CREATE FUNCTION openmettle.deletion_journal_replay(
    p_seq bigint, p_recorded_us bigint, p_event_kind text, p_entity_id uuid, p_scope_id uuid,
    p_original_purge_after_us bigint, p_purged_us bigint, p_content_digest bytea,
    p_policy_revision bigint, p_chain_digest bytea, p_retained_us bigint DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    e openmettle.deletion_journal%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_state text;
    v_size bigint;
    v_content bytea;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'journal replay requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_seq IS NULL OR p_seq <= 0 OR p_recorded_us IS NULL
       OR p_event_kind IS NULL
       OR p_entity_id IS NULL OR p_scope_id IS NULL
       OR p_content_digest IS NULL OR octet_length(p_content_digest) <> 32
       OR p_chain_digest IS NULL OR octet_length(p_chain_digest) <> 32
       OR (p_policy_revision IS NOT NULL AND p_policy_revision <= 0) THEN
        RAISE EXCEPTION 'invalid journal replay record' USING ERRCODE = 'OMR03';
    END IF;
    IF p_event_kind = 'artifact_revision.purged' THEN
        IF p_original_purge_after_us IS NULL OR p_purged_us IS NULL OR p_retained_us IS NOT NULL THEN
            RAISE EXCEPTION 'invalid purged journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_event_kind IN ('artifact_revision.retained', 'artifact_revision.deadline_adjusted') THEN
        IF p_retained_us IS NULL OR p_original_purge_after_us IS NULL
           OR p_original_purge_after_us < p_retained_us OR p_purged_us IS NOT NULL THEN
            RAISE EXCEPTION 'invalid retention journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_event_kind = 'artifact_revision.restored' THEN
        IF p_retained_us IS NOT NULL OR p_original_purge_after_us IS NOT NULL OR p_purged_us IS NOT NULL THEN
            RAISE EXCEPTION 'invalid restore journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown journal replay event kind' USING ERRCODE = 'OMR03';
    END IF;

    e.journal_seq := p_seq;
    e.recorded_at := timestamptz 'epoch' + p_recorded_us * interval '1 microsecond';
    e.event_kind := p_event_kind;
    e.entity_id := p_entity_id;
    e.scope_id := p_scope_id;
    e.original_purge_after := CASE WHEN p_original_purge_after_us IS NOT NULL
        THEN timestamptz 'epoch' + p_original_purge_after_us * interval '1 microsecond' END;
    e.purged_at := CASE WHEN p_purged_us IS NOT NULL
        THEN timestamptz 'epoch' + p_purged_us * interval '1 microsecond' END;
    e.content_digest := p_content_digest;
    e.policy_revision := p_policy_revision;
    e.chain_digest := p_chain_digest;
    e.retained_at := CASE WHEN p_retained_us IS NOT NULL
        THEN timestamptz 'epoch' + p_retained_us * interval '1 microsecond' END;

    IF p_seq <= (SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id) THEN
        PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF NOT EXISTS (SELECT FROM openmettle.deletion_journal j
                        WHERE j.journal_seq = p_seq AND j IS NOT DISTINCT FROM e) THEN
            RAISE EXCEPTION 'exported journal record % differs from the restored journal', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        RETURN false;
    END IF;

    SELECT state, size_bytes, content_digest INTO v_state, v_size, v_content
      FROM openmettle.artifact_revisions WHERE scope_id = p_scope_id AND id = p_entity_id FOR UPDATE;
    PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
    END IF;
    IF v_state IS NOT NULL AND v_content IS DISTINCT FROM p_content_digest THEN
        RAISE EXCEPTION 'journal record % names a revision with other content', p_seq
            USING ERRCODE = 'OMR03';
    END IF;

    IF p_event_kind = 'artifact_revision.purged' THEN
        IF v_state = 'purged' THEN
            RAISE EXCEPTION 'journal record % names a revision already purged under another sequence', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        IF EXISTS (SELECT FROM openmettle.deletion_journal
                    WHERE event_kind = 'artifact_revision.purged' AND entity_id = e.entity_id) THEN
            RAISE EXCEPTION 'journal record % duplicates an existing purged entity', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        DELETE FROM openmettle.artifact_retention_holds
         WHERE scope_id = p_scope_id AND artifact_revision_id = p_entity_id;
        IF v_state = 'active' THEN
            PERFORM openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
             WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
            UPDATE openmettle.storage_accounts
               SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size
             WHERE scope_id = p_scope_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
            END IF;
            UPDATE openmettle.storage_instance
               SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size;
        END IF;
        IF v_state IN ('active', 'retained') THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.artifact_revisions
               SET state = 'purging',
                   retained_at = least(coalesce(retained_at, e.original_purge_after), e.original_purge_after),
                   purge_after = e.original_purge_after,
                   retention_policy_revision = e.policy_revision,
                   purging_at = greatest(clock_timestamp(), e.original_purge_after)
             WHERE scope_id = p_scope_id AND id = p_entity_id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind IN ('artifact_revision.retained', 'artifact_revision.deadline_adjusted') THEN
        IF v_state IN ('purging', 'purged') THEN
            RAISE EXCEPTION 'journal record % cannot transition a purging or purged revision', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        IF v_state = 'active' THEN
            PERFORM openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
             WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
            UPDATE openmettle.storage_accounts
               SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size
             WHERE scope_id = p_scope_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
            END IF;
            UPDATE openmettle.storage_instance
               SET active_bytes = active_bytes - v_size, retained_bytes = retained_bytes + v_size;
        END IF;
        IF v_state IN ('active', 'retained') THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.artifact_revisions
               SET state = 'retained',
                   retained_at = e.retained_at,
                   purge_after = e.original_purge_after,
                   retention_policy_revision = e.policy_revision
             WHERE scope_id = p_scope_id AND id = p_entity_id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind = 'artifact_revision.restored' THEN
        IF v_state IN ('purging', 'purged') THEN
            RAISE EXCEPTION 'journal record % cannot restore a purging or purged revision', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        IF v_state = 'retained' THEN
            PERFORM openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
             WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
            UPDATE openmettle.storage_accounts
               SET retained_bytes = retained_bytes - v_size, active_bytes = active_bytes + v_size
             WHERE scope_id = p_scope_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
            END IF;
            UPDATE openmettle.storage_instance
               SET retained_bytes = retained_bytes - v_size, active_bytes = active_bytes + v_size;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.artifact_revisions
               SET state = 'active',
                   retained_at = NULL,
                   purge_after = NULL,
                   retention_policy_revision = NULL
             WHERE scope_id = p_scope_id AND id = p_entity_id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    END IF;

    IF e.policy_revision IS NOT NULL THEN
        UPDATE openmettle.retention_policy
           SET revision = e.policy_revision + 1
         WHERE id AND revision <= e.policy_revision;
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    IF p_seq <> head.journal_seq + 1
       OR p_chain_digest IS DISTINCT FROM openmettle.deletion_journal_digest(head.chain_digest, e) THEN
        RAISE EXCEPTION 'journal record % does not extend the restored chain', p_seq
            USING ERRCODE = 'OMR03';
    END IF;
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head SET journal_seq = p_seq, chain_digest = p_chain_digest
     WHERE id;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.deletion_journal_replay(bigint, bigint, text, uuid, uuid, bigint,
    bigint, bytea, bigint, bytea, bigint) FROM PUBLIC;

-- Require only 'artifact_revision.purged' journal rows to have state = 'purged' before opening
-- the restore gate; retained, deadline_adjusted and restored records leave revisions in retained
-- or active states as replayed.
CREATE OR REPLACE FUNCTION openmettle.restore_gate_open(
    p_restore_run_id uuid,
    p_claim_token uuid,
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_expected_volume_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_volume_id uuid;
    v_adoption_run_id uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL OR p_claim_token IS NULL
       OR p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32 THEN
        RAISE EXCEPTION 'invalid restore gate open parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'restore gate is not closed' USING ERRCODE = 'OMR02';
    END IF;
    IF g.restore_run_id IS DISTINCT FROM p_restore_run_id
       OR g.volume_claim_token IS DISTINCT FROM p_claim_token
       OR g.volume_lease_until IS NULL
       OR g.volume_lease_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase lease lost or mismatched' USING ERRCODE = 'OMR02';
    END IF;
    SELECT volume_id, adoption_run_id
      INTO STRICT v_volume_id, v_adoption_run_id
      FROM openmettle.storage_volume_control
     WHERE id
       FOR SHARE;
    IF v_adoption_run_id IS NOT NULL OR v_volume_id IS DISTINCT FROM p_expected_volume_id THEN
        RAISE EXCEPTION 'storage volume pin changed or adoption/rebind in progress'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF NOT g.coverage_complete THEN
        RAISE EXCEPTION 'unexported purge window after last export; inspect or run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
    v_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_seq IS DISTINCT FROM head.journal_seq
       OR head.journal_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export ends at %, the restored journal at %, restore requires %',
            p_export_seq, head.journal_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM head.chain_digest
       OR head.chain_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'journal chain digest does not match export or locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    PERFORM openmettle.restore_verify_checkpoints();
    IF EXISTS (SELECT FROM openmettle.deletion_journal j JOIN openmettle.artifact_revisions r
                 ON r.scope_id = j.scope_id AND r.id = j.entity_id
                WHERE j.event_kind = 'artifact_revision.purged' AND r.state <> 'purged') THEN
        RAISE EXCEPTION 'journaled revisions are not purged yet' USING ERRCODE = 'OMR05';
    END IF;
    UPDATE openmettle.restore_reconciliation_gate
       SET open = true,
           opened_at = clock_timestamp(),
           restore_run_id = NULL,
           required_origin_us = NULL,
           checkpoints = '[]'::jsonb,
           volume_claim_token = NULL,
           volume_lease_until = NULL
     WHERE id;
END
$$;

-- Least-privilege restore-gate check for openmettle_api: acquires FOR SHARE when open without
-- granting openmettle_api direct SELECT on restore_reconciliation_gate.
GRANT EXECUTE ON FUNCTION openmettle.restore_gate_lock_open() TO openmettle_api;

-- Widen authorization_audit action check additively for PR3 routes.
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
        'artifact.delete', 'artifact_revision.delete', 'artifact_revision.restore',
        'family_policy.set', 'family_policy.clear',
        'family_policy.model_study_allow', 'family_policy.model_study_revoke',
        'family_policy.model_disable', 'family_policy.model_enable',
        'restore.accept_coverage_gap'));

-- Internal owner-only helper shared by the retention admin functions to verify full live
-- approval-bound account_admin authority at p_now_ms (42501 with DETAIL distinguishing
-- inactive_principal vs not_account_admin for accurate HTTP 401/403 mapping).
CREATE FUNCTION openmettle.retention_assert_active_admin(
    p_actor uuid,
    p_approval uuid,
    p_now_ms bigint)
RETURNS void LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    v_is_admin boolean;
BEGIN
    IF p_actor IS NULL OR p_approval IS NULL OR p_now_ms IS NULL THEN
        RAISE EXCEPTION 'active principal required'
            USING ERRCODE = '42501', DETAIL = 'inactive_principal';
    END IF;
    SELECT EXISTS (
               SELECT FROM openmettle.account_admins adm
                WHERE adm.user_id = u.id AND adm.active
           )
      INTO v_is_admin
      FROM openmettle.users u
      JOIN openmettle.scopes sc ON sc.personal_user_id = u.id AND sc.kind = 'personal'
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
       AND a.expires_ms > p_now_ms;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'active principal required'
            USING ERRCODE = '42501', DETAIL = 'inactive_principal';
    END IF;
    IF NOT v_is_admin THEN
        RAISE EXCEPTION 'administrator required'
            USING ERRCODE = '42501', DETAIL = 'not_account_admin';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_assert_active_admin(uuid, uuid, bigint) FROM PUBLIC;

-- Update retention_set_grace (preserving migration 38's exact 5-argument signature, approval-bound
-- lock order and post-write authority recheck) to enforce the restore gate (OMR02) and support
-- idempotent replay on (actor_user_id, request_key) while raising 23505 on parameter mismatch.
CREATE OR REPLACE FUNCTION openmettle.retention_set_grace(
    p_actor uuid,
    p_approval uuid,
    p_grace_seconds integer,
    p_reason text,
    p_request_key text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    prior openmettle.retention_policy%ROWTYPE;
    v_existing record;
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
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);
    PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
    END IF;
    IF p_grace_seconds IS NULL OR p_reason IS NULL OR p_request_key IS NULL THEN
        RAISE EXCEPTION 'invalid retention policy parameters' USING ERRCODE = '23514';
    END IF;
    SELECT action, target_kind, target_id, reason, details
      INTO v_existing
      FROM openmettle.authorization_audit
     WHERE actor_user_id = p_actor
       AND request_key = p_request_key;
    IF FOUND THEN
        IF v_existing.action = 'retention.policy_update'
           AND v_existing.target_kind = 'retention_policy'
           AND v_existing.target_id = 'instance'
           AND v_existing.reason = p_reason
           AND (v_existing.details->>'new_grace_seconds') = p_grace_seconds::text THEN
            now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
            PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);
            RETURN (v_existing.details->>'revision')::bigint;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;
    SELECT * INTO STRICT prior FROM openmettle.retention_policy WHERE id FOR UPDATE;
    UPDATE openmettle.retention_policy SET grace_seconds = p_grace_seconds WHERE id
        RETURNING revision INTO STRICT rev;
    INSERT INTO openmettle.authorization_audit
        (actor_user_id, action, target_kind, target_id, request_key, reason, details)
    VALUES (p_actor, 'retention.policy_update', 'retention_policy', 'instance', p_request_key, p_reason,
            jsonb_build_object('old_grace_seconds', prior.grace_seconds,
                               'new_grace_seconds', p_grace_seconds, 'revision', rev));
    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);
    RETURN rev;
END
$$;

-- Audited account_admin read-only preview of adjusting existing 'retained' deadlines to
-- retained_at + p_target_grace_seconds. Exposes counts and total bytes only; never exposes
-- artifact IDs, filenames or content.
CREATE FUNCTION openmettle.retention_preview_deadlines(
    p_actor uuid,
    p_approval uuid,
    p_now_ms bigint,
    p_target_grace_seconds integer,
    p_scope_id uuid DEFAULT NULL)
RETURNS TABLE(
    affected_revisions bigint,
    affected_bytes bigint,
    current_policy_revision bigint,
    target_grace_seconds integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_policy openmettle.retention_policy%ROWTYPE;
    v_now_ms bigint;
BEGIN
    v_now_ms := coalesce(p_now_ms, floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint);
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, v_now_ms);
    SELECT * INTO STRICT v_policy FROM openmettle.retention_policy WHERE id;
    IF p_target_grace_seconds IS NULL
       OR p_target_grace_seconds < v_policy.min_grace_seconds
       OR p_target_grace_seconds > v_policy.max_grace_seconds THEN
        RAISE EXCEPTION 'target grace seconds outside deployment bounds' USING ERRCODE = '23514';
    END IF;
    IF p_scope_id IS NOT NULL
       AND NOT EXISTS (SELECT FROM openmettle.scopes WHERE id = p_scope_id) THEN
        RAISE EXCEPTION 'scope not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY
    SELECT count(*)::bigint,
           coalesce(sum(r.size_bytes), 0)::bigint,
           v_policy.revision,
           p_target_grace_seconds
      FROM openmettle.artifact_revisions r
     WHERE r.state = 'retained'
       AND (p_scope_id IS NULL OR r.scope_id = p_scope_id)
       AND r.purge_after IS DISTINCT FROM (r.retained_at + p_target_grace_seconds * interval '1 second');
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_preview_deadlines(uuid, uuid, bigint, integer, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.retention_preview_deadlines(uuid, uuid, bigint, integer, uuid) TO openmettle_api;

-- Audited account_admin explicit deadline adjustment for existing 'retained' revisions.
-- Follows canonical lock order (account_admin_lock -> login_providers -> local_identity_approvals
-- -> users -> artifact_revisions (scope_id, id) -> restore_reconciliation_gate FOR SHARE ->
-- retention_policy FOR SHARE -> authorization_audit -> deletion_journal_head at commit), appends
-- 'artifact_revision.deadline_adjusted' journal entries via the deferred trigger, records one
-- authorization_audit row with zero private metadata, supports exact replay on (actor, request_key)
-- and re-verifies live authority post-write.
CREATE FUNCTION openmettle.retention_apply_deadlines(
    p_actor uuid,
    p_approval uuid,
    p_expected_policy_revision bigint,
    p_target_grace_seconds integer,
    p_scope_id uuid,
    p_reason text,
    p_request_key text)
RETURNS TABLE(
    affected_revisions bigint,
    affected_bytes bigint,
    policy_revision bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_policy openmettle.retention_policy%ROWTYPE;
    v_existing record;
    v_target_id text;
    v_gate_open boolean;
    v_ids uuid[];
    v_affected_revisions bigint := 0;
    v_affected_bytes bigint := 0;
    now_ms bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'retention deadline adjustments require READ COMMITTED' USING ERRCODE = '25000';
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
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);
    IF p_expected_policy_revision IS NULL OR p_expected_policy_revision <= 0
       OR p_target_grace_seconds IS NULL
       OR p_reason IS NULL OR p_request_key IS NULL THEN
        RAISE EXCEPTION 'invalid retention deadline parameters' USING ERRCODE = '23514';
    END IF;
    v_target_id := coalesce(p_scope_id::text, 'instance');

    SELECT action, target_kind, target_id, reason, details
      INTO v_existing
      FROM openmettle.authorization_audit
     WHERE actor_user_id = p_actor
       AND request_key = p_request_key;
    IF FOUND THEN
        PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
        END IF;
        IF v_existing.action = 'retention.deadlines_apply'
           AND v_existing.target_kind = 'retention_policy'
           AND v_existing.target_id = v_target_id
           AND v_existing.reason = p_reason
           AND (v_existing.details->>'expected_policy_revision') = p_expected_policy_revision::text
           AND (v_existing.details->>'target_grace_seconds') = p_target_grace_seconds::text
           AND (v_existing.details->>'scope_id') IS NOT DISTINCT FROM p_scope_id::text THEN
            now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
            PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);
            RETURN QUERY
            SELECT (v_existing.details->>'affected_revisions')::bigint,
                   (v_existing.details->>'affected_bytes')::bigint,
                   (v_existing.details->>'policy_revision')::bigint;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;

    -- Fast non-locking pre-checks before acquiring row locks on artifact_revisions.
    SELECT open INTO STRICT v_gate_open FROM openmettle.restore_reconciliation_gate WHERE id;
    IF NOT v_gate_open THEN
        RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT v_policy FROM openmettle.retention_policy WHERE id;
    IF p_target_grace_seconds < v_policy.min_grace_seconds
       OR p_target_grace_seconds > v_policy.max_grace_seconds THEN
        RAISE EXCEPTION 'target grace seconds outside deployment bounds' USING ERRCODE = '23514';
    END IF;
    IF v_policy.revision <> p_expected_policy_revision THEN
        RAISE EXCEPTION 'retention policy revision % does not match expected %',
            v_policy.revision, p_expected_policy_revision USING ERRCODE = 'OMR06';
    END IF;
    IF p_scope_id IS NOT NULL
       AND NOT EXISTS (SELECT FROM openmettle.scopes WHERE id = p_scope_id) THEN
        RAISE EXCEPTION 'scope not found' USING ERRCODE = 'P0002';
    END IF;

    -- Lock matching retained revisions in canonical (scope_id, id) order before taking FOR SHARE
    -- on restore_reconciliation_gate and retention_policy.
    SELECT array_agg(t.id ORDER BY t.scope_id, t.id),
           count(*)::bigint,
           coalesce(sum(t.size_bytes), 0)::bigint
      INTO v_ids, v_affected_revisions, v_affected_bytes
      FROM (
          SELECT r.id, r.scope_id, r.size_bytes
            FROM openmettle.artifact_revisions r
           WHERE r.state = 'retained'
             AND (p_scope_id IS NULL OR r.scope_id = p_scope_id)
             AND r.purge_after IS DISTINCT FROM (r.retained_at + p_target_grace_seconds * interval '1 second')
           ORDER BY r.scope_id, r.id
             FOR UPDATE
      ) t;

    PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT v_policy FROM openmettle.retention_policy WHERE id FOR SHARE;
    IF p_target_grace_seconds < v_policy.min_grace_seconds
       OR p_target_grace_seconds > v_policy.max_grace_seconds THEN
        RAISE EXCEPTION 'target grace seconds outside deployment bounds' USING ERRCODE = '23514';
    END IF;
    IF v_policy.revision <> p_expected_policy_revision THEN
        RAISE EXCEPTION 'retention policy revision % does not match expected %',
            v_policy.revision, p_expected_policy_revision USING ERRCODE = 'OMR06';
    END IF;

    IF v_ids IS NOT NULL AND array_length(v_ids, 1) > 0 THEN
        UPDATE openmettle.artifact_revisions r
           SET purge_after = r.retained_at + p_target_grace_seconds * interval '1 second',
               retention_policy_revision = v_policy.revision
          FROM pg_catalog.unnest(v_ids) WITH ORDINALITY AS u(id, ord)
         WHERE r.id = u.id
           AND r.state = 'retained';
    END IF;

    INSERT INTO openmettle.authorization_audit
        (actor_user_id, action, target_kind, target_id, request_key, reason, details)
    VALUES (
        p_actor,
        'retention.deadlines_apply',
        'retention_policy',
        v_target_id,
        p_request_key,
        p_reason,
        jsonb_build_object(
            'expected_policy_revision', p_expected_policy_revision,
            'policy_revision', v_policy.revision,
            'target_grace_seconds', p_target_grace_seconds,
            'scope_id', p_scope_id,
            'affected_revisions', v_affected_revisions,
            'affected_bytes', v_affected_bytes
        )
    );

    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);

    RETURN QUERY SELECT v_affected_revisions, v_affected_bytes, v_policy.revision;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_apply_deadlines(uuid, uuid, bigint, integer, uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.retention_apply_deadlines(uuid, uuid, bigint, integer, uuid, text, text) TO openmettle_api;

-- Read-only SECURITY DEFINER projection for active account_admins: exposes retention policy,
-- restore-gate state (without volume_claim_token, restore_run_id or checkpoints) and deletion
-- journal head sequence/origin without granting openmettle_api direct SELECT on deletion_journal,
-- deletion_journal_head or restore_reconciliation_gate. Works even while the restore gate is closed.
CREATE FUNCTION openmettle.admin_retention_status(
    p_actor uuid,
    p_approval uuid,
    p_now_ms bigint)
RETURNS TABLE(
    policy_revision bigint,
    grace_seconds integer,
    min_grace_seconds integer,
    max_grace_seconds integer,
    gate_open boolean,
    snapshot_journal_seq bigint,
    required_journal_seq bigint,
    coverage_complete boolean,
    journal_seq bigint,
    coverage_started_at_us bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_now_ms bigint;
BEGIN
    v_now_ms := coalesce(p_now_ms, floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint);
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, v_now_ms);
    RETURN QUERY
    SELECT p.revision,
           p.grace_seconds,
           p.min_grace_seconds,
           p.max_grace_seconds,
           g.open,
           g.snapshot_journal_seq,
           g.required_journal_seq,
           g.coverage_complete,
           h.journal_seq,
           (extract(epoch FROM h.coverage_started_at) * 1000000)::bigint
      FROM openmettle.retention_policy p
      CROSS JOIN openmettle.restore_reconciliation_gate g
      CROSS JOIN openmettle.deletion_journal_head h
     WHERE p.id AND g.id AND h.id;
END
$$;
REVOKE ALL ON FUNCTION openmettle.admin_retention_status(uuid, uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.admin_retention_status(uuid, uuid, bigint) TO openmettle_api;
