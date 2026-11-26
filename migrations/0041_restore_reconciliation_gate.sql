-- V1-16 migration 41 (ADR 0041 PR2b): the restore reconciliation gate, deletion journal origin
-- stamping, owner-only export verification/replay/break-glass functions, and policy revision
-- monotonicity across replay. Released migrations are immutable. Runs once per release as
-- openmettle_owner in one transaction with search_path pg_catalog,pg_temp; see
-- docs/adr/0003-schema-migrations.md.
--
-- A database cannot tell that it was restored, so the restore procedure closes the gate
-- (restore_gate_lock) before any API or worker starts. While it is closed no application role can
-- move a revision into 'purging' or 'purged' (restore_gate_guard_purge), so nothing appends to the
-- restored journal before replay, and the worker binary claims no run and runs no purge sweep.
-- The owner verifies the export's installation origin and locked watermark (restore_verify_export)
-- and replays records (deletion_journal_replay) in one READ COMMITTED transaction, stripping
-- resurrected mutable retention holds and advancing retention_policy.revision so post-restore
-- policy edits never reuse a replayed policy_revision. openmettle-admin then purges resurrected
-- payloads on the volume-pinned path, scrubs unsettled upload reservations, verifies volume and
-- ledger accounting, and calls restore_gate_open. The gate, the journal and its head grant
-- application roles nothing but the worker's SELECT on the gate row; src/boundaries.sql refuses
-- anything more.
--
-- Lock order (ADR 0005, ADR 0040, migration 28): artifact_revisions -> restore_reconciliation_gate
-- (FOR SHARE) -> storage_volume_control -> storage_accounts -> storage_instance ->
-- retention_policy -> deletion_journal_head. restore_gate_lock, restore_verify_export,
-- restore_gate_open and restore_accept_coverage_gap lock the gate row first and touch no storage
-- row.
--
-- Upgrade from 40: the gate starts open (a live database is not a restore), deletion_journal_head
-- records coverage_started_at from migration 28's installed_on timestamp (matching backups taken
-- at schema >= 28 and rejecting schema <= 27 backups migrated during restore with OMR04), and the
-- deletion journal hash chain continues unchanged. See
-- docs/operator/storage-adoption-and-quota-upgrade.md.

ALTER TABLE openmettle.deletion_journal_head
    ADD COLUMN coverage_started_at timestamptz;
UPDATE openmettle.deletion_journal_head
   SET coverage_started_at = coalesce(
       (SELECT installed_on FROM openmettle._sqlx_migrations WHERE version = 28),
       clock_timestamp()
   )
 WHERE id;
ALTER TABLE openmettle.deletion_journal_head
    ALTER COLUMN coverage_started_at SET NOT NULL,
    ALTER COLUMN coverage_started_at SET DEFAULT clock_timestamp();

CREATE TABLE openmettle.restore_reconciliation_gate (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    open boolean NOT NULL DEFAULT true,
    snapshot_journal_seq bigint CHECK (snapshot_journal_seq >= 0),
    required_journal_seq bigint,
    required_chain_digest bytea CHECK (octet_length(required_chain_digest) = 32),
    coverage_complete boolean NOT NULL DEFAULT true,
    locked_at timestamptz,
    opened_at timestamptz,
    CONSTRAINT restore_reconciliation_gate_closed_check CHECK (
        open OR (
            locked_at IS NOT NULL
            AND snapshot_journal_seq IS NOT NULL
            AND required_journal_seq >= snapshot_journal_seq
            AND required_chain_digest IS NOT NULL
            AND opened_at IS NULL
        )
    )
);
INSERT INTO openmettle.restore_reconciliation_gate (id) VALUES (true);
GRANT SELECT ON openmettle.restore_reconciliation_gate TO openmettle_worker;

-- Widen authorization_audit CHECK constraints additively under a bounded NOWAIT retry loop
-- so audited break-glass coverage-gap acceptance writes an operator audit row.
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
            'family_policy.model_disable', 'family_policy.model_enable',
            'restore.accept_coverage_gap')),
        DROP CONSTRAINT authorization_audit_target_kind_check,
        ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN (
            'user', 'project', 'conversation', 'artifact', 'local_group', 'capability',
            'scope', 'branch', 'quota_scope', 'retention_policy',
            'family_policy', 'oidc_group', 'restore_gate'));
END
$$;

-- While the gate is closed no application role may move a revision into 'purging' or 'purged'
-- (OMR02). FOR SHARE waits for a lock or open in flight; under READ COMMITTED the row is then
-- reread, and under REPEATABLE READ a change after the snapshot fails with 40001. The share lock
-- lasts until commit, journal append included, so restore_gate_lock waits for every transition
-- that passed this check. Alphabetical trigger order places artifact_revisions_restore_gate before
-- artifact_revisions_runtime_volume_pin_guard. The WHEN clause exempts openmettle_owner.
CREATE FUNCTION openmettle.restore_gate_guard_purge()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restore reconciliation pending' USING ERRCODE = 'OMR02';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_guard_purge() FROM PUBLIC;
CREATE TRIGGER artifact_revisions_restore_gate
    BEFORE UPDATE OF state ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (
        NEW.state IN ('purging', 'purged')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    )
    EXECUTE FUNCTION openmettle.restore_gate_guard_purge();

-- Preserve monotonic retention_policy.revision increments for ordinary updates while letting
-- restore replay advance revision to a higher replayed policy_revision so post-restore edits
-- never reuse a replayed policy revision number.
CREATE OR REPLACE FUNCTION openmettle.retention_policy_bump_revision()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    NEW.revision := greatest(OLD.revision + 1, coalesce(NEW.revision, OLD.revision + 1));
    RETURN NEW;
END
$$;

-- Migration 28's chain encoding, now shared by the append trigger and replay.
CREATE FUNCTION openmettle.deletion_journal_digest(p_previous bytea, e openmettle.deletion_journal)
RETURNS bytea LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT sha256(p_previous || convert_to(concat_ws('|',
        'openmettle.deletion_journal/1', e.journal_seq, e.event_kind, e.entity_id, e.scope_id,
        (extract(epoch FROM e.recorded_at) * 1000000)::bigint,
        (extract(epoch FROM e.original_purge_after) * 1000000)::bigint,
        (extract(epoch FROM e.purged_at) * 1000000)::bigint,
        encode(e.content_digest, 'hex'), coalesce(e.policy_revision::text, '')), 'UTF8'))
$$;
REVOKE ALL ON FUNCTION openmettle.deletion_journal_digest(bytea, openmettle.deletion_journal) FROM PUBLIC;

-- Migration 28's append, using the shared encoding. A revision enters 'purged' once, so a record
-- for it exists beforehand only when replay restored that record verbatim and the purge path is
-- now completing it; that confirmation appends nothing.
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
    e.chain_digest := openmettle.deletion_journal_digest(head.chain_digest, e);
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head SET journal_seq = e.journal_seq, chain_digest = e.chain_digest
     WHERE id;
    RETURN NULL;
END
$$;

-- Owner only. Closes the gate after a restore and before any API or worker starts, pinning the
-- independently recorded target watermark (p_required_seq, p_required_digest) and whether the
-- operator asserts complete post-quiesce export coverage (p_coverage_complete). The snapshot is
-- the restored journal head read after acquiring the gate lock. If p_required_seq <= head, its
-- digest must match the stored journal at p_required_seq (OMR03 otherwise). Re-locking a closed
-- gate preserves snapshot_journal_seq and locked_at and never lowers required_journal_seq.
CREATE FUNCTION openmettle.restore_gate_lock(
    p_required_seq bigint,
    p_required_digest bytea,
    p_coverage_complete boolean)
RETURNS openmettle.restore_reconciliation_gate
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_genesis bytea := decode(repeat('00', 32), 'hex');
    v_stored_digest bytea;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_required_seq IS NULL OR p_required_seq < 0
       OR p_required_digest IS NULL OR octet_length(p_required_digest) <> 32
       OR p_coverage_complete IS NULL THEN
        RAISE EXCEPTION 'invalid restore gate lock parameters' USING ERRCODE = '22023';
    END IF;
    IF p_required_seq = 0 AND p_required_digest <> v_genesis THEN
        RAISE EXCEPTION 'sequence 0 requires the genesis chain digest' USING ERRCODE = 'OMR03';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
    IF p_required_seq <= head.journal_seq THEN
        IF p_required_seq = 0 THEN
            v_stored_digest := v_genesis;
        ELSE
            SELECT chain_digest INTO v_stored_digest
              FROM openmettle.deletion_journal
             WHERE journal_seq = p_required_seq;
        END IF;
        IF v_stored_digest IS DISTINCT FROM p_required_digest THEN
            RAISE EXCEPTION 'required watermark digest does not match stored journal at %',
                p_required_seq USING ERRCODE = 'OMR03';
        END IF;
    END IF;
    IF g.open THEN
        g.snapshot_journal_seq := head.journal_seq;
        g.locked_at := clock_timestamp();
        g.opened_at := NULL;
        g.coverage_complete := p_coverage_complete;
        IF p_required_seq >= head.journal_seq THEN
            g.required_journal_seq := p_required_seq;
            g.required_chain_digest := p_required_digest;
        ELSE
            g.required_journal_seq := head.journal_seq;
            g.required_chain_digest := head.chain_digest;
        END IF;
    ELSE
        IF p_required_seq > g.required_journal_seq THEN
            g.required_journal_seq := p_required_seq;
            g.required_chain_digest := p_required_digest;
            g.coverage_complete := p_coverage_complete;
        ELSIF p_required_seq = g.required_journal_seq THEN
            IF p_required_digest <> g.required_chain_digest THEN
                RAISE EXCEPTION 'required watermark digest conflicts with locked gate'
                    USING ERRCODE = 'OMR03';
            END IF;
            g.coverage_complete := g.coverage_complete OR p_coverage_complete;
        ELSE
            IF p_required_seq > head.journal_seq THEN
                RAISE EXCEPTION 'cannot lower or verify partial watermark % below required %',
                    p_required_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
            END IF;
        END IF;
    END IF;
    UPDATE openmettle.restore_reconciliation_gate
       SET open = false,
           snapshot_journal_seq = g.snapshot_journal_seq,
           required_journal_seq = g.required_journal_seq,
           required_chain_digest = g.required_chain_digest,
           coverage_complete = g.coverage_complete,
           locked_at = g.locked_at,
           opened_at = NULL
     WHERE id
    RETURNING * INTO STRICT g;
    RETURN g;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock(bigint, bytea, boolean) FROM PUBLIC;

-- Owner only. Validates an export's target watermark and installation origin against the closed
-- restore gate and deletion_journal_head before deletion_journal_replay writes any row.
CREATE FUNCTION openmettle.restore_verify_export(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'export verification requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32 THEN
        RAISE EXCEPTION 'invalid export verification parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
    IF p_export_seq < g.snapshot_journal_seq
       OR p_export_seq < head.journal_seq
       OR p_export_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'export sequence % does not match locked restore requirement %',
            p_export_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'export watermark digest does not match locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    v_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    IF v_origin_us IS DISTINCT FROM p_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch: backup predates deletion journal creation or belongs to another installation'
            USING ERRCODE = 'OMR04';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_verify_export(bigint, bigint, bytea) FROM PUBLIC;

-- Owner only: replays one record of an export while the gate is closed. The caller verifies the
-- export header via restore_verify_export and sends every record in order in one READ COMMITTED
-- transaction, committing only if all pass. A record at or below the restored head must equal the
-- stored row (false). The next record must extend the chain and is stored verbatim (true). If the
-- restored database still holds the revision unpurged with matching content, resurrected mutable
-- retention holds are stripped and the revision moves to 'purging' under the journal's original
-- deadline and policy stamp; an active revision first shifts its bytes from active to retained.
-- retention_policy.revision advances to at least e.policy_revision so post-restore policy edits
-- never reuse a replayed policy revision number.
CREATE FUNCTION openmettle.deletion_journal_replay(
    p_seq bigint, p_recorded_us bigint, p_event_kind text, p_entity_id uuid, p_scope_id uuid,
    p_original_purge_after_us bigint, p_purged_us bigint, p_content_digest bytea,
    p_policy_revision bigint, p_chain_digest bytea)
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
       OR p_event_kind IS DISTINCT FROM 'artifact_revision.purged'
       OR p_entity_id IS NULL OR p_scope_id IS NULL
       OR p_original_purge_after_us IS NULL OR p_purged_us IS NULL
       OR p_content_digest IS NULL OR octet_length(p_content_digest) <> 32
       OR p_chain_digest IS NULL OR octet_length(p_chain_digest) <> 32 THEN
        RAISE EXCEPTION 'invalid journal replay record' USING ERRCODE = 'OMR03';
    END IF;
    e.journal_seq := p_seq;
    e.recorded_at := timestamptz 'epoch' + p_recorded_us * interval '1 microsecond';
    e.event_kind := p_event_kind;
    e.entity_id := p_entity_id;
    e.scope_id := p_scope_id;
    e.original_purge_after := timestamptz 'epoch' + p_original_purge_after_us * interval '1 microsecond';
    e.purged_at := timestamptz 'epoch' + p_purged_us * interval '1 microsecond';
    e.content_digest := p_content_digest;
    e.policy_revision := p_policy_revision;
    e.chain_digest := p_chain_digest;
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
    IF v_state = 'purged' THEN
        RAISE EXCEPTION 'journal record % names a revision already purged under another sequence', p_seq
            USING ERRCODE = 'OMR03';
    END IF;
    IF EXISTS (SELECT FROM openmettle.deletion_journal
                WHERE event_kind = e.event_kind AND entity_id = e.entity_id) THEN
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
        UPDATE openmettle.artifact_revisions
           SET state = 'purging', retained_at = coalesce(retained_at, e.original_purge_after),
               purge_after = e.original_purge_after, retention_policy_revision = e.policy_revision,
               purging_at = clock_timestamp()
         WHERE scope_id = p_scope_id AND id = p_entity_id;
    END IF;
    IF e.policy_revision IS NOT NULL THEN
        UPDATE openmettle.retention_policy
           SET revision = e.policy_revision
         WHERE id AND revision < e.policy_revision;
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
    bigint, bytea, bigint, bytea) FROM PUBLIC;

-- Owner only: opens a closed gate when coverage_complete is true (else OMR04), the restored head
-- matches both the replayed export watermark and the locked requirement (OMR04 / OMR03), and every
-- revision named in deletion_journal is purged (OMR05). Requires READ COMMITTED.
CREATE FUNCTION openmettle.restore_gate_open(p_export_seq bigint, p_export_digest bytea)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'restore gate is not closed' USING ERRCODE = 'OMR02';
    END IF;
    IF NOT g.coverage_complete THEN
        RAISE EXCEPTION 'unexported purge window after last export; inspect or run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
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
    IF EXISTS (SELECT FROM openmettle.deletion_journal j JOIN openmettle.artifact_revisions r
                 ON r.scope_id = j.scope_id AND r.id = j.entity_id WHERE r.state <> 'purged') THEN
        RAISE EXCEPTION 'journaled revisions are not purged yet' USING ERRCODE = 'OMR05';
    END IF;
    UPDATE openmettle.restore_reconciliation_gate SET open = true, opened_at = clock_timestamp()
     WHERE id;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_open(bigint, bytea) FROM PUBLIC;

-- Owner only: audited break-glass acceptance of an unexported purge window after the last
-- surviving journal export (for example catastrophic primary loss without a post-quiesce export).
-- Sets coverage_complete = true on a closed gate and records an operator row in
-- authorization_audit. Idempotent on exact replay (false); mismatched parameters raise 23505.
CREATE FUNCTION openmettle.restore_accept_coverage_gap(
    p_operator_id uuid,
    p_request_key text,
    p_reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    v_details jsonb;
    v_existing record;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_operator_id IS NULL
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 512
       OR btrim(p_reason) <> p_reason
       OR p_reason COLLATE "C" ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid coverage gap acceptance parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'restore gate is not closed' USING ERRCODE = 'OMR02';
    END IF;
    v_details := jsonb_build_object(
        'snapshot_journal_seq', g.snapshot_journal_seq,
        'required_journal_seq', g.required_journal_seq,
        'required_chain_digest', encode(g.required_chain_digest, 'hex')
    );
    SELECT actor_kind, operator_id, target_kind, target_id, reason, details
      INTO v_existing
      FROM openmettle.authorization_audit
     WHERE action = 'restore.accept_coverage_gap'
       AND request_key = p_request_key;
    IF FOUND THEN
        IF v_existing.actor_kind = 'operator'
           AND v_existing.operator_id = p_operator_id
           AND v_existing.target_kind = 'restore_gate'
           AND v_existing.target_id = 'instance'
           AND v_existing.reason = p_reason
           AND v_existing.details = v_details THEN
            RETURN false;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;
    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id, request_key, reason, details)
    VALUES
        ('operator', NULL, p_operator_id, 'restore.accept_coverage_gap', 'restore_gate',
         'instance', p_request_key, p_reason, v_details);
    UPDATE openmettle.restore_reconciliation_gate
       SET coverage_complete = true
     WHERE id;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_accept_coverage_gap(uuid, text, text) FROM PUBLIC;
