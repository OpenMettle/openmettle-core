-- V1-16 migration 29 (ADR 0041 PR2b): the restore reconciliation gate and the owner's replay of an
-- exported deletion journal into a restored database. Released migrations are immutable. Runs
-- once per release as openmettle_owner in one transaction with search_path pg_catalog,pg_temp;
-- see docs/adr/0003-schema-migrations.md.
--
-- A database cannot tell that it was restored, so the restore procedure closes the gate
-- (restore_gate_lock) before any API or worker starts. While it is closed no application role can
-- move a revision into 'purging' or 'purged' (restore_gate_guard_purge), so nothing appends to the
-- restored journal before replay, and the worker binary claims no run and runs no purge sweep.
-- The owner replays an export (deletion_journal_replay), openmettle-admin purges the resurrected
-- payloads on the volume-pinned path, and restore_gate_open opens the gate only when the restored
-- journal ends at the export's watermark, reaches the required sequence and every revision the
-- journal names is purged. The gate, the journal and its head grant application roles nothing
-- but the worker's SELECT on the gate row; src/boundaries.sql refuses anything more.
--
-- Lock order (ADR 0005, ADR 0040, migration 28): artifact_revisions -> restore_reconciliation_gate
-- (FOR SHARE) -> storage_volume_control -> storage_accounts -> storage_instance ->
-- deletion_journal_head. restore_gate_lock and restore_gate_open lock the gate row alone and only
-- read afterwards.
--
-- Upgrade from 28: the gate starts open (a live database is not a restore) and the journal and its
-- head are unchanged; the append trigger keeps migration 28's encoding. Previous-release workers
-- purge as before while the gate is open. Once it is closed their purge claims and confirmations
-- fail with OMR02, but they still claim runs, so a restore must not start any of them. See
-- docs/operator/storage-adoption-and-quota-upgrade.md.

CREATE TABLE openmettle.restore_reconciliation_gate (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    open boolean NOT NULL DEFAULT true,
    snapshot_journal_seq bigint CHECK (snapshot_journal_seq >= 0),
    required_journal_seq bigint,
    locked_at timestamptz,
    opened_at timestamptz,
    CONSTRAINT restore_reconciliation_gate_closed_check CHECK (open OR (locked_at IS NOT NULL
        AND snapshot_journal_seq IS NOT NULL AND required_journal_seq >= snapshot_journal_seq
        AND opened_at IS NULL))
);
INSERT INTO openmettle.restore_reconciliation_gate (id) VALUES (true);
GRANT SELECT ON openmettle.restore_reconciliation_gate TO openmettle_worker;

-- While the gate is closed no application role may move a revision into 'purging' or 'purged'
-- (OMR02). FOR SHARE waits for a lock or open in flight; under READ COMMITTED the row is then
-- reread, and under REPEATABLE READ a change after the snapshot fails with 40001. The share lock
-- lasts until commit, journal append included, so restore_gate_lock waits for every transition
-- that passed this check. The WHEN clause runs as the caller and exempts the owner's replay.
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
CREATE TRIGGER artifact_revisions_restore_gate BEFORE UPDATE OF state ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (NEW.state IN ('purging', 'purged') AND NEW.state IS DISTINCT FROM OLD.state
        AND NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE'))
    EXECUTE FUNCTION openmettle.restore_gate_guard_purge();

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

-- Owner only. Closes the gate after a restore and before any API or worker starts. The snapshot
-- is the restored journal head, read in a statement after the gate lock: that lock waits for
-- every purge transition holding the guard's share lock, so their records are included. The
-- requirement is the larger of the snapshot and p_required_seq, the newest export watermark
-- known independently of the export to be replayed. Closing a closed gate keeps its snapshot
-- (replay may have advanced the head) and can only raise the requirement. READ COMMITTED.
CREATE FUNCTION openmettle.restore_gate_lock(p_required_seq bigint)
RETURNS openmettle.restore_reconciliation_gate
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    v_head bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    SELECT journal_seq INTO STRICT v_head FROM openmettle.deletion_journal_head WHERE id;
    IF g.open THEN
        g.snapshot_journal_seq := v_head;
        g.required_journal_seq := v_head;
        g.locked_at := clock_timestamp();
    END IF;
    UPDATE openmettle.restore_reconciliation_gate
       SET open = false, snapshot_journal_seq = g.snapshot_journal_seq, opened_at = NULL,
           required_journal_seq = greatest(g.required_journal_seq, p_required_seq), locked_at = g.locked_at
     WHERE id RETURNING * INTO STRICT g;
    RETURN g;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock(bigint) FROM PUBLIC;

-- Owner only: replays one record of an export while the gate is closed. The caller sends every
-- record of the export in order in one READ COMMITTED transaction and commits only if all pass.
-- A record at or below the restored head must equal the stored one (false). The next one must
-- extend the chain and is stored verbatim (true). If the restored database still holds its
-- revision unpurged with the same content, the revision moves to 'purging' under the journal's
-- original deadline and policy stamp, never a new grace window; an active one first shifts its
-- bytes to retained, as its removal did. The volume-pinned purge then deletes the resurrected
-- payload and releases the bytes once. A revision already 'purging' (a claim the backup captured)
-- keeps its claim; one already 'purged' has its own record, so the insert fails (23505). Anything
-- else that does not match raises OMR03; every error aborts the caller's transaction.
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
        PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open;
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
    IF v_content IS DISTINCT FROM p_content_digest AND v_state IS NOT NULL THEN
        RAISE EXCEPTION 'journal record % names a revision with other content', p_seq
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
        UPDATE openmettle.artifact_revisions
           SET state = 'purging', retained_at = coalesce(retained_at, e.original_purge_after),
               purge_after = e.original_purge_after, retention_policy_revision = e.policy_revision,
               purging_at = clock_timestamp()
         WHERE scope_id = p_scope_id AND id = p_entity_id;
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

-- Owner only: opens a closed gate when the restored journal ends exactly at the replayed
-- export's watermark (an export that lags the restored database, or a replay that stopped early,
-- does not) and reaches the required sequence (else OMR04), and every revision the journal names
-- is purged (else OMR05). Requires READ COMMITTED: the checks follow the gate lock and must see
-- what committed while it waited.
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
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
    IF (p_export_seq, p_export_digest) IS DISTINCT FROM (head.journal_seq, head.chain_digest) THEN
        RAISE EXCEPTION 'journal export ends at %, the restored journal at %', p_export_seq,
            head.journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF head.journal_seq < g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export ends at %, the restore requires %', head.journal_seq,
            g.required_journal_seq USING ERRCODE = 'OMR04';
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
