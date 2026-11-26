-- V1-16 migration 41 (ADR 0041 PR2b): the restore reconciliation gate, deletion journal origin
-- stamping, owner-only export verification/replay/checkpoint/volume-phase/break-glass functions,
-- worker gate lock helper, and policy revision monotonicity across replay. Released migrations are
-- immutable. Runs once per release as openmettle_owner in one transaction with search_path
-- pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- A database cannot tell that it was restored, so the restore procedure closes the gate
-- (restore_gate_lock) before any API or worker starts. While it is closed no application role can
-- move a revision into 'purging' or 'purged' (restore_gate_guard_purge), so nothing appends to the
-- restored journal before replay, and the worker claims no run (restore_gate_lock_open inside
-- claim_next / reclaim_next) and runs no purge sweep. The owner verifies the export's installation
-- origin and locked watermark (restore_verify_export), replays records (deletion_journal_replay)
-- and verifies all pinned checkpoints (restore_verify_checkpoints) in one READ COMMITTED
-- transaction, stripping resurrected mutable retention holds and advancing
-- retention_policy.revision strictly past every replayed policy_revision. openmettle-admin then
-- claims the restore volume phase lease (restore_claim_volume_phase), purges resurrected payloads
-- on the volume-pinned path, scrubs unsettled upload reservations, verifies volume and ledger
-- accounting, and calls restore_gate_open. The gate, the journal and its head grant application
-- roles nothing but the worker's SELECT on the gate row and EXECUTE on restore_gate_lock_open();
-- src/boundaries.sql refuses anything more.
--
-- Lock order (ADR 0005, ADR 0040, migration 28): run_dispatch_lock / artifact_revisions /
-- storage_reservations -> restore_reconciliation_gate (FOR SHARE) -> storage_volume_control ->
-- storage_accounts -> storage_instance -> retention_policy -> deletion_journal_head.
-- restore_gate_lock, restore_verify_export, restore_verify_checkpoints, restore_claim_volume_phase,
-- restore_renew_volume_phase, restore_release_volume_phase and restore_accept_coverage_gap lock
-- the gate row first and touch no storage or dispatch lock row; restore_gate_open locks the gate
-- row FOR UPDATE and then storage_volume_control FOR SHARE (in canonical order) before
-- deletion_journal_head FOR SHARE.
--
-- Upgrade from 40: the gate starts open (a live database is not a restore), deletion_journal_head
-- records coverage_started_at from migration 28's installed_on timestamp when _sqlx_migrations is
-- present (matching backups taken at schema >= 28 and rejecting schema <= 27 backups migrated
-- during restore with OMR04), and the deletion journal hash chain continues unchanged. See
-- docs/operator/storage-adoption-and-quota-upgrade.md.

-- Acquire ACCESS EXCLUSIVE on every pre-existing table modified by migration 41 in one atomic
-- bounded NOWAIT retry loop at the top of the transaction so concurrent 0040 writers (such as
-- confirm_purge locking artifact_revisions -> deletion_journal_head) cannot deadlock with DDL.
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
                       openmettle.deletion_journal_head
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

ALTER TABLE openmettle.deletion_journal_head
    ADD COLUMN coverage_started_at timestamptz;
DO $$
DECLARE
    v_started timestamptz;
BEGIN
    IF pg_catalog.to_regclass('openmettle._sqlx_migrations') IS NOT NULL THEN
        EXECUTE 'SELECT installed_on FROM openmettle._sqlx_migrations WHERE version = 28'
           INTO v_started;
    END IF;
    UPDATE openmettle.deletion_journal_head
       SET coverage_started_at = coalesce(v_started, pg_catalog.clock_timestamp())
     WHERE id;
END
$$;
ALTER TABLE openmettle.deletion_journal_head
    ALTER COLUMN coverage_started_at SET NOT NULL,
    ALTER COLUMN coverage_started_at SET DEFAULT clock_timestamp();

CREATE TABLE openmettle.restore_reconciliation_gate (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    open boolean NOT NULL DEFAULT true,
    restore_run_id uuid,
    required_origin_us bigint,
    snapshot_journal_seq bigint CHECK (snapshot_journal_seq >= 0),
    required_journal_seq bigint,
    required_chain_digest bytea CHECK (octet_length(required_chain_digest) = 32),
    checkpoints jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(checkpoints) = 'array'),
    coverage_complete boolean NOT NULL DEFAULT true,
    volume_claim_token uuid,
    volume_lease_until timestamptz,
    locked_at timestamptz,
    opened_at timestamptz,
    CONSTRAINT restore_reconciliation_gate_closed_check CHECK (
        (
            open
            AND restore_run_id IS NULL
            AND required_origin_us IS NULL
            AND checkpoints = '[]'::jsonb
            AND volume_claim_token IS NULL
            AND volume_lease_until IS NULL
        ) OR (
            NOT open
            AND restore_run_id IS NOT NULL
            AND required_origin_us IS NOT NULL
            AND locked_at IS NOT NULL
            AND snapshot_journal_seq IS NOT NULL
            AND required_journal_seq >= snapshot_journal_seq
            AND required_chain_digest IS NOT NULL
            AND opened_at IS NULL
            AND ((volume_claim_token IS NULL) = (volume_lease_until IS NULL))
        )
    )
);
INSERT INTO openmettle.restore_reconciliation_gate (id) VALUES (true);
GRANT SELECT ON openmettle.restore_reconciliation_gate TO openmettle_worker;

-- Widen authorization_audit CHECK constraints additively (ACCESS EXCLUSIVE is already held from
-- the top-of-migration atomic NOWAIT lock) so audited break-glass coverage-gap acceptance writes
-- an operator-only audit row.
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
        'family_policy', 'oidc_group', 'restore_gate')),
    ADD CONSTRAINT authorization_audit_restore_gate_check CHECK (
        (action = 'restore.accept_coverage_gap') = (target_kind = 'restore_gate')
        AND (
            action <> 'restore.accept_coverage_gap'
            OR (
                actor_kind = 'operator'
                AND actor_user_id IS NULL
                AND operator_id IS NOT NULL
                AND target_id = 'instance'
            )
        )
    );

-- Worker helper: locks the singleton restore gate row FOR SHARE inside a claim/reclaim transaction
-- without granting openmettle_worker UPDATE on restore_reconciliation_gate. Returns true only when
-- the gate is open, serializing with restore_gate_lock.
CREATE FUNCTION openmettle.restore_gate_lock_open()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM FROM openmettle.restore_reconciliation_gate WHERE id AND open FOR SHARE;
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.restore_gate_lock_open() TO openmettle_worker;

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
-- restore replay advance revision strictly past any replayed policy_revision so post-restore
-- removals and policy edits never reuse a replayed policy revision number.
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

-- Owner only. Closes the gate after a restore and before any API or worker starts, authenticating
-- the independently recorded installation origin (p_origin_us), target watermark
-- (p_required_seq, p_required_digest), and whether the operator asserts complete post-quiesce
-- export coverage (p_coverage_complete).
--
-- When the gate is open: requires p_new_restore = true and p_replace_restore_run IS NULL (OMR02),
-- mints a new restore_run_id, resets checkpoints, and sets coverage_complete = p_coverage_complete.
-- When the gate is already closed: requires p_replace_restore_run = g.restore_run_id and no active
-- volume-phase lease (OMR02). With p_new_restore = true (a fresh restore over a backup captured
-- while an earlier restore gate was closed), mints a new restore_run_id, resets snapshot_journal_seq
-- and checkpoints, and sets coverage_complete = p_coverage_complete without inheriting true. With
-- p_new_restore = false (updating the same in-progress restore), keeps restore_run_id,
-- snapshot_journal_seq and all pinned checkpoints (refusing conflicting digests with OMR03), and
-- never lowers required_journal_seq.
CREATE FUNCTION openmettle.restore_gate_lock(
    p_origin_us bigint,
    p_required_seq bigint,
    p_required_digest bytea,
    p_coverage_complete boolean,
    p_replace_restore_run uuid DEFAULT NULL,
    p_new_restore boolean DEFAULT true)
RETURNS openmettle.restore_reconciliation_gate
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_genesis bytea := decode(repeat('00', 32), 'hex');
    v_head_origin_us bigint;
    v_stored_digest bytea;
    v_digest_hex text;
    v_req_hex text;
    v_effective_required_seq bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_required_seq IS NULL OR p_required_seq < 0
       OR p_required_digest IS NULL OR octet_length(p_required_digest) <> 32
       OR p_coverage_complete IS NULL OR p_new_restore IS NULL THEN
        RAISE EXCEPTION 'invalid restore gate lock parameters' USING ERRCODE = '22023';
    END IF;
    IF p_required_seq = 0 AND p_required_digest <> v_genesis THEN
        RAISE EXCEPTION 'sequence 0 requires the genesis chain digest' USING ERRCODE = 'OMR03';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        IF NOT p_new_restore OR p_replace_restore_run IS NOT NULL THEN
            RAISE EXCEPTION 'cannot replace a restore run while the restore gate is open'
                USING ERRCODE = 'OMR02';
        END IF;
    ELSE
        IF p_replace_restore_run IS NULL OR p_replace_restore_run IS DISTINCT FROM g.restore_run_id THEN
            RAISE EXCEPTION 'restore gate is already closed; pass --replace-restore-run matching current restore_run_id'
                USING ERRCODE = 'OMR02';
        END IF;
        IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
            RAISE EXCEPTION 'restore volume phase is active' USING ERRCODE = 'OMR02';
        END IF;
        g.volume_claim_token := NULL;
        g.volume_lease_until := NULL;
    END IF;

    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
    v_head_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM v_head_origin_us THEN
        RAISE EXCEPTION 'required origin % does not match restored journal origin %',
            p_origin_us, v_head_origin_us USING ERRCODE = 'OMR04';
    END IF;
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
    IF g.open OR p_new_restore THEN
        v_effective_required_seq := head.journal_seq;
    ELSE
        v_effective_required_seq := greatest(head.journal_seq, g.required_journal_seq);
    END IF;
    IF p_coverage_complete AND p_required_seq < v_effective_required_seq THEN
        RAISE EXCEPTION 'cannot assert complete export coverage for watermark % below target sequence %',
            p_required_seq, v_effective_required_seq USING ERRCODE = 'OMR04';
    END IF;

    v_digest_hex := encode(p_required_digest, 'hex');
    IF g.open OR p_new_restore THEN
        g.restore_run_id := gen_random_uuid();
        g.required_origin_us := p_origin_us;
        g.snapshot_journal_seq := head.journal_seq;
        g.locked_at := clock_timestamp();
        g.opened_at := NULL;
        g.coverage_complete := p_coverage_complete;
        g.volume_claim_token := NULL;
        g.volume_lease_until := NULL;
        g.checkpoints := jsonb_build_array(
            jsonb_build_object('seq', p_required_seq, 'digest', v_digest_hex)
        );
        IF p_required_seq >= head.journal_seq THEN
            g.required_journal_seq := p_required_seq;
            g.required_chain_digest := p_required_digest;
        ELSE
            g.required_journal_seq := head.journal_seq;
            g.required_chain_digest := head.chain_digest;
            v_req_hex := encode(head.chain_digest, 'hex');
            g.checkpoints := g.checkpoints || jsonb_build_array(
                jsonb_build_object('seq', head.journal_seq, 'digest', v_req_hex)
            );
        END IF;
    ELSE
        IF p_origin_us IS DISTINCT FROM g.required_origin_us THEN
            RAISE EXCEPTION 'required origin % conflicts with locked restore origin %',
                p_origin_us, g.required_origin_us USING ERRCODE = 'OMR04';
        END IF;
        IF EXISTS (
            SELECT FROM pg_catalog.jsonb_array_elements(g.checkpoints) AS c
             WHERE (c->>'seq')::bigint = p_required_seq
               AND (c->>'digest') IS DISTINCT FROM v_digest_hex
        ) THEN
            RAISE EXCEPTION 'required watermark digest conflicts with pinned checkpoint at %',
                p_required_seq USING ERRCODE = 'OMR03';
        END IF;
        IF p_required_seq = g.required_journal_seq AND p_required_digest <> g.required_chain_digest THEN
            RAISE EXCEPTION 'required watermark digest conflicts with locked gate'
                USING ERRCODE = 'OMR03';
        END IF;
        IF NOT EXISTS (
            SELECT FROM pg_catalog.jsonb_array_elements(g.checkpoints) AS c
             WHERE (c->>'seq')::bigint = p_required_seq
        ) THEN
            g.checkpoints := g.checkpoints || jsonb_build_array(
                jsonb_build_object('seq', p_required_seq, 'digest', v_digest_hex)
            );
        END IF;
        IF p_required_seq > g.required_journal_seq THEN
            g.required_journal_seq := p_required_seq;
            g.required_chain_digest := p_required_digest;
            g.coverage_complete := p_coverage_complete;
        ELSIF p_required_seq = g.required_journal_seq THEN
            g.coverage_complete := g.coverage_complete OR p_coverage_complete;
        END IF;
    END IF;

    UPDATE openmettle.restore_reconciliation_gate
       SET open = false,
           restore_run_id = g.restore_run_id,
           required_origin_us = g.required_origin_us,
           snapshot_journal_seq = g.snapshot_journal_seq,
           required_journal_seq = g.required_journal_seq,
           required_chain_digest = g.required_chain_digest,
           checkpoints = g.checkpoints,
           coverage_complete = g.coverage_complete,
           volume_claim_token = NULL,
           volume_lease_until = NULL,
           locked_at = g.locked_at,
           opened_at = NULL
     WHERE id
    RETURNING * INTO STRICT g;
    RETURN g;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock(bigint, bigint, bytea, boolean, uuid, boolean) FROM PUBLIC;

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
    IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase is active' USING ERRCODE = 'OMR02';
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
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR v_origin_us IS DISTINCT FROM p_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch: backup predates deletion journal creation or belongs to another installation'
            USING ERRCODE = 'OMR04';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_verify_export(bigint, bigint, bytea) FROM PUBLIC;

-- Owner only. Verifies that deletion_journal_head matches the closed restore gate's required
-- watermark and that EVERY pinned (seq, digest) checkpoint in restore_reconciliation_gate.checkpoints
-- matches the restored deletion_journal (OMR03 on any missing or divergent checkpoint).
CREATE FUNCTION openmettle.restore_verify_checkpoints()
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    c jsonb;
    v_seq bigint;
    v_digest text;
    v_genesis text := repeat('00', 32);
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'checkpoint verification requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'checkpoint verification requires a closed restore gate' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
    IF head.journal_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'restored journal head % does not match required %',
            head.journal_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF head.chain_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'restored journal head digest does not match locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    FOR c IN SELECT value FROM pg_catalog.jsonb_array_elements(g.checkpoints)
    LOOP
        v_seq := (c->>'seq')::bigint;
        v_digest := c->>'digest';
        IF v_seq = 0 THEN
            IF v_digest IS DISTINCT FROM v_genesis THEN
                RAISE EXCEPTION 'pinned checkpoint at sequence 0 does not match genesis'
                    USING ERRCODE = 'OMR03';
            END IF;
        ELSIF NOT EXISTS (
            SELECT FROM openmettle.deletion_journal j
             WHERE j.journal_seq = v_seq
               AND encode(j.chain_digest, 'hex') = v_digest
        ) THEN
            RAISE EXCEPTION 'pinned checkpoint at sequence % does not match replayed journal', v_seq
                USING ERRCODE = 'OMR03';
        END IF;
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_verify_checkpoints() FROM PUBLIC;

-- Owner only: claims the exclusive volume-phase lease before purge_journaled / scrub_unsettled_on_restore.
-- Verifies closed gate, no live lease, matching origin/seq/digest, and all pinned checkpoints.
CREATE FUNCTION openmettle.restore_claim_volume_phase(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea)
RETURNS TABLE(restore_run_id uuid, volume_claim_token uuid)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_token uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore volume phase claim requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32 THEN
        RAISE EXCEPTION 'invalid restore volume phase parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'restore gate is not closed' USING ERRCODE = 'OMR02';
    END IF;
    IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase is already active' USING ERRCODE = 'OMR02';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
    v_origin_us := (extract(epoch FROM head.coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_seq IS DISTINCT FROM head.journal_seq OR head.journal_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export sequence does not match restored head or locked requirement'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM head.chain_digest OR head.chain_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'journal chain digest does not match export or locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    PERFORM openmettle.restore_verify_checkpoints();
    v_token := gen_random_uuid();
    UPDATE openmettle.restore_reconciliation_gate
       SET volume_claim_token = v_token,
           volume_lease_until = clock_timestamp() + interval '300 seconds'
     WHERE id;
    RETURN QUERY SELECT g.restore_run_id, v_token;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_claim_volume_phase(bigint, bigint, bytea) FROM PUBLIC;

-- Owner only: renews an active restore volume-phase lease (OMR02 if lost, expired, or gate moved).
CREATE FUNCTION openmettle.restore_renew_volume_phase(
    p_restore_run_id uuid,
    p_claim_token uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore volume phase renewal requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL OR p_claim_token IS NULL THEN
        RAISE EXCEPTION 'invalid restore volume phase renewal parameters' USING ERRCODE = '22023';
    END IF;
    UPDATE openmettle.restore_reconciliation_gate
       SET volume_lease_until = clock_timestamp() + interval '300 seconds'
     WHERE id
       AND NOT open
       AND restore_run_id = p_restore_run_id
       AND volume_claim_token = p_claim_token
       AND volume_lease_until > clock_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restore volume phase lease lost or gate moved' USING ERRCODE = 'OMR02';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_renew_volume_phase(uuid, uuid) FROM PUBLIC;

-- Owner only: asserts and locks FOR SHARE an active restore volume-phase lease inside a
-- purge/scrub write transaction (OMR02 if lost, expired, or gate moved).
CREATE FUNCTION openmettle.restore_assert_volume_phase(
    p_restore_run_id uuid,
    p_claim_token uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore volume phase assertion requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL OR p_claim_token IS NULL THEN
        RAISE EXCEPTION 'invalid restore volume phase assertion parameters' USING ERRCODE = '22023';
    END IF;
    PERFORM FROM openmettle.restore_reconciliation_gate
     WHERE id
       AND NOT open
       AND restore_run_id = p_restore_run_id
       AND volume_claim_token = p_claim_token
       AND volume_lease_until > clock_timestamp()
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restore volume phase lease lost or gate moved' USING ERRCODE = 'OMR02';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_assert_volume_phase(uuid, uuid) FROM PUBLIC;

-- Owner only: releases the caller's own restore volume-phase lease on clean error exit so
-- operator repair and retry do not have to wait for the 300-second lease timeout.
CREATE FUNCTION openmettle.restore_release_volume_phase(
    p_restore_run_id uuid,
    p_claim_token uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore volume phase release requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL OR p_claim_token IS NULL THEN
        RAISE EXCEPTION 'invalid restore volume phase release parameters' USING ERRCODE = '22023';
    END IF;
    UPDATE openmettle.restore_reconciliation_gate
       SET volume_claim_token = NULL,
           volume_lease_until = NULL
     WHERE id
       AND NOT open
       AND restore_run_id = p_restore_run_id
       AND volume_claim_token = p_claim_token;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_release_volume_phase(uuid, uuid) FROM PUBLIC;

-- Owner only: replays one record of an export while the gate is closed. The caller verifies the
-- export header via restore_verify_export, sends every record in order, and calls
-- restore_verify_checkpoints in one READ COMMITTED transaction, committing only if all pass. A
-- record at or below the restored head must equal the stored row (false). The next record must
-- extend the chain and is stored verbatim (true). If the restored database still holds the revision
-- unpurged with matching content, resurrected mutable retention holds are stripped and the revision
-- moves to 'purging' under the journal's original deadline and policy stamp; an active revision
-- first shifts its bytes from active to retained. retention_policy.revision advances strictly past
-- e.policy_revision (to e.policy_revision + 1) so even an immediate post-restore removal before any
-- policy edit never reuses a replayed policy revision number.
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
    bigint, bytea, bigint, bytea) FROM PUBLIC;

-- Owner only: opens a closed gate when the caller holds the active restore volume-phase lease
-- (OMR02), the storage volume control pin matches p_expected_volume_id with no active
-- adoption/rebind barrier (OMQ03, locked FOR SHARE in canonical order after the gate),
-- coverage_complete is true (OMR04), origin and head match both export and locked requirement plus
-- all pinned checkpoints (OMR04 / OMR03), and every revision named in deletion_journal is purged
-- (OMR05). Clears restore_run_id, required_origin_us, checkpoints, and
-- volume_claim_token/volume_lease_until on open. Requires READ COMMITTED.
CREATE FUNCTION openmettle.restore_gate_open(
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
                 ON r.scope_id = j.scope_id AND r.id = j.entity_id WHERE r.state <> 'purged') THEN
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
REVOKE ALL ON FUNCTION openmettle.restore_gate_open(uuid, uuid, bigint, bigint, bytea, uuid) FROM PUBLIC;

-- Owner only: audited break-glass acceptance of an unexported purge window after the last
-- surviving journal export (for example catastrophic primary loss without a post-quiesce export).
-- Bound to the active restore_run_id (OMR02 if open or mismatched). Sets coverage_complete = true
-- on the closed gate and records an operator row in authorization_audit. Idempotent on exact
-- replay (false); mismatched parameters raise 23505.
CREATE FUNCTION openmettle.restore_accept_coverage_gap(
    p_restore_run_id uuid,
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
    IF p_restore_run_id IS NULL
       OR p_operator_id IS NULL
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
    IF g.open OR g.restore_run_id IS DISTINCT FROM p_restore_run_id THEN
        RAISE EXCEPTION 'restore gate is not closed under the specified restore_run_id'
            USING ERRCODE = 'OMR02';
    END IF;
    v_details := jsonb_build_object(
        'restore_run_id', g.restore_run_id,
        'required_origin_us', g.required_origin_us,
        'snapshot_journal_seq', g.snapshot_journal_seq,
        'required_journal_seq', g.required_journal_seq,
        'required_chain_digest', encode(g.required_chain_digest, 'hex')
    );
    SELECT actor_kind, operator_id, target_kind, target_id, reason, details
      INTO v_existing
      FROM openmettle.authorization_audit
     WHERE actor_kind = 'operator'
       AND action = 'restore.accept_coverage_gap'
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
REVOKE ALL ON FUNCTION openmettle.restore_accept_coverage_gap(uuid, uuid, text, text) FROM PUBLIC;
