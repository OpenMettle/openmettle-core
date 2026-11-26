-- V1-16 migration 42 (ADR 0041 PR3): journaled deadline commitments and pre-expiry restores,
-- immutable pre-42 upgrade baseline (retention_upgrade_baseline + lifecycle_baseline_digest),
-- lifecycle journal origin cutoff (rejecting pre-42 backups under --export-complete unless
-- explicitly accepted via audited break-glass), monotonic restore-gate generation counter and
-- generation-returning lock helper (restore_gate_lock_open_generation), extended restore-gate
-- guards on artifact_revisions, live-reference and hold check helpers for disassociation/restore,
-- least-privilege API restore-gate helper execution, idempotent retention_set_grace, audited
-- account_admin deadline preview/apply, and audited admin_retention_status projection. Released
-- migrations are immutable.
-- Runs once per release as openmettle_owner in one transaction with search_path
-- pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (ADR 0005, ADR 0027, ADR 0040, ADR 0041):
--   account_admin_lock -> projects -> login_providers -> local_identity_approvals ->
--   users (ascending id) -> runs -> storage_reservations -> artifacts ->
--   artifact_revisions (scope_id, id) -> restore_reconciliation_gate (FOR SHARE) ->
--   storage_volume_control -> storage_accounts -> storage_instance ->
--   retention_policy -> deletion_journal_head (flushed before post-write authority recheck).
--
-- Upgrade from 41: existing deletion_journal rows (all 'artifact_revision.purged') keep
-- retained_at = NULL and preserve their exact openmettle.deletion_journal/1 chain digest.
-- deletion_journal_head records lifecycle_coverage_started_at (when migration 42 was installed)
-- so backups taken at schema <= 41 cannot satisfy --export-complete on schema 42 without explicit
-- audited break-glass acceptance. New lifecycle transitions ('artifact_revision.retained',
-- 'artifact_revision.deadline_adjusted', 'artifact_revision.restored') append domain-separated
-- openmettle.deletion_journal/2 records on the same monotonic hash chain.

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

-- Capture an immutable, owner-only baseline snapshot of all pre-42 retained/purging revisions so
-- restoring an older schema-41 backup (where those revisions were still active or held an older
-- window) replays every pre-42 state (retained or purging), deadline and policy revision
-- deterministically before post-42 deletion_journal records, without mutating deletion_journal
-- during migration 42.
CREATE TABLE openmettle.retention_upgrade_baseline (
    artifact_revision_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('retained', 'purging')),
    retained_at timestamptz NOT NULL,
    original_purge_after timestamptz NOT NULL,
    purging_at timestamptz,
    content_digest bytea NOT NULL CHECK (pg_catalog.octet_length(content_digest) = 32),
    policy_revision bigint CHECK (policy_revision IS NULL OR policy_revision >= 1),
    CHECK (original_purge_after >= retained_at),
    CHECK (
        (state = 'retained' AND purging_at IS NULL)
        OR (state = 'purging' AND purging_at IS NOT NULL AND purging_at >= original_purge_after)
    )
);
REVOKE ALL ON TABLE openmettle.retention_upgrade_baseline FROM PUBLIC;

INSERT INTO openmettle.retention_upgrade_baseline (
    artifact_revision_id,
    scope_id,
    state,
    retained_at,
    original_purge_after,
    purging_at,
    content_digest,
    policy_revision
)
SELECT id,
       scope_id,
       state,
       retained_at,
       purge_after,
       purging_at,
       content_digest,
       retention_policy_revision
  FROM openmettle.artifact_revisions
 WHERE state IN ('retained', 'purging')
 ORDER BY id ASC;

CREATE FUNCTION openmettle.retention_upgrade_baseline_immutable()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'DELETE')
       AND pg_catalog.current_setting('openmettle.replaying_upgrade_baseline', true) = 'on'
       AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'MEMBER')
       AND EXISTS (SELECT 1 FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open) THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'retention_upgrade_baseline is immutable' USING ERRCODE = 'OMR01';
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_upgrade_baseline_immutable() FROM PUBLIC;

CREATE TRIGGER retention_upgrade_baseline_no_mutate
    BEFORE INSERT OR UPDATE OR DELETE ON openmettle.retention_upgrade_baseline
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.retention_upgrade_baseline_immutable();

CREATE TRIGGER retention_upgrade_baseline_no_truncate
    BEFORE TRUNCATE ON openmettle.retention_upgrade_baseline
    FOR EACH STATEMENT
    EXECUTE FUNCTION openmettle.retention_upgrade_baseline_immutable();

-- Canonical folded SHA-256 step over retention_upgrade_baseline rows ordered by
-- artifact_revision_id ASC (starting from 32 zero bytes when empty).
CREATE FUNCTION openmettle.retention_baseline_step(
    p_previous bytea,
    p_entity_id uuid,
    p_scope_id uuid,
    p_state text,
    p_retained_us bigint,
    p_original_purge_after_us bigint,
    p_purging_us bigint,
    p_content_digest bytea,
    p_policy_revision bigint)
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT sha256(convert_to(
        encode(p_previous, 'hex') || ':' ||
        p_entity_id::text || ':' ||
        p_scope_id::text || ':' ||
        p_state || ':' ||
        p_retained_us::text || ':' ||
        p_original_purge_after_us::text || ':' ||
        coalesce(p_purging_us::text, '-') || ':' ||
        encode(p_content_digest, 'hex') || ':' ||
        coalesce(p_policy_revision::text, '-'),
        'UTF8'
    ))
$$;
REVOKE ALL ON FUNCTION openmettle.retention_baseline_step(bytea, uuid, uuid, text, bigint, bigint, bigint, bytea, bigint) FROM PUBLIC;

-- Record when lifecycle commitment journaling began (migration 42 installation) and commit the
-- canonical digest of retention_upgrade_baseline so a backup taken at schema <= 41 and migrated
-- to 42 during recovery gets a distinct lifecycle_coverage_started_at timestamp, cannot reopen
-- under --export-complete without audited break-glass acceptance, and replays the primary's
-- pre-42 retained/purging baseline before deletion_journal records.
ALTER TABLE openmettle.deletion_journal_head
    ADD COLUMN lifecycle_coverage_started_at timestamptz,
    ADD COLUMN lifecycle_baseline_digest bytea;
DO $$
DECLARE
    v_started timestamptz;
    v_baseline_digest bytea := pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex');
    r record;
BEGIN
    IF pg_catalog.to_regclass('openmettle._sqlx_migrations') IS NOT NULL THEN
        EXECUTE 'SELECT installed_on FROM openmettle._sqlx_migrations WHERE version = 42'
           INTO v_started;
    END IF;
    FOR r IN
        SELECT artifact_revision_id,
               scope_id,
               state,
               round(extract(epoch FROM retained_at) * 1000000)::bigint AS retained_us,
               round(extract(epoch FROM original_purge_after) * 1000000)::bigint AS purge_after_us,
               CASE WHEN purging_at IS NOT NULL
                    THEN round(extract(epoch FROM purging_at) * 1000000)::bigint END AS purging_us,
               content_digest,
               policy_revision
          FROM openmettle.retention_upgrade_baseline
         ORDER BY artifact_revision_id ASC
    LOOP
        v_baseline_digest := openmettle.retention_baseline_step(
            v_baseline_digest,
            r.artifact_revision_id,
            r.scope_id,
            r.state,
            r.retained_us,
            r.purge_after_us,
            r.purging_us,
            r.content_digest,
            r.policy_revision
        );
    END LOOP;
    UPDATE openmettle.deletion_journal_head
       SET lifecycle_coverage_started_at = coalesce(v_started, pg_catalog.clock_timestamp()),
           lifecycle_baseline_digest = v_baseline_digest
     WHERE id;
END
$$;
ALTER TABLE openmettle.deletion_journal_head
    ALTER COLUMN lifecycle_coverage_started_at SET NOT NULL,
    ALTER COLUMN lifecycle_coverage_started_at SET DEFAULT clock_timestamp(),
    ALTER COLUMN lifecycle_baseline_digest SET NOT NULL,
    ALTER COLUMN lifecycle_baseline_digest SET DEFAULT decode(repeat('00', 32), 'hex'),
    ADD CONSTRAINT deletion_journal_head_lifecycle_baseline_digest_check
        CHECK (pg_catalog.octet_length(lifecycle_baseline_digest) = 32);

ALTER TABLE openmettle.restore_reconciliation_gate
    ADD COLUMN snapshot_lifecycle_origin_us bigint,
    ADD COLUMN snapshot_lifecycle_baseline_digest bytea
        CHECK (snapshot_lifecycle_baseline_digest IS NULL
            OR pg_catalog.octet_length(snapshot_lifecycle_baseline_digest) = 32),
    ADD COLUMN required_lifecycle_origin_us bigint,
    ADD COLUMN required_lifecycle_baseline_digest bytea
        CHECK (required_lifecycle_baseline_digest IS NULL
            OR pg_catalog.octet_length(required_lifecycle_baseline_digest) = 32),
    ADD COLUMN replayed_lifecycle_baseline_digest bytea
        CHECK (replayed_lifecycle_baseline_digest IS NULL
            OR pg_catalog.octet_length(replayed_lifecycle_baseline_digest) = 32),
    ADD COLUMN gate_generation bigint NOT NULL DEFAULT 1
        CHECK (gate_generation >= 1);

UPDATE openmettle.restore_reconciliation_gate AS g
   SET snapshot_lifecycle_origin_us =
           (extract(epoch FROM h.lifecycle_coverage_started_at) * 1000000)::bigint,
       snapshot_lifecycle_baseline_digest = h.lifecycle_baseline_digest
  FROM openmettle.deletion_journal_head AS h
 WHERE g.id AND h.id AND NOT g.open;

ALTER TABLE openmettle.restore_reconciliation_gate
    DROP CONSTRAINT restore_reconciliation_gate_closed_check,
    ADD CONSTRAINT restore_reconciliation_gate_closed_check CHECK (
        (
            open
            AND restore_run_id IS NULL
            AND required_origin_us IS NULL
            AND snapshot_lifecycle_origin_us IS NULL
            AND snapshot_lifecycle_baseline_digest IS NULL
            AND required_lifecycle_origin_us IS NULL
            AND required_lifecycle_baseline_digest IS NULL
            AND replayed_lifecycle_baseline_digest IS NULL
            AND checkpoints = '[]'::jsonb
            AND volume_claim_token IS NULL
            AND volume_lease_until IS NULL
        ) OR (
            NOT open
            AND restore_run_id IS NOT NULL
            AND required_origin_us IS NOT NULL
            AND snapshot_lifecycle_origin_us IS NOT NULL
            AND snapshot_lifecycle_baseline_digest IS NOT NULL
            AND ((required_lifecycle_origin_us IS NULL) = (required_lifecycle_baseline_digest IS NULL))
            AND locked_at IS NOT NULL
            AND snapshot_journal_seq IS NOT NULL
            AND required_journal_seq >= snapshot_journal_seq
            AND required_chain_digest IS NOT NULL
            AND opened_at IS NULL
            AND ((volume_claim_token IS NULL) = (volume_lease_until IS NULL))
        )
    );

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

-- Owner-only gate probe used inside trigger WHEN CASE guards only after both session_user and
-- current_user are verified to hold openmettle_owner and the replay GUC is 'on'. Marked SECURITY
-- DEFINER with EXECUTE granted to openmettle_api and openmettle_worker because PostgreSQL checks
-- EXECUTE privileges for every function in a trigger WHEN expression as the invoking role; the body
-- still requires session_user to hold openmettle_owner so application roles always receive false
-- and learn nothing about gate state.
CREATE FUNCTION openmettle.restore_gate_is_closed_for_owner()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
       AND EXISTS (SELECT FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open)
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_is_closed_for_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.restore_gate_is_closed_for_owner() TO openmettle_api, openmettle_worker;

-- Keep migration 28's deadline stamping for all normal disassociations while letting owner
-- deletion_journal_replay (and only an openmettle_owner session while the restore gate is closed)
-- preserve exact journaled retained_at, purge_after and policy_revision without restarting grace.
DROP TRIGGER artifact_revisions_retention_deadline ON openmettle.artifact_revisions;
CREATE TRIGGER artifact_revisions_retention_deadline
    BEFORE UPDATE OF state ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (
        OLD.state = 'active'
        AND NEW.state = 'retained'
        AND pg_catalog.has_column_privilege('openmettle.artifact_revisions', 'purge_after', 'UPDATE')
        AND NOT (
            CASE
                WHEN pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.current_setting('openmettle.replaying_deletion_journal', true) IS NOT DISTINCT FROM 'on'
                THEN openmettle.restore_gate_is_closed_for_owner()
                ELSE false
            END
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
-- Fires at commit (or when explicitly flushed via SET CONSTRAINTS ... IMMEDIATE strictly before
-- post-write approval expiry rechecks) so deletion_journal_head is always locked last and
-- rolled-back savepoints or transactions append nothing. Skipped ONLY for an openmettle_owner
-- session during deletion_journal_replay while the restore gate is closed.
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
            CASE
                WHEN pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
                 AND pg_catalog.current_setting('openmettle.replaying_deletion_journal', true) IS NOT DISTINCT FROM 'on'
                THEN openmettle.restore_gate_is_closed_for_owner()
                ELSE false
            END
        )
    )
    EXECUTE FUNCTION openmettle.deletion_journal_append_lifecycle();

-- Owner only: close or update the restore reconciliation gate, enforcing coverage_started_at
-- (migration 28), lifecycle_coverage_started_at (migration 42), and optional
-- required_lifecycle_baseline_digest. Increments gate_generation whenever transitioning from
-- open to closed so slow downloads, SSE streams and uploads cannot span a close/replay/reopen
-- cycle. Backups predating migration 42 or exports lacking a matching lifecycle_origin cannot
-- set coverage_complete = true (OMR04) and require audited restore.accept_coverage_gap before
-- the gate may open.
DROP FUNCTION openmettle.restore_gate_lock(bigint, bigint, bytea, boolean, uuid, boolean);

CREATE FUNCTION openmettle.restore_gate_lock(
    p_origin_us bigint,
    p_required_seq bigint,
    p_required_digest bytea,
    p_coverage_complete boolean,
    p_replace_restore_run uuid DEFAULT NULL,
    p_new_restore boolean DEFAULT true,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL)
RETURNS openmettle.restore_reconciliation_gate
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_genesis bytea := decode(repeat('00', 32), 'hex');
    v_head_origin_us bigint;
    v_head_lifecycle_origin_us bigint;
    v_snapshot_lifecycle_origin_us bigint;
    v_snapshot_lifecycle_baseline_digest bytea;
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
       OR p_coverage_complete IS NULL OR p_new_restore IS NULL
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32)
       OR ((p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL)) THEN
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
        g.gate_generation := g.gate_generation + 1;
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
    v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    IF g.open THEN
        v_snapshot_lifecycle_origin_us := v_head_lifecycle_origin_us;
        v_snapshot_lifecycle_baseline_digest := head.lifecycle_baseline_digest;
    ELSE
        v_snapshot_lifecycle_origin_us := g.snapshot_lifecycle_origin_us;
        v_snapshot_lifecycle_baseline_digest := g.snapshot_lifecycle_baseline_digest;
    END IF;
    IF p_origin_us IS DISTINCT FROM v_head_origin_us THEN
        RAISE EXCEPTION 'required origin % does not match restored journal origin %',
            p_origin_us, v_head_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_coverage_complete
       AND (p_lifecycle_origin_us IS NULL
            OR p_lifecycle_origin_us IS DISTINCT FROM v_snapshot_lifecycle_origin_us) THEN
        RAISE EXCEPTION 'cannot assert complete export coverage when lifecycle journal origin % does not match restored %',
            p_lifecycle_origin_us, v_snapshot_lifecycle_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_coverage_complete
       AND p_lifecycle_baseline_digest IS DISTINCT FROM v_snapshot_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'cannot assert complete export coverage when lifecycle baseline digest does not match restored head'
            USING ERRCODE = 'OMR04';
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
        g.snapshot_lifecycle_origin_us := v_snapshot_lifecycle_origin_us;
        g.snapshot_lifecycle_baseline_digest := v_snapshot_lifecycle_baseline_digest;
        g.required_lifecycle_origin_us := p_lifecycle_origin_us;
        g.required_lifecycle_baseline_digest := p_lifecycle_baseline_digest;
        g.replayed_lifecycle_baseline_digest := NULL;
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
        IF g.required_lifecycle_origin_us IS NOT NULL
           AND p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
            RAISE EXCEPTION 'required lifecycle origin % conflicts with locked restore lifecycle origin %',
                p_lifecycle_origin_us, g.required_lifecycle_origin_us USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_lifecycle_origin_us IS NULL AND p_lifecycle_origin_us IS NOT NULL THEN
            g.required_lifecycle_origin_us := p_lifecycle_origin_us;
        END IF;
        IF g.required_lifecycle_baseline_digest IS NOT NULL
           AND p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'required lifecycle baseline digest conflicts with locked restore baseline'
                USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_lifecycle_baseline_digest IS NULL AND p_lifecycle_baseline_digest IS NOT NULL THEN
            g.required_lifecycle_baseline_digest := p_lifecycle_baseline_digest;
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
           snapshot_lifecycle_origin_us = g.snapshot_lifecycle_origin_us,
           snapshot_lifecycle_baseline_digest = g.snapshot_lifecycle_baseline_digest,
           required_lifecycle_origin_us = g.required_lifecycle_origin_us,
           required_lifecycle_baseline_digest = g.required_lifecycle_baseline_digest,
           replayed_lifecycle_baseline_digest = g.replayed_lifecycle_baseline_digest,
           gate_generation = g.gate_generation,
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
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock(bigint, bigint, bytea, boolean, uuid, boolean, bigint, bytea) FROM PUBLIC;

-- Owner only: validate an export's watermark, installation origin, lifecycle origin and
-- lifecycle baseline digest against the closed restore gate before replay writes any row, and
-- lock every affected revision row upfront in ascending id order to match storage rebind.
DROP FUNCTION openmettle.restore_verify_export(bigint, bigint, bytea);

CREATE FUNCTION openmettle.restore_verify_export(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_lock_entity_ids uuid[] DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_head_lifecycle_origin_us bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'export verification requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32) THEN
        RAISE EXCEPTION 'invalid export verification parameters' USING ERRCODE = '22023';
    END IF;
    IF (p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL) THEN
        RAISE EXCEPTION 'schema-42 export must carry both lifecycle_origin and lifecycle_baseline'
            USING ERRCODE = 'OMR03';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(1330467394, 42);
    -- Canonical lock order: lock the full union of export-referenced and currently retained/purging
    -- revisions in ascending id order BEFORE restore_reconciliation_gate and storage_volume_control
    -- so restore replay never deadlocks with storage rebind.
    PERFORM 1
       FROM openmettle.artifact_revisions
      WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         OR state IN ('retained', 'purging')
      ORDER BY id ASC
        FOR UPDATE;
    SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR UPDATE;
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
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'export lifecycle origin % does not match locked requirement %',
            p_lifecycle_origin_us, g.required_lifecycle_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'export lifecycle baseline digest does not match locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    IF p_lifecycle_origin_us IS NOT NULL
       AND p_lifecycle_origin_us = g.snapshot_lifecycle_origin_us
       AND p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'export lifecycle baseline digest does not match restored snapshot'
            USING ERRCODE = 'OMR03';
    END IF;
    IF p_lifecycle_origin_us IS NOT NULL
       AND p_lifecycle_origin_us = v_head_lifecycle_origin_us
       AND p_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'export lifecycle baseline digest does not match restored installation head'
            USING ERRCODE = 'OMR03';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_verify_export(bigint, bigint, bytea, bigint, bytea, uuid[]) FROM PUBLIC;

-- Owner only: verify the canonical folded SHA-256 of an exported pre-42 retention upgrade
-- baseline inside PostgreSQL, replay its authoritative retained/purging state, deadlines and
-- policy revisions onto a restored pre-42 backup before deletion_journal records, reconcile any
-- locally retained backup revisions restored to active before migration 42 (failing closed on
-- unresolved purging/timestamp/reservation conflicts), persist the verified baseline rows and
-- provenance into retention_upgrade_baseline and deletion_journal_head so subsequent exports and
-- recoveries retain pre-42 coverage, and pin replayed_lifecycle_baseline_digest on the closed gate.
CREATE FUNCTION openmettle.restore_replay_baseline(
    p_lifecycle_origin_us bigint,
    p_expected_digest bytea,
    p_entity_ids uuid[],
    p_scope_ids uuid[],
    p_states text[],
    p_retained_us bigint[],
    p_original_purge_after_us bigint[],
    p_purging_us bigint[],
    p_content_digests bytea[],
    p_policy_revisions bigint[],
    p_prebaseline_purged_ids uuid[] DEFAULT ARRAY[]::uuid[])
RETURNS integer
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_len integer;
    v_idx integer;
    v_head_lifecycle_origin_us bigint;
    v_baseline_origin timestamptz;
    v_apply boolean;
    v_digest bytea := decode(repeat('00', 32), 'hex');
    v_prev_entity_id uuid;
    v_entity_id uuid;
    v_scope_id uuid;
    v_target_state text;
    v_retained_us bigint;
    v_purge_after_us bigint;
    v_purging_us bigint;
    v_content_digest bytea;
    v_policy_revision bigint;
    v_rev_scope uuid;
    v_state text;
    v_size bigint;
    v_content bytea;
    v_cur_retained timestamptz;
    v_cur_purge_after timestamptz;
    v_cur_purging_at timestamptz;
    v_cur_policy_rev bigint;
    v_target_retained timestamptz;
    v_target_purge_after timestamptz;
    v_target_purging_at timestamptz;
    v_local record;
    v_applied integer := 0;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'baseline replay requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_lifecycle_origin_us IS NULL
       OR p_expected_digest IS NULL OR octet_length(p_expected_digest) <> 32
       OR p_entity_ids IS NULL OR p_scope_ids IS NULL
       OR p_states IS NULL OR p_retained_us IS NULL
       OR p_original_purge_after_us IS NULL OR p_purging_us IS NULL
       OR p_content_digests IS NULL OR p_policy_revisions IS NULL
       OR p_prebaseline_purged_ids IS NULL THEN
        RAISE EXCEPTION 'invalid baseline replay parameters' USING ERRCODE = '22023';
    END IF;
    v_len := coalesce(array_length(p_entity_ids, 1), 0);
    IF coalesce(array_length(p_scope_ids, 1), 0) <> v_len
       OR coalesce(array_length(p_states, 1), 0) <> v_len
       OR coalesce(array_length(p_retained_us, 1), 0) <> v_len
       OR coalesce(array_length(p_original_purge_after_us, 1), 0) <> v_len
       OR coalesce(array_length(p_purging_us, 1), 0) <> v_len
       OR coalesce(array_length(p_content_digests, 1), 0) <> v_len
       OR coalesce(array_length(p_policy_revisions, 1), 0) <> v_len THEN
        RAISE EXCEPTION 'mismatched baseline replay array lengths' USING ERRCODE = 'OMR03';
    END IF;
    IF v_len > 0 AND (
        array_lower(p_entity_ids, 1) <> 1
        OR array_lower(p_scope_ids, 1) <> 1
        OR array_lower(p_states, 1) <> 1
        OR array_lower(p_retained_us, 1) <> 1
        OR array_lower(p_original_purge_after_us, 1) <> 1
        OR array_lower(p_purging_us, 1) <> 1
        OR array_lower(p_content_digests, 1) <> 1
        OR array_lower(p_policy_revisions, 1) <> 1
    ) THEN
        RAISE EXCEPTION 'baseline replay arrays must be 1-based' USING ERRCODE = '22023';
    END IF;
    IF coalesce(array_length(p_prebaseline_purged_ids, 1), 0) > 0
       AND array_lower(p_prebaseline_purged_ids, 1) <> 1 THEN
        RAISE EXCEPTION 'prebaseline purged array must be 1-based' USING ERRCODE = '22023';
    END IF;

    -- Serialize concurrent owner replays and follow canonical lock order:
    -- artifact_revisions (ascending by id) BEFORE restore_reconciliation_gate.
    PERFORM pg_catalog.pg_advisory_xact_lock(1330467394, 42);
    PERFORM 1
       FROM openmettle.artifact_revisions
      WHERE id = ANY(p_entity_ids)
         OR state IN ('retained', 'purging')
      ORDER BY id ASC
        FOR UPDATE;
    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    IF g.open THEN
        RAISE EXCEPTION 'baseline replay requires a closed restore gate' USING ERRCODE = 'OMR02';
    END IF;
    IF g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase is active' USING ERRCODE = 'OMR02';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'baseline lifecycle origin % does not match locked requirement %',
            p_lifecycle_origin_us, g.required_lifecycle_origin_us USING ERRCODE = 'OMR04';
    END IF;
    IF p_expected_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'baseline digest does not match locked restore requirement'
            USING ERRCODE = 'OMR03';
    END IF;

    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    v_baseline_origin := timestamptz 'epoch' + p_lifecycle_origin_us * interval '1 microsecond';
    v_apply := (v_head_lifecycle_origin_us IS DISTINCT FROM p_lifecycle_origin_us)
        AND (g.replayed_lifecycle_baseline_digest IS NULL);

    -- First validate every baseline entry and fold the canonical SHA-256 digest before mutating.
    FOR v_idx IN 1..v_len LOOP
        v_entity_id := p_entity_ids[v_idx];
        v_scope_id := p_scope_ids[v_idx];
        v_target_state := p_states[v_idx];
        v_retained_us := p_retained_us[v_idx];
        v_purge_after_us := p_original_purge_after_us[v_idx];
        v_purging_us := p_purging_us[v_idx];
        v_content_digest := p_content_digests[v_idx];
        v_policy_revision := p_policy_revisions[v_idx];

        IF v_entity_id IS NULL OR v_scope_id IS NULL
           OR v_target_state IS NULL OR v_target_state NOT IN ('retained', 'purging')
           OR v_retained_us IS NULL OR v_purge_after_us IS NULL
           OR v_purge_after_us < v_retained_us
           OR (v_target_state = 'retained' AND v_purging_us IS NOT NULL)
           OR (v_target_state = 'purging' AND (v_purging_us IS NULL OR v_purging_us < v_purge_after_us))
           OR v_content_digest IS NULL OR octet_length(v_content_digest) <> 32
           OR (v_policy_revision IS NOT NULL AND v_policy_revision <= 0) THEN
            RAISE EXCEPTION 'invalid baseline entry at index %', v_idx USING ERRCODE = 'OMR03';
        END IF;
        IF v_prev_entity_id IS NOT NULL AND v_entity_id <= v_prev_entity_id THEN
            RAISE EXCEPTION 'baseline entries must be strictly ordered by artifact_revision_id'
                USING ERRCODE = 'OMR03';
        END IF;
        v_prev_entity_id := v_entity_id;

        v_digest := openmettle.retention_baseline_step(
            v_digest,
            v_entity_id,
            v_scope_id,
            v_target_state,
            v_retained_us,
            v_purge_after_us,
            v_purging_us,
            v_content_digest,
            v_policy_revision
        );
    END LOOP;

    IF v_digest IS DISTINCT FROM p_expected_digest THEN
        RAISE EXCEPTION 'computed lifecycle baseline digest does not match export header'
            USING ERRCODE = 'OMR03';
    END IF;
    IF v_head_lifecycle_origin_us = p_lifecycle_origin_us
       AND v_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest does not match restored head'
            USING ERRCODE = 'OMR03';
    END IF;
    IF g.replayed_lifecycle_baseline_digest IS NOT NULL
       AND v_digest IS DISTINCT FROM g.replayed_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest conflicts with previously replayed baseline'
            USING ERRCODE = 'OMR03';
    END IF;

    IF v_apply THEN
        FOR v_idx IN 1..v_len LOOP
            v_entity_id := p_entity_ids[v_idx];
            v_scope_id := p_scope_ids[v_idx];
            v_target_state := p_states[v_idx];
            v_retained_us := p_retained_us[v_idx];
            v_purge_after_us := p_original_purge_after_us[v_idx];
            v_purging_us := p_purging_us[v_idx];
            v_content_digest := p_content_digests[v_idx];
            v_policy_revision := p_policy_revisions[v_idx];

            SELECT scope_id, state, size_bytes, content_digest,
                   retained_at, purge_after, purging_at, retention_policy_revision
              INTO v_rev_scope, v_state, v_size, v_content,
                   v_cur_retained, v_cur_purge_after, v_cur_purging_at, v_cur_policy_rev
              FROM openmettle.artifact_revisions
             WHERE id = v_entity_id;
            IF FOUND THEN
                IF v_rev_scope IS DISTINCT FROM v_scope_id
                   OR v_content IS DISTINCT FROM v_content_digest THEN
                    RAISE EXCEPTION 'baseline entry % does not match artifact revision scope or content',
                        v_entity_id USING ERRCODE = 'OMR02';
                END IF;
                IF v_state = 'purged' THEN
                    RAISE EXCEPTION 'baseline entry % cannot overwrite an already purged revision',
                        v_entity_id USING ERRCODE = 'OMR03';
                END IF;
                IF v_state = 'purging' AND v_target_state = 'retained' THEN
                    RAISE EXCEPTION 'baseline entry % cannot downgrade a purging revision to retained',
                        v_entity_id USING ERRCODE = 'OMR03';
                END IF;
                v_target_retained := timestamptz 'epoch' + v_retained_us * interval '1 microsecond';
                v_target_purge_after := timestamptz 'epoch' + v_purge_after_us * interval '1 microsecond';
                v_target_purging_at := CASE WHEN v_purging_us IS NOT NULL
                    THEN timestamptz 'epoch' + v_purging_us * interval '1 microsecond' END;
                IF v_target_state = 'purging' THEN
                    DELETE FROM openmettle.artifact_retention_holds
                     WHERE scope_id = v_scope_id AND artifact_revision_id = v_entity_id;
                END IF;
                IF v_state = 'active' THEN
                    PERFORM openmettle.storage_lock_pinned_volume()
                       FROM openmettle.storage_volume_control
                      WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
                    UPDATE openmettle.storage_accounts
                       SET active_bytes = active_bytes - v_size,
                           retained_bytes = retained_bytes + v_size
                     WHERE scope_id = v_scope_id;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
                    END IF;
                    UPDATE openmettle.storage_instance
                       SET active_bytes = active_bytes - v_size,
                           retained_bytes = retained_bytes + v_size;
                END IF;
                IF v_state IS DISTINCT FROM v_target_state
                   OR v_cur_retained IS DISTINCT FROM v_target_retained
                   OR v_cur_purge_after IS DISTINCT FROM v_target_purge_after
                   OR v_cur_purging_at IS DISTINCT FROM v_target_purging_at
                   OR v_cur_policy_rev IS DISTINCT FROM v_policy_revision THEN
                    PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
                    UPDATE openmettle.artifact_revisions
                       SET state = v_target_state,
                           retained_at = v_target_retained,
                           purge_after = v_target_purge_after,
                           purging_at = v_target_purging_at,
                           retention_policy_revision = v_policy_revision
                     WHERE scope_id = v_scope_id AND id = v_entity_id;
                    PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
                    v_applied := v_applied + 1;
                END IF;
            END IF;
            IF v_policy_revision IS NOT NULL THEN
                UPDATE openmettle.retention_policy
                   SET revision = v_policy_revision + 1
                 WHERE id AND revision <= v_policy_revision;
            END IF;
        END LOOP;

        -- Reconcile locally retained/purging backup rows absent from the primary's upgrade
        -- baseline: revisions purged pre-42 remain for deletion_journal_replay; revisions
        -- restored to active before migration 42 return to active; unresolved purging,
        -- post-baseline timestamp, or unverified/reclaiming reservation conflicts fail closed.
        FOR v_local IN
            SELECT ar.id,
                   ar.scope_id,
                   ar.reservation_id,
                   ar.state,
                   ar.size_bytes,
                   ar.retained_at
              FROM openmettle.artifact_revisions ar
             WHERE ar.state IN ('retained', 'purging')
               AND NOT (ar.id = ANY(p_entity_ids))
             ORDER BY ar.id ASC
        LOOP
            IF v_local.id = ANY(p_prebaseline_purged_ids)
               OR EXISTS (
                   SELECT 1
                     FROM openmettle.deletion_journal j
                    WHERE j.event_kind = 'artifact_revision.purged'
                      AND j.entity_id = v_local.id
               ) THEN
                CONTINUE;
            END IF;
            IF v_local.state = 'purging' THEN
                RAISE EXCEPTION 'local purging revision % is absent from lifecycle upgrade baseline and purge journal',
                    v_local.id USING ERRCODE = 'OMR04';
            END IF;
            IF v_local.retained_at IS NULL OR v_local.retained_at > v_baseline_origin THEN
                RAISE EXCEPTION 'local retained revision % postdates lifecycle upgrade baseline origin',
                    v_local.id USING ERRCODE = 'OMR04';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM openmettle.storage_reservations s
                 WHERE s.scope_id = v_local.scope_id
                   AND s.id = v_local.reservation_id
                   AND (
                       s.state <> 'settled'
                       OR s.reclaim_state <> 'none'
                       OR s.adoption_unverified
                       OR (s.payload_ino IS NULL
                           AND EXISTS (
                               SELECT 1 FROM openmettle.storage_volume_control
                                WHERE id AND volume_id IS NOT NULL
                           ))
                   )
            ) THEN
                RAISE EXCEPTION 'local retained revision % has unverified or reclaiming reservation',
                    v_local.id USING ERRCODE = 'OMR04';
            END IF;
            PERFORM openmettle.storage_lock_pinned_volume()
               FROM openmettle.storage_volume_control
              WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL);
            UPDATE openmettle.storage_accounts
               SET retained_bytes = retained_bytes - v_local.size_bytes,
                   active_bytes = active_bytes + v_local.size_bytes
             WHERE scope_id = v_local.scope_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
            END IF;
            UPDATE openmettle.storage_instance
               SET retained_bytes = retained_bytes - v_local.size_bytes,
                   active_bytes = active_bytes + v_local.size_bytes;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.artifact_revisions
               SET state = 'active',
                   retained_at = NULL,
                   purge_after = NULL,
                   purging_at = NULL,
                   retention_policy_revision = NULL
             WHERE scope_id = v_local.scope_id AND id = v_local.id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
            v_applied := v_applied + 1;
        END LOOP;

        PERFORM pg_catalog.set_config('openmettle.replaying_upgrade_baseline', 'on', true);
        DELETE FROM openmettle.retention_upgrade_baseline;
        FOR v_idx IN 1..v_len LOOP
            INSERT INTO openmettle.retention_upgrade_baseline (
                artifact_revision_id,
                scope_id,
                state,
                retained_at,
                original_purge_after,
                purging_at,
                content_digest,
                policy_revision
            ) VALUES (
                p_entity_ids[v_idx],
                p_scope_ids[v_idx],
                p_states[v_idx],
                timestamptz 'epoch' + p_retained_us[v_idx] * interval '1 microsecond',
                timestamptz 'epoch' + p_original_purge_after_us[v_idx] * interval '1 microsecond',
                CASE WHEN p_purging_us[v_idx] IS NOT NULL
                     THEN timestamptz 'epoch' + p_purging_us[v_idx] * interval '1 microsecond' END,
                p_content_digests[v_idx],
                p_policy_revisions[v_idx]
            );
        END LOOP;
        PERFORM pg_catalog.set_config('openmettle.replaying_upgrade_baseline', 'off', true);
        UPDATE openmettle.deletion_journal_head
           SET lifecycle_coverage_started_at = v_baseline_origin,
               lifecycle_baseline_digest = v_digest
         WHERE id;
    END IF;

    UPDATE openmettle.restore_reconciliation_gate
       SET replayed_lifecycle_baseline_digest = v_digest
     WHERE id;
    RETURN v_applied;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_replay_baseline(bigint, bytea, uuid[], uuid[], text[], bigint[], bigint[], bigint[], bytea[], bigint[], uuid[]) FROM PUBLIC;

-- Owner only: claim the exclusive volume-phase lease, checking both origins, lifecycle baseline
-- replay status, watermark and pinned checkpoints.
DROP FUNCTION openmettle.restore_claim_volume_phase(bigint, bigint, bytea);

CREATE FUNCTION openmettle.restore_claim_volume_phase(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL)
RETURNS TABLE(restore_run_id uuid, volume_claim_token uuid)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_lifecycle_origin_us bigint;
    v_token uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore volume phase claim requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32) THEN
        RAISE EXCEPTION 'invalid restore volume phase parameters' USING ERRCODE = '22023';
    END IF;
    IF (p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL) THEN
        RAISE EXCEPTION 'lifecycle origin and lifecycle baseline digest must be supplied together'
            USING ERRCODE = 'OMR03';
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
    v_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'lifecycle journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest does not match locked requirement' USING ERRCODE = 'OMR03';
    END IF;
    IF p_lifecycle_origin_us IS NOT NULL AND p_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
        IF p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
           OR p_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle baseline digest does not match restored head' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_lifecycle_origin_us IS NOT NULL THEN
        IF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest
           OR v_lifecycle_origin_us IS DISTINCT FROM p_lifecycle_origin_us
           OR head.lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle upgrade baseline must be replayed before claiming volume phase'
                USING ERRCODE = 'OMR04';
        END IF;
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
    IF p_lifecycle_origin_us IS NOT NULL AND EXISTS (
        SELECT 1
          FROM openmettle.artifact_revisions r
         WHERE r.state IN ('retained', 'purging')
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.retention_upgrade_baseline b
                WHERE b.artifact_revision_id = r.id
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.deletion_journal j
                WHERE j.entity_id = r.id
                  AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
           )
    ) THEN
        RAISE EXCEPTION 'unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal'
            USING ERRCODE = 'OMR04';
    END IF;
    v_token := gen_random_uuid();
    UPDATE openmettle.restore_reconciliation_gate
       SET volume_claim_token = v_token,
           volume_lease_until = clock_timestamp() + interval '300 seconds'
     WHERE id;
    RETURN QUERY SELECT g.restore_run_id, v_token;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_claim_volume_phase(bigint, bigint, bytea, bigint, bytea) FROM PUBLIC;

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

    PERFORM pg_catalog.pg_advisory_xact_lock(1330467394, 42);
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
    ELSIF p_event_kind = 'artifact_revision.retained' THEN
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
    ELSIF p_event_kind = 'artifact_revision.deadline_adjusted' THEN
        IF (v_state IS NOT NULL AND v_state <> 'retained')
           OR (NOT EXISTS (
                   SELECT 1 FROM openmettle.retention_upgrade_baseline b
                    WHERE b.artifact_revision_id = p_entity_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM openmettle.deletion_journal j
                    WHERE j.entity_id = p_entity_id
                      AND j.event_kind = 'artifact_revision.retained'
               )) THEN
            RAISE EXCEPTION 'journal record % requires a retained revision for deadline adjustment', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        IF v_state = 'retained' THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.artifact_revisions
               SET retained_at = e.retained_at,
                   purge_after = e.original_purge_after,
                   retention_policy_revision = e.policy_revision
             WHERE scope_id = p_scope_id AND id = p_entity_id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind = 'artifact_revision.restored' THEN
        IF (v_state IS NOT NULL AND v_state <> 'retained')
           OR (NOT EXISTS (
                   SELECT 1 FROM openmettle.retention_upgrade_baseline b
                    WHERE b.artifact_revision_id = p_entity_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM openmettle.deletion_journal j
                    WHERE j.entity_id = p_entity_id
                      AND j.event_kind = 'artifact_revision.retained'
               )) THEN
            RAISE EXCEPTION 'journal record % requires a retained revision for restore', p_seq
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
-- the restore gate, require matching lifecycle_coverage_started_at unless an audited owner
-- restore.accept_coverage_gap record explicitly accepted the coverage gap for this restore_run_id,
-- and require any locked or pre-42 lifecycle upgrade baseline to have been replayed.
DROP FUNCTION openmettle.restore_gate_open(uuid, uuid, bigint, bigint, bytea, uuid);

CREATE FUNCTION openmettle.restore_gate_open(
    p_restore_run_id uuid,
    p_claim_token uuid,
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_expected_volume_id uuid,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_lifecycle_origin_us bigint;
    v_volume_id uuid;
    v_adoption_run_id uuid;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'restore gate changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF p_restore_run_id IS NULL OR p_claim_token IS NULL
       OR p_origin_us IS NULL OR p_export_seq IS NULL OR p_export_seq < 0
       OR p_export_digest IS NULL OR octet_length(p_export_digest) <> 32
       OR (p_lifecycle_baseline_digest IS NOT NULL AND octet_length(p_lifecycle_baseline_digest) <> 32) THEN
        RAISE EXCEPTION 'invalid restore gate open parameters' USING ERRCODE = '22023';
    END IF;
    IF (p_lifecycle_origin_us IS NULL) <> (p_lifecycle_baseline_digest IS NULL) THEN
        RAISE EXCEPTION 'lifecycle origin and lifecycle baseline digest must be supplied together'
            USING ERRCODE = 'OMR03';
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
    v_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'lifecycle journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest does not match locked requirement' USING ERRCODE = 'OMR03';
    END IF;
    IF p_lifecycle_origin_us IS NOT NULL AND p_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
        IF p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
           OR p_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle baseline digest does not match restored head' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_lifecycle_origin_us IS NOT NULL THEN
        IF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest
           OR v_lifecycle_origin_us IS DISTINCT FROM p_lifecycle_origin_us
           OR head.lifecycle_baseline_digest IS DISTINCT FROM p_lifecycle_baseline_digest THEN
            RAISE EXCEPTION 'lifecycle upgrade baseline must be replayed before opening restore gate'
                USING ERRCODE = 'OMR04';
        END IF;
    END IF;
    IF (p_lifecycle_origin_us IS NULL
        OR p_lifecycle_origin_us IS DISTINCT FROM g.snapshot_lifecycle_origin_us
        OR p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest)
       AND NOT EXISTS (
           SELECT FROM openmettle.authorization_audit
            WHERE actor_kind = 'operator'
              AND action = 'restore.accept_coverage_gap'
              AND target_kind = 'restore_gate'
              AND target_id = 'instance'
              AND (details->>'restore_run_id') = g.restore_run_id::text
              AND (details->>'required_journal_seq')::bigint = g.required_journal_seq
              AND (details->>'required_chain_digest') = encode(g.required_chain_digest, 'hex')
       ) THEN
        RAISE EXCEPTION 'backup predates lifecycle journal coverage; inspect or run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
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
    IF p_lifecycle_origin_us IS NOT NULL AND EXISTS (
        SELECT 1
          FROM openmettle.artifact_revisions r
         WHERE r.state IN ('retained', 'purging')
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.retention_upgrade_baseline b
                WHERE b.artifact_revision_id = r.id
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM openmettle.deletion_journal j
                WHERE j.entity_id = r.id
                  AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
           )
    ) THEN
        RAISE EXCEPTION 'unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal'
            USING ERRCODE = 'OMR04';
    END IF;
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
           snapshot_lifecycle_origin_us = NULL,
           snapshot_lifecycle_baseline_digest = NULL,
           required_lifecycle_origin_us = NULL,
           required_lifecycle_baseline_digest = NULL,
           replayed_lifecycle_baseline_digest = NULL,
           checkpoints = '[]'::jsonb,
           volume_claim_token = NULL,
           volume_lease_until = NULL
     WHERE id;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_open(uuid, uuid, bigint, bigint, bytea, uuid, bigint, bytea) FROM PUBLIC;

-- Record required_lifecycle_origin_us and required_lifecycle_baseline_digest alongside
-- required_origin_us in break-glass audit details.
CREATE OR REPLACE FUNCTION openmettle.restore_accept_coverage_gap(
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
        'required_lifecycle_origin_us', g.required_lifecycle_origin_us,
        'required_lifecycle_baseline_digest', encode(g.required_lifecycle_baseline_digest, 'hex'),
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

-- Least-privilege restore-gate helpers for openmettle_api and openmettle_worker: acquire FOR SHARE
-- when open without granting openmettle_api direct SELECT on restore_reconciliation_gate, and
-- return the monotonic gate_generation so long-lived streams/uploads detect any close/reopen cycle.
CREATE FUNCTION openmettle.restore_gate_lock_open_generation()
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_generation bigint;
BEGIN
    SELECT gate_generation
      INTO v_generation
      FROM openmettle.restore_reconciliation_gate
     WHERE id AND open
       FOR SHARE;
    RETURN v_generation;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_gate_lock_open_generation() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.restore_gate_lock_open_generation() TO openmettle_api, openmettle_worker;

CREATE OR REPLACE FUNCTION openmettle.restore_gate_lock_open()
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT openmettle.restore_gate_lock_open_generation() IS NOT NULL
$$;
GRANT EXECUTE ON FUNCTION openmettle.restore_gate_lock_open() TO openmettle_api;

-- Least-privilege live-reference check for disassociation (active -> retained): true when any
-- live message attachment references (p_scope, p_revision) OR its writing run/operation is still
-- unfinished. Requires READ COMMITTED so callers holding artifact_revisions FOR UPDATE see every
-- attachment or run/operation transition committed before the lock.
CREATE FUNCTION openmettle.artifact_revision_live_referenced(
    p_scope uuid,
    p_revision uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'live reference checks require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    RETURN EXISTS (
               SELECT FROM openmettle.message_parts
                WHERE scope_id = p_scope
                  AND artifact_revision_id = p_revision
           )
        OR EXISTS (
               SELECT FROM openmettle.artifact_revisions r
                 JOIN openmettle.storage_reservations s
                   ON s.scope_id = r.scope_id AND s.id = r.reservation_id
                 JOIN openmettle.runs u
                   ON u.scope_id = s.scope_id AND u.id = s.run_id
                WHERE r.scope_id = p_scope
                  AND r.id = p_revision
                  AND (
                      u.state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
                      OR EXISTS (
                          SELECT FROM openmettle.operations o
                           WHERE o.scope_id = u.scope_id
                             AND o.run_id = u.id
                             AND (s.operation_id IS NULL OR o.id = s.operation_id)
                             AND o.outcome IN ('intent', 'outcome_unknown')
                      )
                  )
           );
END
$$;
REVOKE ALL ON FUNCTION openmettle.artifact_revision_live_referenced(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.artifact_revision_live_referenced(uuid, uuid) TO openmettle_api;

-- Least-privilege operator-hold check for pre-expiry restore (retained -> active): lets
-- openmettle_api refuse restoring a revision placed under an operator hold without granting
-- openmettle_api direct SELECT on artifact_retention_holds.
CREATE FUNCTION openmettle.artifact_revision_has_hold(
    p_scope uuid,
    p_revision uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'retention hold checks require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    RETURN EXISTS (
        SELECT FROM openmettle.artifact_retention_holds
         WHERE scope_id = p_scope
           AND artifact_revision_id = p_revision
    );
END
$$;
REVOKE ALL ON FUNCTION openmettle.artifact_revision_has_hold(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.artifact_revision_has_hold(uuid, uuid) TO openmettle_api;

-- Widen authorization_audit action check additively for PR3 routes (including audited admin reads).
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

-- Audited account_admin preview of adjusting existing 'retained' deadlines to
-- retained_at + p_target_grace_seconds. Exposes counts and total bytes only; never exposes
-- artifact IDs, filenames or content. Verifies authority at server-side clock_timestamp() and
-- writes a redacted retention.deadlines_preview audit record while remaining available when the
-- restore gate is closed.
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
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_policy openmettle.retention_policy%ROWTYPE;
    v_now_ms bigint;
    v_affected_revisions bigint;
    v_affected_bytes bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'retention deadline preview requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR SHARE;
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
    v_now_ms := greatest(
        coalesce(p_now_ms, 0),
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    );
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
    SELECT count(*)::bigint,
           coalesce(sum(r.size_bytes), 0)::bigint
      INTO v_affected_revisions, v_affected_bytes
      FROM openmettle.artifact_revisions r
     WHERE r.state = 'retained'
       AND (p_scope_id IS NULL OR r.scope_id = p_scope_id)
       AND r.purge_after IS DISTINCT FROM (r.retained_at + p_target_grace_seconds * interval '1 second');

    INSERT INTO openmettle.authorization_audit
        (actor_user_id, action, target_kind, target_id, request_key, reason, details)
    VALUES (
        p_actor,
        'retention.deadlines_preview',
        'retention_policy',
        coalesce(p_scope_id::text, 'instance'),
        gen_random_uuid()::text,
        'admin_inspection',
        jsonb_build_object(
            'current_policy_revision', v_policy.revision,
            'target_grace_seconds', p_target_grace_seconds,
            'scope_id', p_scope_id,
            'affected_revisions', v_affected_revisions,
            'affected_bytes', v_affected_bytes
        )
    );

    v_now_ms := greatest(
        v_now_ms,
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    );
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, v_now_ms);

    RETURN QUERY SELECT v_affected_revisions, v_affected_bytes, v_policy.revision, p_target_grace_seconds;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_preview_deadlines(uuid, uuid, bigint, integer, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.retention_preview_deadlines(uuid, uuid, bigint, integer, uuid) TO openmettle_api;

-- Audited account_admin explicit deadline adjustment for existing 'retained' revisions.
-- Follows canonical lock order (account_admin_lock -> login_providers -> local_identity_approvals
-- -> users -> artifact_revisions (scope_id, id) -> restore_reconciliation_gate FOR SHARE ->
-- retention_policy FOR SHARE -> authorization_audit -> deletion_journal_head via explicit
-- SET CONSTRAINTS ... IMMEDIATE before the post-write authority recheck).
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
    -- Defense-in-depth: never allow a caller-set session GUC to suppress lifecycle journaling.
    PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
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

    -- Flush deferred lifecycle journal appends (acquiring deletion_journal_head FOR UPDATE)
    -- strictly BEFORE the final post-write approval-expiry recheck so an approval expiring
    -- during a contended deletion_journal_head wait rolls the entire transaction back.
    SET CONSTRAINTS openmettle.artifact_revisions_lifecycle_journal IMMEDIATE;

    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, now_ms);

    RETURN QUERY SELECT v_affected_revisions, v_affected_bytes, v_policy.revision;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_apply_deadlines(uuid, uuid, bigint, integer, uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.retention_apply_deadlines(uuid, uuid, bigint, integer, uuid, text, text) TO openmettle_api;

-- Audited SECURITY DEFINER projection for active account_admins: exposes retention policy,
-- restore-gate state (without volume_claim_token, restore_run_id or checkpoints) and deletion
-- journal head sequence/origin without granting openmettle_api direct SELECT on deletion_journal,
-- deletion_journal_head or restore_reconciliation_gate. Evaluates authority at server-side
-- clock_timestamp(), records a redacted retention.status_read audit row, and works even while
-- the restore gate is closed.
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
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_now_ms bigint;
    v_policy_revision bigint;
    v_grace_seconds integer;
    v_min_grace_seconds integer;
    v_max_grace_seconds integer;
    v_gate_open boolean;
    v_snapshot_journal_seq bigint;
    v_required_journal_seq bigint;
    v_coverage_complete boolean;
    v_journal_seq bigint;
    v_coverage_started_at_us bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'retention status inspection requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR SHARE;
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
    v_now_ms := greatest(
        coalesce(p_now_ms, 0),
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    );
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, v_now_ms);
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
      INTO STRICT
           v_policy_revision,
           v_grace_seconds,
           v_min_grace_seconds,
           v_max_grace_seconds,
           v_gate_open,
           v_snapshot_journal_seq,
           v_required_journal_seq,
           v_coverage_complete,
           v_journal_seq,
           v_coverage_started_at_us
      FROM openmettle.retention_policy p
      CROSS JOIN openmettle.restore_reconciliation_gate g
      CROSS JOIN openmettle.deletion_journal_head h
     WHERE p.id AND g.id AND h.id;

    INSERT INTO openmettle.authorization_audit
        (actor_user_id, action, target_kind, target_id, request_key, reason, details)
    VALUES (
        p_actor,
        'retention.status_read',
        'retention_policy',
        'instance',
        gen_random_uuid()::text,
        'admin_inspection',
        jsonb_build_object(
            'policy_revision', v_policy_revision,
            'gate_open', v_gate_open,
            'journal_seq', v_journal_seq
        )
    );

    v_now_ms := greatest(
        v_now_ms,
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    );
    PERFORM openmettle.retention_assert_active_admin(p_actor, p_approval, v_now_ms);

    RETURN QUERY SELECT
        v_policy_revision,
        v_grace_seconds,
        v_min_grace_seconds,
        v_max_grace_seconds,
        v_gate_open,
        v_snapshot_journal_seq,
        v_required_journal_seq,
        v_coverage_complete,
        v_journal_seq,
        v_coverage_started_at_us;
END
$$;
REVOKE ALL ON FUNCTION openmettle.admin_retention_status(uuid, uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.admin_retention_status(uuid, uuid, bigint) TO openmettle_api;
