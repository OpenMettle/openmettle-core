-- V1-30 migration 44 (ADR 0040 / ADR 0041, issue #154): owner-only declaration of an
-- unrecoverable artifact payload as permanently lost after a restore.
-- Adds artifact_revisions.lost_at, widens artifact_revisions state and lifecycle CHECKs to
-- include 'lost' with an owner-only trigger guard (SQLSTATE 42501 for non-owners), widens
-- authorization_audit for operator action 'storage.declare_payload_lost' on target_kind
-- 'artifact_revision', widens deletion_journal for event_kind 'artifact_revision.lost' with a
-- unique partial index enforcing mutual exclusion across terminal 'artifact_revision.purged' and
-- 'artifact_revision.lost' commitments, adds owner-only storage_declare_payload_lost(...) and
-- restore_verify_lost_journal_tail(...), and updates restore_replay_baseline,
-- restore_verify_checkpoints, restore_verify_export, restore_claim_volume_phase,
-- restore_gate_open, and deletion_journal_replay so DB-only journal replay works under a held
-- adoption_run_id barrier and post-replay lost declarations keep restore reconciliation and
-- subsequent restores to older backups consistent.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (ADR 0005, ADR 0040, ADR 0041):
--   pg_advisory_xact_lock(1330467394, 42) -> storage_reservations -> artifact_revisions ->
--   restore_reconciliation_gate -> storage_volume_control (FOR SHARE) -> storage_accounts ->
--   storage_instance -> deletion_journal_head.
--
-- Role boundaries (verified by src/boundaries.sql):
--   - openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway: zero EXECUTE
--     on any new function, zero UPDATE privilege on artifact_revisions.lost_at, and trigger-
--     enforced 42501 on any attempt to enter, leave, or alter a 'lost' revision.
--   - openmettle_api and openmettle_worker already hold table-level SELECT on
--     artifact_revisions (migration 4), so lost_at is readable for owner metadata and /v1 410.

-- Acquire ACCESS EXCLUSIVE on every pre-existing table modified by migration 44 in one atomic
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
            LOCK TABLE openmettle.artifact_revisions,
                       openmettle.authorization_audit,
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

-- Additive column lost_at and widened state/lifecycle constraints on artifact_revisions.
ALTER TABLE openmettle.artifact_revisions
    ADD COLUMN lost_at timestamptz,
    DROP CONSTRAINT artifact_revisions_state_check,
    ADD CONSTRAINT artifact_revisions_state_check
        CHECK (state IN ('active', 'retained', 'purging', 'purged', 'lost')),
    DROP CONSTRAINT artifact_revisions_lifecycle_check,
    ADD CONSTRAINT artifact_revisions_lifecycle_check CHECK (
        (
            state = 'active'
            AND retained_at IS NULL
            AND purge_after IS NULL
            AND purging_at IS NULL
            AND purged_at IS NULL
            AND lost_at IS NULL
        )
        OR (
            state = 'retained'
            AND retained_at IS NOT NULL
            AND purge_after IS NOT NULL
            AND purge_after >= retained_at
            AND purging_at IS NULL
            AND purged_at IS NULL
            AND lost_at IS NULL
        )
        OR (
            state = 'purging'
            AND retained_at IS NOT NULL
            AND purge_after IS NOT NULL
            AND purge_after >= retained_at
            AND purging_at IS NOT NULL
            AND purging_at >= purge_after
            AND purged_at IS NULL
            AND lost_at IS NULL
        )
        OR (
            state = 'purged'
            AND retained_at IS NOT NULL
            AND purge_after IS NOT NULL
            AND purge_after >= retained_at
            AND purging_at IS NOT NULL
            AND purged_at IS NOT NULL
            AND purging_at >= purge_after
            AND purged_at >= purging_at
            AND lost_at IS NULL
        )
        OR (
            state = 'lost'
            AND lost_at IS NOT NULL
            AND purged_at IS NULL
            AND (
                (retained_at IS NULL AND purge_after IS NULL AND purging_at IS NULL)
                OR (
                    retained_at IS NOT NULL
                    AND purge_after IS NOT NULL
                    AND purge_after >= retained_at
                    AND purging_at IS NULL
                )
                OR (
                    retained_at IS NOT NULL
                    AND purge_after IS NOT NULL
                    AND purge_after >= retained_at
                    AND purging_at IS NOT NULL
                    AND purging_at >= purge_after
                )
            )
        )
    );

-- Owner-only trigger guard: no runtime role may insert or transition a revision into 'lost',
-- update any column on a 'lost' revision, or modify lost_at.
CREATE FUNCTION openmettle.enforce_artifact_revision_lost_owner_only()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF (TG_OP = 'INSERT' AND (NEW.state = 'lost' OR NEW.lost_at IS NOT NULL))
       OR (
           TG_OP = 'UPDATE'
           AND (
               OLD.state = 'lost'
               OR NEW.state = 'lost'
               OR NEW.lost_at IS DISTINCT FROM OLD.lost_at
           )
       ) THEN
        IF NOT (
            pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
            AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
        ) THEN
            RAISE EXCEPTION 'only openmettle_owner may transition or modify lost artifact revisions'
                USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_artifact_revision_lost_owner_only() FROM PUBLIC;

CREATE TRIGGER artifact_revisions_lost_owner_only
    BEFORE INSERT OR UPDATE
    ON openmettle.artifact_revisions
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.enforce_artifact_revision_lost_owner_only();

-- Widen authorization_audit constraints additively for operator payload-loss declarations.
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
        'storage.declare_payload_lost')),
    DROP CONSTRAINT authorization_audit_target_kind_check,
    ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN (
        'user', 'project', 'conversation', 'artifact', 'local_group', 'capability',
        'scope', 'branch', 'quota_scope', 'retention_policy',
        'family_policy', 'oidc_group', 'restore_gate',
        'external_connection', 'vault', 'artifact_revision')),
    ADD CONSTRAINT authorization_audit_declare_lost_check CHECK (
        (action = 'storage.declare_payload_lost') = (target_kind = 'artifact_revision')
        AND (
            action <> 'storage.declare_payload_lost'
            OR (
                actor_kind = 'operator'
                AND actor_user_id IS NULL
                AND operator_id IS NOT NULL
            )
        )
    );

-- Widen deletion_journal for artifact_revision.lost commitments (uses deletion_journal/2 digest).
-- purged_at records lost_at; retained_at and original_purge_after carry any prior retention
-- timestamps (both NULL when the revision was active when lost).
ALTER TABLE openmettle.deletion_journal
    DROP CONSTRAINT deletion_journal_event_kind_check,
    DROP CONSTRAINT deletion_journal_fields_check,
    ADD CONSTRAINT deletion_journal_event_kind_check CHECK (event_kind IN (
        'artifact_revision.purged',
        'artifact_revision.retained',
        'artifact_revision.deadline_adjusted',
        'artifact_revision.restored',
        'artifact_revision.lost',
        'external_connection.disconnected',
        'external_connection.credential_superseded',
        'external_connection.share_revoked'
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
        OR (
            event_kind = 'artifact_revision.lost'
            AND purged_at IS NOT NULL
            AND (
                (retained_at IS NULL AND original_purge_after IS NULL)
                OR (
                    retained_at IS NOT NULL
                    AND original_purge_after IS NOT NULL
                    AND original_purge_after >= retained_at
                )
            )
        )
        OR (
            event_kind IN (
                'external_connection.disconnected',
                'external_connection.credential_superseded',
                'external_connection.share_revoked'
            )
            AND retained_at IS NULL
            AND original_purge_after IS NULL
            AND purged_at IS NULL
            AND policy_revision IS NOT NULL
            AND policy_revision >= 1
        )
    );

CREATE UNIQUE INDEX deletion_journal_terminal_revision_idx
    ON openmettle.deletion_journal (entity_id)
    WHERE event_kind IN ('artifact_revision.purged', 'artifact_revision.lost');

-- Owner only: verifies that deletion_journal_head either sits exactly at
-- (p_required_seq, p_required_digest), OR extends strictly beyond p_required_seq solely via
-- contiguous, valid-chain 'artifact_revision.lost' records each backed by a
-- storage.declare_payload_lost audit row bound to p_restore_run_id.
CREATE FUNCTION openmettle.restore_verify_lost_journal_tail(
    p_required_seq bigint,
    p_required_digest bytea,
    p_restore_run_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    head openmettle.deletion_journal_head%ROWTYPE;
    j openmettle.deletion_journal%ROWTYPE;
    v_genesis bytea := decode(repeat('00', 32), 'hex');
    v_prev_digest bytea;
    v_expected_seq bigint;
    v_req_digest bytea;
BEGIN
    IF p_required_seq IS NULL OR p_required_seq < 0
       OR p_required_digest IS NULL OR octet_length(p_required_digest) <> 32
       OR p_restore_run_id IS NULL THEN
        RAISE EXCEPTION 'invalid lost journal tail verification parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
    IF head.journal_seq < p_required_seq THEN
        RAISE EXCEPTION 'restored journal head % is behind required %',
            head.journal_seq, p_required_seq USING ERRCODE = 'OMR04';
    END IF;
    IF head.journal_seq = p_required_seq THEN
        IF head.chain_digest IS DISTINCT FROM p_required_digest THEN
            RAISE EXCEPTION 'restored journal head digest does not match locked requirement'
                USING ERRCODE = 'OMR03';
        END IF;
        RETURN;
    END IF;
    IF p_required_seq = 0 THEN
        IF p_required_digest IS DISTINCT FROM v_genesis THEN
            RAISE EXCEPTION 'sequence 0 requires the genesis chain digest' USING ERRCODE = 'OMR03';
        END IF;
    ELSE
        SELECT chain_digest INTO v_req_digest
          FROM openmettle.deletion_journal
         WHERE journal_seq = p_required_seq;
        IF NOT FOUND OR v_req_digest IS DISTINCT FROM p_required_digest THEN
            RAISE EXCEPTION 'required watermark at sequence % does not match journal',
                p_required_seq USING ERRCODE = 'OMR03';
        END IF;
    END IF;
    v_prev_digest := p_required_digest;
    v_expected_seq := p_required_seq;
    FOR j IN
        SELECT *
          FROM openmettle.deletion_journal
         WHERE journal_seq > p_required_seq
         ORDER BY journal_seq ASC
    LOOP
        v_expected_seq := v_expected_seq + 1;
        IF j.journal_seq <> v_expected_seq THEN
            RAISE EXCEPTION 'post-replay journal tail has a sequence gap at %', v_expected_seq
                USING ERRCODE = 'OMR03';
        END IF;
        IF j.event_kind <> 'artifact_revision.lost' THEN
            RAISE EXCEPTION 'unexpected non-lost journal record % beyond locked restore watermark %',
                j.journal_seq, p_required_seq USING ERRCODE = 'OMR03';
        END IF;
        IF j.chain_digest IS DISTINCT FROM openmettle.deletion_journal_digest(v_prev_digest, j) THEN
            RAISE EXCEPTION 'post-replay lost journal record % has an invalid chain digest',
                j.journal_seq USING ERRCODE = 'OMR03';
        END IF;
        IF NOT EXISTS (
            SELECT 1
              FROM openmettle.authorization_audit a
             WHERE a.actor_kind = 'operator'
               AND a.action = 'storage.declare_payload_lost'
               AND a.target_kind = 'artifact_revision'
               AND a.target_id = j.entity_id::text
               AND (a.details->>'restore_run_id') = p_restore_run_id::text
               AND (a.details->>'journal_seq') = j.journal_seq::text
        ) THEN
            RAISE EXCEPTION 'post-replay lost journal record % lacks matching audit for restore run %',
                j.journal_seq, p_restore_run_id USING ERRCODE = 'OMR03';
        END IF;
        v_prev_digest := j.chain_digest;
    END LOOP;
    IF v_expected_seq <> head.journal_seq OR v_prev_digest IS DISTINCT FROM head.chain_digest THEN
        RAISE EXCEPTION 'post-replay lost journal tail does not match deletion_journal_head'
            USING ERRCODE = 'OMR03';
    END IF;
END
$$;
REVOKE ALL ON FUNCTION openmettle.restore_verify_lost_journal_tail(bigint, bytea, uuid) FROM PUBLIC;

-- Owner only: declare one settled artifact revision's unrecoverable payload permanently lost.
-- Enforces READ COMMITTED, owner-only execution, canonical lock order, active adoption barrier
-- or closed restore gate after journal replay has caught up, idempotency on request_key (23505
-- on mismatch), retention-hold deletion, storage accounting decrement (exactly once), audited
-- operator record, and append-only 'artifact_revision.lost' commitment in deletion_journal.
CREATE FUNCTION openmettle.storage_declare_payload_lost(
    p_revision_id uuid,
    p_operator_id uuid,
    p_request_key text,
    p_reason text)
RETURNS TABLE(
    applied boolean,
    reservation_id uuid,
    scope_id uuid,
    artifact_id uuid,
    previous_state text,
    journal_seq bigint)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    v_scope_id uuid;
    v_reservation_id uuid;
    s openmettle.storage_reservations%ROWTYPE;
    r openmettle.artifact_revisions%ROWTYPE;
    v_rev_found boolean := false;
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    v_volume_id uuid;
    v_adoption_run_id uuid;
    v_head_lifecycle_origin_us bigint;
    head openmettle.deletion_journal_head%ROWTYPE;
    e openmettle.deletion_journal%ROWTYPE;
    v_existing record;
    v_lost_at timestamptz;
    v_details jsonb;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'storage declare-lost requires READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF NOT (
        pg_catalog.pg_has_role(session_user, 'openmettle_owner', 'USAGE')
        AND pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'only openmettle_owner may declare artifact payloads lost'
            USING ERRCODE = '42501';
    END IF;
    IF p_revision_id IS NULL
       OR p_operator_id IS NULL
       OR p_request_key IS NULL
       OR octet_length(p_request_key) NOT BETWEEN 1 AND 128
       OR btrim(p_request_key) <> p_request_key
       OR p_request_key COLLATE "C" ~ '[[:cntrl:]]'
       OR p_reason IS NULL
       OR octet_length(p_reason) NOT BETWEEN 1 AND 512
       OR btrim(p_reason) <> p_reason
       OR p_reason COLLATE "C" ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid storage declare-lost parameters' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(1330467394, 42);

    -- Read immutable (scope_id, reservation_id) to take locks in canonical order:
    -- storage_reservations -> artifact_revisions -> restore_reconciliation_gate ->
    -- storage_volume_control -> storage_accounts -> storage_instance -> deletion_journal_head.
    SELECT ar.scope_id, ar.reservation_id
      INTO v_scope_id, v_reservation_id
      FROM openmettle.artifact_revisions ar
     WHERE ar.id = p_revision_id;
    IF FOUND THEN
        SELECT * INTO STRICT s
          FROM openmettle.storage_reservations sr
         WHERE sr.scope_id = v_scope_id AND sr.id = v_reservation_id
           FOR UPDATE;
        SELECT * INTO STRICT r
          FROM openmettle.artifact_revisions ar
         WHERE ar.scope_id = v_scope_id AND ar.id = p_revision_id
           FOR UPDATE;
        v_rev_found := true;
    END IF;

    SELECT * INTO STRICT g FROM openmettle.restore_reconciliation_gate WHERE id FOR UPDATE;
    SELECT volume_id, adoption_run_id
      INTO STRICT v_volume_id, v_adoption_run_id
      FROM openmettle.storage_volume_control
     WHERE id
       FOR SHARE;

    IF v_volume_id IS NULL THEN
        RAISE EXCEPTION 'storage volume is not pinned' USING ERRCODE = 'OMQ03';
    END IF;
    IF v_adoption_run_id IS NULL AND g.open THEN
        RAISE EXCEPTION 'volume is live and open; storage declare-lost requires an active adoption barrier or a closed restore gate'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF NOT g.open AND g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp() THEN
        RAISE EXCEPTION 'restore volume phase is active' USING ERRCODE = 'OMR02';
    END IF;
    IF NOT g.open THEN
        SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id;
        IF head.journal_seq < g.required_journal_seq
           OR (head.journal_seq = g.required_journal_seq
               AND head.chain_digest IS DISTINCT FROM g.required_chain_digest) THEN
            RAISE EXCEPTION 'replay the deletion journal before declaring payloads lost'
                USING ERRCODE = 'OMR04';
        END IF;
        IF g.required_lifecycle_origin_us IS NOT NULL THEN
            v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
            IF g.required_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
                IF g.required_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
                   OR g.required_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
                    RAISE EXCEPTION 'replay the deletion journal and lifecycle baseline before declaring payloads lost'
                        USING ERRCODE = 'OMR04';
                END IF;
            ELSIF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest
                  OR v_head_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us
                  OR head.lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
                RAISE EXCEPTION 'replay the deletion journal and lifecycle baseline before declaring payloads lost'
                    USING ERRCODE = 'OMR04';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM openmettle.artifact_revisions r2
                 WHERE r2.state IN ('retained', 'purging')
                   AND NOT EXISTS (
                       SELECT 1
                         FROM openmettle.retention_upgrade_baseline b
                        WHERE b.artifact_revision_id = r2.id
                   )
                   AND NOT EXISTS (
                       SELECT 1
                         FROM openmettle.deletion_journal j
                        WHERE j.entity_id = r2.id
                          AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
                   )
            ) THEN
                RAISE EXCEPTION 'unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal'
                    USING ERRCODE = 'OMR04';
            END IF;
        END IF;
    END IF;

    -- Idempotency / request-key conflict check under locks.
    SELECT a.actor_kind, a.operator_id, a.action, a.target_kind, a.target_id, a.reason, a.details
      INTO v_existing
      FROM openmettle.authorization_audit a
     WHERE a.actor_kind = 'operator'
       AND (
           (a.action = 'storage.declare_payload_lost' AND a.request_key = p_request_key)
           OR (a.operator_id = p_operator_id AND a.request_key = p_request_key)
       )
     LIMIT 1;
    IF FOUND THEN
        IF v_existing.action = 'storage.declare_payload_lost'
           AND v_existing.operator_id = p_operator_id
           AND v_existing.target_kind = 'artifact_revision'
           AND v_existing.target_id = p_revision_id::text
           AND v_existing.reason = p_reason THEN
            IF NOT v_rev_found OR r.state <> 'lost' THEN
                RAISE EXCEPTION 'replayed declare-lost target revision is not in lost state'
                    USING ERRCODE = 'OMQ03';
            END IF;
            IF NOT g.open THEN
                -- Exact retry touches neither storage_accounts nor storage_instance, so taking
                -- deletion_journal_head FOR SHARE here strictly follows canonical lock order.
                SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR SHARE;
                IF head.journal_seq < g.required_journal_seq
                   OR (head.journal_seq = g.required_journal_seq
                       AND head.chain_digest IS DISTINCT FROM g.required_chain_digest) THEN
                    RAISE EXCEPTION 'replay the deletion journal before declaring payloads lost'
                        USING ERRCODE = 'OMR04';
                END IF;
                IF head.journal_seq > g.required_journal_seq THEN
                    PERFORM openmettle.restore_verify_lost_journal_tail(
                        g.required_journal_seq,
                        g.required_chain_digest,
                        g.restore_run_id
                    );
                END IF;
                IF g.required_lifecycle_origin_us IS NOT NULL THEN
                    v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
                    IF g.required_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
                        IF g.required_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
                           OR g.required_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
                            RAISE EXCEPTION 'replay the deletion journal and lifecycle baseline before declaring payloads lost'
                                USING ERRCODE = 'OMR04';
                        END IF;
                    ELSIF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest
                          OR v_head_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us
                          OR head.lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
                        RAISE EXCEPTION 'replay the deletion journal and lifecycle baseline before declaring payloads lost'
                            USING ERRCODE = 'OMR04';
                    END IF;
                END IF;
            END IF;
            RETURN QUERY SELECT
                false,
                s.id,
                r.scope_id,
                r.artifact_id,
                (v_existing.details->>'previous_state')::text,
                (v_existing.details->>'journal_seq')::bigint;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request key already used with different parameters' USING ERRCODE = '23505';
    END IF;

    IF NOT v_rev_found THEN
        RAISE EXCEPTION 'artifact revision not found' USING ERRCODE = 'P0002';
    END IF;
    IF s.state <> 'settled' THEN
        RAISE EXCEPTION 'artifact revision reservation is not settled' USING ERRCODE = 'OMQ03';
    END IF;
    IF r.state = 'lost' THEN
        RAISE EXCEPTION 'artifact revision payload is already declared lost' USING ERRCODE = 'OMQ03';
    END IF;
    IF r.state = 'purged' THEN
        RAISE EXCEPTION 'cannot declare a purged artifact revision lost' USING ERRCODE = 'OMQ03';
    END IF;
    IF r.state NOT IN ('active', 'retained', 'purging') THEN
        RAISE EXCEPTION 'artifact revision is not eligible to be declared lost' USING ERRCODE = 'OMQ03';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM openmettle.deletion_journal dj
         WHERE dj.event_kind = 'artifact_revision.lost'
           AND dj.entity_id = r.id
    ) THEN
        RAISE EXCEPTION 'artifact revision already has a lost commitment in deletion_journal'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM openmettle.deletion_journal dj
         WHERE dj.event_kind = 'artifact_revision.purged'
           AND dj.entity_id = r.id
    ) THEN
        RAISE EXCEPTION 'cannot declare lost: artifact revision already has a terminal purge commitment in deletion_journal'
            USING ERRCODE = 'OMQ03';
    END IF;

    -- Release any operator retention hold on the lost revision.
    DELETE FROM openmettle.artifact_retention_holds h
     WHERE h.scope_id = r.scope_id AND h.artifact_revision_id = r.id;

    -- Detach stored inode binding on the settled reservation.
    UPDATE openmettle.storage_reservations sr
       SET payload_ino = NULL,
           adoption_unverified = false
     WHERE sr.scope_id = r.scope_id AND sr.id = s.id;

    -- Release accounted bytes once (active_bytes for active, retained_bytes for retained/purging).
    IF r.state = 'active' THEN
        UPDATE openmettle.storage_accounts sa
           SET active_bytes = sa.active_bytes - r.size_bytes
         WHERE sa.scope_id = r.scope_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
        END IF;
        UPDATE openmettle.storage_instance si
           SET active_bytes = si.active_bytes - r.size_bytes;
    ELSE
        UPDATE openmettle.storage_accounts sa
           SET retained_bytes = sa.retained_bytes - r.size_bytes
         WHERE sa.scope_id = r.scope_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
        END IF;
        UPDATE openmettle.storage_instance si
           SET retained_bytes = si.retained_bytes - r.size_bytes;
    END IF;

    SELECT * INTO STRICT head FROM openmettle.deletion_journal_head WHERE id FOR UPDATE;
    IF NOT g.open THEN
        IF head.journal_seq < g.required_journal_seq
           OR (head.journal_seq = g.required_journal_seq
               AND head.chain_digest IS DISTINCT FROM g.required_chain_digest) THEN
            RAISE EXCEPTION 'replay the deletion journal before declaring payloads lost'
                USING ERRCODE = 'OMR04';
        END IF;
        IF head.journal_seq > g.required_journal_seq THEN
            PERFORM openmettle.restore_verify_lost_journal_tail(
                g.required_journal_seq,
                g.required_chain_digest,
                g.restore_run_id
            );
        END IF;
        IF g.required_lifecycle_origin_us IS NOT NULL THEN
            v_head_lifecycle_origin_us := (extract(epoch FROM head.lifecycle_coverage_started_at) * 1000000)::bigint;
            IF g.required_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
                IF g.required_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
                   OR g.required_lifecycle_baseline_digest IS DISTINCT FROM head.lifecycle_baseline_digest THEN
                    RAISE EXCEPTION 'replay the deletion journal and lifecycle baseline before declaring payloads lost'
                        USING ERRCODE = 'OMR04';
                END IF;
            ELSIF g.replayed_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest
                  OR v_head_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us
                  OR head.lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
                RAISE EXCEPTION 'replay the deletion journal and lifecycle baseline before declaring payloads lost'
                    USING ERRCODE = 'OMR04';
            END IF;
            IF EXISTS (
                SELECT 1
                  FROM openmettle.artifact_revisions r2
                 WHERE r2.state IN ('retained', 'purging')
                   AND NOT EXISTS (
                       SELECT 1
                         FROM openmettle.retention_upgrade_baseline b
                        WHERE b.artifact_revision_id = r2.id
                   )
                   AND NOT EXISTS (
                       SELECT 1
                         FROM openmettle.deletion_journal j
                        WHERE j.entity_id = r2.id
                          AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
                   )
            ) THEN
                RAISE EXCEPTION 'unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal'
                    USING ERRCODE = 'OMR04';
            END IF;
        END IF;
    END IF;

    v_lost_at := clock_timestamp();

    UPDATE openmettle.artifact_revisions ar
       SET state = 'lost',
           lost_at = v_lost_at,
           purge_stage = 'none'
     WHERE ar.scope_id = r.scope_id AND ar.id = r.id;

    e.journal_seq := head.journal_seq + 1;
    e.recorded_at := v_lost_at;
    e.event_kind := 'artifact_revision.lost';
    e.entity_id := r.id;
    e.scope_id := r.scope_id;
    e.retained_at := r.retained_at;
    e.original_purge_after := r.purge_after;
    e.purged_at := v_lost_at;
    e.content_digest := r.content_digest;
    e.policy_revision := r.retention_policy_revision;
    e.chain_digest := openmettle.deletion_journal_digest(head.chain_digest, e);

    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head djh
       SET journal_seq = e.journal_seq,
           chain_digest = e.chain_digest
     WHERE djh.id;

    v_details := jsonb_build_object(
        'scope_id', r.scope_id,
        'artifact_id', r.artifact_id,
        'reservation_id', s.id,
        'previous_state', r.state,
        'size_bytes', r.size_bytes,
        'sha256', encode(r.content_digest, 'hex'),
        'journal_seq', e.journal_seq,
        'restore_run_id', g.restore_run_id,
        'adoption_run_id', v_adoption_run_id
    );
    INSERT INTO openmettle.authorization_audit
        (actor_kind, actor_user_id, operator_id, action, target_kind, target_id, request_key, reason, details)
    VALUES
        ('operator', NULL, p_operator_id, 'storage.declare_payload_lost', 'artifact_revision',
         r.id::text, p_request_key, p_reason, v_details);

    RETURN QUERY SELECT
        true,
        s.id,
        r.scope_id,
        r.artifact_id,
        r.state,
        e.journal_seq;
END
$$;
REVOKE ALL ON FUNCTION openmettle.storage_declare_payload_lost(uuid, uuid, text, text) FROM PUBLIC;

-- Owner only: update restore_verify_checkpoints to tolerate a verified post-replay tail of
-- 'artifact_revision.lost' entries bound to the active restore_run_id.
CREATE OR REPLACE FUNCTION openmettle.restore_verify_checkpoints()
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
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
    PERFORM openmettle.restore_verify_lost_journal_tail(
        g.required_journal_seq,
        g.required_chain_digest,
        g.restore_run_id
    );
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

-- Owner only: update restore_verify_export to lock storage_reservations before artifact_revisions
-- (canonical lock order for replaying artifact_revision.lost) and accept a verified post-replay
-- lost tail beyond g.required_journal_seq when re-running restore replay with the original export.
CREATE OR REPLACE FUNCTION openmettle.restore_verify_export(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_lock_entity_ids uuid[] DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
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
    PERFORM 1
       FROM openmettle.storage_reservations sr
      WHERE sr.id IN (
          SELECT ar.reservation_id
            FROM openmettle.artifact_revisions ar
           WHERE ar.id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
              OR ar.state IN ('retained', 'purging')
      )
      ORDER BY sr.id ASC
        FOR UPDATE;
    PERFORM 1
       FROM openmettle.artifact_revisions
      WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         OR state IN ('retained', 'purging')
      ORDER BY id ASC
        FOR UPDATE;
    PERFORM 1
       FROM openmettle.external_connections
      WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         OR id IN (
             SELECT connection_id
               FROM openmettle.external_connection_shares
              WHERE id = ANY(coalesce(p_lock_entity_ids, ARRAY[]::uuid[]))
         )
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
       OR p_export_seq <> g.required_journal_seq THEN
        RAISE EXCEPTION 'export sequence % does not match locked restore requirement %',
            p_export_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'export watermark digest does not match locked requirement'
            USING ERRCODE = 'OMR03';
    END IF;
    IF head.journal_seq > g.required_journal_seq THEN
        PERFORM openmettle.restore_verify_lost_journal_tail(
            g.required_journal_seq,
            g.required_chain_digest,
            g.restore_run_id
        );
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
    IF g.required_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
        RAISE EXCEPTION 'export connection origin % does not match locked requirement %',
            p_connection_origin_us, g.required_connection_origin_us USING ERRCODE = 'OMR04';
    END IF;
END
$$;

-- Owner only: update restore_claim_volume_phase to accept a verified post-replay lost tail.
CREATE OR REPLACE FUNCTION openmettle.restore_claim_volume_phase(
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
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
    IF g.required_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
        RAISE EXCEPTION 'connection journal origin mismatch' USING ERRCODE = 'OMR04';
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
    IF p_export_seq IS DISTINCT FROM g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export sequence does not match locked requirement'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'journal chain digest does not match locked requirement'
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

-- Owner only: update restore_replay_baseline so DB-only journal/baseline catch-up works while a
-- failed storage rebind holds adoption_run_id (locking storage_volume_control FOR SHARE instead
-- of storage_lock_pinned_volume()), and refuse overwriting already lost revisions.
CREATE OR REPLACE FUNCTION openmettle.restore_replay_baseline(
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
                IF v_state IN ('purged', 'lost') THEN
                    RAISE EXCEPTION 'baseline entry % cannot overwrite an already purged or lost revision',
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
                    PERFORM 1 FROM openmettle.storage_volume_control WHERE id FOR SHARE;
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
                      AND j.recorded_at <= v_baseline_origin
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
            PERFORM 1 FROM openmettle.storage_volume_control WHERE id FOR SHARE;
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

-- Owner only: extend deletion_journal_replay with 'artifact_revision.lost' handling, allow
-- DB-only journal replay under a held adoption_run_id barrier (storage_volume_control FOR SHARE),
-- enforce mutual exclusion across terminal 'artifact_revision.purged' and 'artifact_revision.lost'
-- commitments, and ensure no other artifact lifecycle event can overwrite a 'lost' revision.
CREATE OR REPLACE FUNCTION openmettle.deletion_journal_replay(
    p_seq bigint, p_recorded_us bigint, p_event_kind text, p_entity_id uuid, p_scope_id uuid,
    p_original_purge_after_us bigint, p_purged_us bigint, p_content_digest bytea,
    p_policy_revision bigint, p_chain_digest bytea, p_retained_us bigint DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    e openmettle.deletion_journal%ROWTYPE;
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_reservation_id uuid;
    v_state text;
    v_size bigint;
    v_content bytea;
    v_conn_id uuid;
    v_conn_state text;
    v_conn_gen bigint;
    v_share_active boolean;
    v_share_rev bigint;
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
    ELSIF p_event_kind = 'artifact_revision.lost' THEN
        IF p_purged_us IS NULL
           OR (p_retained_us IS NULL) <> (p_original_purge_after_us IS NULL)
           OR (p_retained_us IS NOT NULL AND p_original_purge_after_us < p_retained_us) THEN
            RAISE EXCEPTION 'invalid lost journal replay record' USING ERRCODE = 'OMR03';
        END IF;
    ELSIF p_event_kind IN (
        'external_connection.disconnected',
        'external_connection.credential_superseded',
        'external_connection.share_revoked'
    ) THEN
        IF p_retained_us IS NOT NULL OR p_original_purge_after_us IS NOT NULL
           OR p_purged_us IS NOT NULL OR p_policy_revision IS NULL THEN
            RAISE EXCEPTION 'invalid external connection journal replay record' USING ERRCODE = 'OMR03';
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

    IF p_event_kind LIKE 'artifact_revision.%' THEN
        SELECT reservation_id INTO v_reservation_id
          FROM openmettle.artifact_revisions
         WHERE scope_id = p_scope_id AND id = p_entity_id;
        IF v_reservation_id IS NOT NULL THEN
            PERFORM 1
               FROM openmettle.storage_reservations
              WHERE scope_id = p_scope_id AND id = v_reservation_id
                FOR UPDATE;
        END IF;
        SELECT state, size_bytes, content_digest INTO v_state, v_size, v_content
          FROM openmettle.artifact_revisions WHERE scope_id = p_scope_id AND id = p_entity_id FOR UPDATE;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_state IS NOT NULL AND v_content IS DISTINCT FROM p_content_digest THEN
            RAISE EXCEPTION 'journal record % names a revision with other content', p_seq
                USING ERRCODE = 'OMR03';
        END IF;

        IF p_event_kind = 'artifact_revision.purged' THEN
            IF v_state IN ('purged', 'lost') THEN
                RAISE EXCEPTION 'journal record % names a revision already purged or lost', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF EXISTS (SELECT FROM openmettle.deletion_journal
                        WHERE event_kind IN ('artifact_revision.purged', 'artifact_revision.lost')
                          AND entity_id = e.entity_id) THEN
                RAISE EXCEPTION 'journal record % conflicts with an existing terminal revision commitment', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF g.required_lifecycle_origin_us IS NOT NULL
               AND p_recorded_us > g.required_lifecycle_origin_us
               AND NOT EXISTS (
                   SELECT 1
                     FROM openmettle.retention_upgrade_baseline b
                    WHERE b.artifact_revision_id = p_entity_id
               )
               AND NOT EXISTS (
                   SELECT 1
                     FROM openmettle.deletion_journal j
                    WHERE j.entity_id = p_entity_id
                      AND j.event_kind = 'artifact_revision.retained'
                      AND j.journal_seq < p_seq
               ) THEN
                RAISE EXCEPTION 'post-upgrade purge record % lacks baseline or prior retained commitment', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            DELETE FROM openmettle.artifact_retention_holds
             WHERE scope_id = p_scope_id AND artifact_revision_id = p_entity_id;
            IF v_state = 'active' THEN
                PERFORM 1 FROM openmettle.storage_volume_control WHERE id FOR SHARE;
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
            IF v_state IN ('purging', 'purged', 'lost') THEN
                RAISE EXCEPTION 'journal record % cannot transition a purging, purged, or lost revision', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF v_state = 'active' THEN
                PERFORM 1 FROM openmettle.storage_volume_control WHERE id FOR SHARE;
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
                          AND j.journal_seq < p_seq
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
                          AND j.journal_seq < p_seq
                   )) THEN
                RAISE EXCEPTION 'journal record % requires a retained revision for restore', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF v_state = 'retained' THEN
                PERFORM 1 FROM openmettle.storage_volume_control WHERE id FOR SHARE;
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
        ELSIF p_event_kind = 'artifact_revision.lost' THEN
            IF v_state = 'purged' THEN
                RAISE EXCEPTION 'journal record % cannot mark a purged revision lost', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF EXISTS (SELECT FROM openmettle.deletion_journal
                        WHERE event_kind IN ('artifact_revision.purged', 'artifact_revision.lost')
                          AND entity_id = e.entity_id) THEN
                RAISE EXCEPTION 'journal record % conflicts with an existing terminal revision commitment', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            IF v_state IN ('active', 'retained', 'purging') THEN
                DELETE FROM openmettle.artifact_retention_holds
                 WHERE scope_id = p_scope_id AND artifact_revision_id = p_entity_id;
                IF v_reservation_id IS NOT NULL THEN
                    UPDATE openmettle.storage_reservations
                       SET payload_ino = NULL,
                           adoption_unverified = false
                     WHERE scope_id = p_scope_id AND id = v_reservation_id;
                END IF;
                PERFORM 1 FROM openmettle.storage_volume_control WHERE id FOR SHARE;
                IF v_state = 'active' THEN
                    UPDATE openmettle.storage_accounts
                       SET active_bytes = active_bytes - v_size
                     WHERE scope_id = p_scope_id;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
                    END IF;
                    UPDATE openmettle.storage_instance
                       SET active_bytes = active_bytes - v_size;
                ELSE
                    UPDATE openmettle.storage_accounts
                       SET retained_bytes = retained_bytes - v_size
                     WHERE scope_id = p_scope_id;
                    IF NOT FOUND THEN
                        RAISE EXCEPTION 'storage account missing' USING ERRCODE = 'P0002';
                    END IF;
                    UPDATE openmettle.storage_instance
                       SET retained_bytes = retained_bytes - v_size;
                END IF;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
                UPDATE openmettle.artifact_revisions
                   SET state = 'lost',
                       lost_at = e.purged_at,
                       retained_at = e.retained_at,
                       purge_after = e.original_purge_after,
                       purging_at = CASE
                           WHEN e.retained_at IS NOT NULL AND v_state = 'purging'
                           THEN greatest(purging_at, e.original_purge_after)
                           ELSE NULL
                       END,
                       retention_policy_revision = e.policy_revision,
                       purge_stage = 'none'
                 WHERE scope_id = p_scope_id AND id = p_entity_id;
                PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
            ELSIF v_state = 'lost' THEN
                DELETE FROM openmettle.artifact_retention_holds
                 WHERE scope_id = p_scope_id AND artifact_revision_id = p_entity_id;
                IF v_reservation_id IS NOT NULL THEN
                    UPDATE openmettle.storage_reservations
                       SET payload_ino = NULL,
                           adoption_unverified = false
                     WHERE scope_id = p_scope_id AND id = v_reservation_id;
                END IF;
            END IF;
        END IF;

        IF e.policy_revision IS NOT NULL THEN
            UPDATE openmettle.retention_policy
               SET revision = e.policy_revision + 1
             WHERE id AND revision <= e.policy_revision;
        END IF;
    ELSIF p_event_kind = 'external_connection.disconnected' THEN
        IF p_content_digest IS DISTINCT FROM sha256(convert_to(
            'disconnect:' || p_entity_id::text || ':' || p_policy_revision::text, 'UTF8')) THEN
            RAISE EXCEPTION 'invalid external connection disconnect journal digest at %', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        SELECT state INTO v_conn_state
          FROM openmettle.external_connections
         WHERE id = p_entity_id AND scope_id = p_scope_id
           FOR UPDATE;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_conn_state IS NOT NULL THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            IF v_conn_state <> 'disconnected' THEN
                UPDATE openmettle.external_connections
                   SET granted_scopes = ARRAY[]::text[],
                       state = 'disconnected',
                       expires_at = NULL,
                       encryption_key_id = NULL,
                       access_salt = NULL,
                       access_nonce = NULL,
                       access_ciphertext = NULL,
                       refresh_salt = NULL,
                       refresh_nonce = NULL,
                       refresh_ciphertext = NULL,
                       revocation_generation = greatest(revocation_generation + 1, p_policy_revision),
                       refresh_claim_token = NULL,
                       refresh_lease_until = NULL,
                       disconnected_at = coalesce(disconnected_at, e.recorded_at),
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id;
            ELSE
                UPDATE openmettle.external_connections
                   SET revocation_generation = greatest(revocation_generation, p_policy_revision),
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id
                   AND revocation_generation < p_policy_revision;
            END IF;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind = 'external_connection.credential_superseded' THEN
        IF p_content_digest IS DISTINCT FROM sha256(convert_to(
            'superseded:' || p_entity_id::text || ':' || p_policy_revision::text, 'UTF8')) THEN
            RAISE EXCEPTION 'invalid external connection supersession journal digest at %', p_seq
                USING ERRCODE = 'OMR03';
        END IF;
        SELECT state, credential_generation INTO v_conn_state, v_conn_gen
          FROM openmettle.external_connections
         WHERE id = p_entity_id AND scope_id = p_scope_id
           FOR UPDATE;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_conn_state IS NOT NULL THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            IF v_conn_state = 'authorized' AND v_conn_gen < p_policy_revision THEN
                UPDATE openmettle.external_connections
                   SET granted_scopes = ARRAY[]::text[],
                       state = 'reauth_required',
                       expires_at = NULL,
                       encryption_key_id = NULL,
                       access_salt = NULL,
                       access_nonce = NULL,
                       access_ciphertext = NULL,
                       refresh_salt = NULL,
                       refresh_nonce = NULL,
                       refresh_ciphertext = NULL,
                       credential_generation = p_policy_revision,
                       revocation_generation = revocation_generation + 1,
                       refresh_claim_token = NULL,
                       refresh_lease_until = NULL,
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id;
            ELSIF v_conn_state IN ('pending_auth', 'reauth_required')
                  AND v_conn_gen < p_policy_revision THEN
                UPDATE openmettle.external_connections
                   SET credential_generation = p_policy_revision,
                       updated_at = clock_timestamp()
                 WHERE id = p_entity_id AND scope_id = p_scope_id;
            END IF;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
    ELSIF p_event_kind = 'external_connection.share_revoked' THEN
        SELECT connection_id INTO v_conn_id
          FROM openmettle.external_connection_shares
         WHERE id = p_entity_id AND scope_id = p_scope_id;
        IF v_conn_id IS NOT NULL THEN
            IF p_content_digest IS DISTINCT FROM sha256(convert_to(
                'share_revoked:' || p_entity_id::text || ':' || v_conn_id::text || ':' || p_policy_revision::text,
                'UTF8')) THEN
                RAISE EXCEPTION 'invalid external connection share revocation journal digest at %', p_seq
                    USING ERRCODE = 'OMR03';
            END IF;
            PERFORM 1 FROM openmettle.external_connections
             WHERE id = v_conn_id AND scope_id = p_scope_id
               FOR UPDATE;
            SELECT active, revision INTO v_share_active, v_share_rev
              FROM openmettle.external_connection_shares
             WHERE id = p_entity_id AND scope_id = p_scope_id
               FOR UPDATE;
        END IF;
        SELECT * INTO g FROM openmettle.restore_reconciliation_gate WHERE id AND NOT open FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'journal replay requires a closed restore gate' USING ERRCODE = 'OMR02';
        END IF;
        IF v_conn_id IS NOT NULL AND (v_share_active OR v_share_rev < p_policy_revision) THEN
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'on', true);
            UPDATE openmettle.external_connection_shares
               SET active = false,
                   revision = greatest(revision + 1, p_policy_revision),
                   updated_at = clock_timestamp()
             WHERE id = p_entity_id AND scope_id = p_scope_id;
            UPDATE openmettle.external_connections
               SET share_revision = share_revision + 1,
                   revocation_generation = revocation_generation + 1,
                   updated_at = clock_timestamp()
             WHERE id = v_conn_id AND scope_id = p_scope_id;
            PERFORM pg_catalog.set_config('openmettle.replaying_deletion_journal', 'off', true);
        END IF;
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

-- Owner only: update restore_gate_open to accept a verified post-replay lost tail and ensure
-- every 'artifact_revision.lost' journal entry matches a revision in state 'lost' (OMR05).
CREATE OR REPLACE FUNCTION openmettle.restore_gate_open(
    p_restore_run_id uuid,
    p_claim_token uuid,
    p_origin_us bigint,
    p_export_seq bigint,
    p_export_digest bytea,
    p_expected_volume_id uuid,
    p_lifecycle_origin_us bigint DEFAULT NULL,
    p_lifecycle_baseline_digest bytea DEFAULT NULL,
    p_connection_origin_us bigint DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    g openmettle.restore_reconciliation_gate%ROWTYPE;
    head openmettle.deletion_journal_head%ROWTYPE;
    v_origin_us bigint;
    v_lifecycle_origin_us bigint;
    v_connection_origin_us bigint;
    v_volume_id uuid;
    v_adoption_run_id uuid;
    v_has_live_conn_auth boolean;
    v_conn_origin_verified boolean;
    v_gap_accepted boolean;
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
    v_connection_origin_us := (extract(epoch FROM head.connection_coverage_started_at) * 1000000)::bigint;
    IF p_origin_us IS DISTINCT FROM g.required_origin_us OR p_origin_us IS DISTINCT FROM v_origin_us THEN
        RAISE EXCEPTION 'journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_origin_us IS DISTINCT FROM g.required_lifecycle_origin_us THEN
        RAISE EXCEPTION 'lifecycle journal origin mismatch' USING ERRCODE = 'OMR04';
    END IF;
    IF p_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest THEN
        RAISE EXCEPTION 'lifecycle baseline digest does not match locked requirement' USING ERRCODE = 'OMR03';
    END IF;
    IF g.required_connection_origin_us IS NOT NULL
       AND p_connection_origin_us IS DISTINCT FROM g.required_connection_origin_us THEN
        RAISE EXCEPTION 'connection journal origin mismatch' USING ERRCODE = 'OMR04';
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
    v_gap_accepted := EXISTS (
        SELECT FROM openmettle.authorization_audit
         WHERE actor_kind = 'operator'
           AND action = 'restore.accept_coverage_gap'
           AND target_kind = 'restore_gate'
           AND target_id = 'instance'
           AND (details->>'restore_run_id') = g.restore_run_id::text
           AND (details->>'required_journal_seq')::bigint = g.required_journal_seq
           AND (details->>'required_chain_digest') = encode(g.required_chain_digest, 'hex')
    );
    IF (p_lifecycle_origin_us IS NULL
        OR p_lifecycle_origin_us IS DISTINCT FROM g.snapshot_lifecycle_origin_us
        OR p_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest)
       AND NOT v_gap_accepted THEN
        RAISE EXCEPTION 'backup predates lifecycle journal coverage; inspect or run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    v_has_live_conn_auth := EXISTS (
        SELECT 1 FROM openmettle.external_connections WHERE state = 'authorized'
    ) OR EXISTS (
        SELECT 1 FROM openmettle.external_connection_shares WHERE active
    );
    v_conn_origin_verified := g.required_connection_origin_us IS NOT NULL
        AND p_connection_origin_us = g.required_connection_origin_us
        AND g.required_connection_origin_us = g.snapshot_connection_origin_us
        AND g.required_connection_origin_us = v_connection_origin_us
        AND NOT g.connection_gap_reconciled
        AND NOT v_gap_accepted;
    IF NOT v_conn_origin_verified AND v_has_live_conn_auth THEN
        RAISE EXCEPTION 'authorized external connections or active shares cannot survive an unverified connection coverage gap; run restore accept-coverage-gap'
            USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_seq IS DISTINCT FROM g.required_journal_seq THEN
        RAISE EXCEPTION 'journal export ends at %, restore requires %',
            p_export_seq, g.required_journal_seq USING ERRCODE = 'OMR04';
    END IF;
    IF p_export_digest IS DISTINCT FROM g.required_chain_digest THEN
        RAISE EXCEPTION 'journal chain digest does not match locked requirement'
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
    IF EXISTS (SELECT FROM openmettle.deletion_journal j JOIN openmettle.artifact_revisions r
                 ON r.scope_id = j.scope_id AND r.id = j.entity_id
                WHERE j.event_kind = 'artifact_revision.lost' AND r.state <> 'lost') THEN
        RAISE EXCEPTION 'journaled lost revisions are not marked lost yet' USING ERRCODE = 'OMR05';
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
           snapshot_connection_origin_us = NULL,
           required_connection_origin_us = NULL,
           connection_gap_reconciled = false,
           checkpoints = '[]'::jsonb,
           volume_claim_token = NULL,
           volume_lease_until = NULL
     WHERE id;
END
$$;
