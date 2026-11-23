-- V1-16 migration 28 (ADR 0041 PR2a): audited retention policy, purge reference recheck and the
-- append-only deletion journal for purged artifact revisions. Released migrations are immutable.
-- Runs once per release as openmettle_owner in one transaction with search_path
-- pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
--
-- Lock order (ADR 0005, ADR 0040): runs -> storage_reservations -> artifacts ->
-- artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance, then
-- retention_policy FOR SHARE (a removal's deadline stamp) and the deletion journal head at
-- commit. Policy writes lock account_admin_lock and then the policy row and touch no storage row.
--
-- Upgrade from 27: a purge claim ('purging') committed by the previous worker completes even if
-- the revision is attached. It was valid under schema 27, which rechecked no reference, and its
-- payload may already be truncated, so returning it to 'retained' would present damaged bytes as
-- recoverable. Under this schema a 'purging' revision accepts no new attachment or hold, so only
-- such pre-upgrade claims (and owner break-glass claims) complete while referenced. See
-- docs/operator/storage-adoption-and-quota-upgrade.md.

-- Installation-wide retention grace. openmettle_owner sets the deployment bounds; an
-- account_admin chooses grace_seconds within them through retention_set_grace. Every change, by
-- either path, increments revision (trigger below), and disassociation stamps the revision it
-- applied. The default bounds admit only the 30-day default, so nothing shorter (including 0,
-- immediate purge eligibility) is possible until the operator widens them.
CREATE TABLE openmettle.retention_policy (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    grace_seconds integer NOT NULL DEFAULT 2592000,
    min_grace_seconds integer NOT NULL DEFAULT 2592000 CHECK (min_grace_seconds >= 0),
    max_grace_seconds integer NOT NULL DEFAULT 2592000,
    CONSTRAINT retention_policy_bounds_check
        CHECK (grace_seconds BETWEEN min_grace_seconds AND max_grace_seconds)
);
INSERT INTO openmettle.retention_policy (id) VALUES (true);

CREATE FUNCTION openmettle.retention_policy_bump_revision()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_policy_bump_revision() FROM PUBLIC;
CREATE TRIGGER retention_policy_revision BEFORE UPDATE ON openmettle.retention_policy
    FOR EACH ROW EXECUTE FUNCTION openmettle.retention_policy_bump_revision();

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
        'retention.policy_update')),
    DROP CONSTRAINT authorization_audit_target_kind_check,
    ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN
        ('user', 'project', 'conversation', 'artifact', 'local_group', 'capability', 'scope', 'branch',
         'quota_scope', 'retention_policy'));

-- The audited account_admin change: one policy revision and one authorization_audit row, or an
-- error (42501 not an active administrator, 23514 outside the deployment bounds or an invalid
-- reason/key, 23505 a reused request key, 25000 not READ COMMITTED) that aborts the caller's
-- transaction. Changes govern later disassociations only; no stored deadline moves. As in the
-- administration store, the actor is checked in a statement after account_admin_lock, which
-- demotion and disablement also take, so READ COMMITTED sees one committed during the wait.
CREATE FUNCTION openmettle.retention_set_grace(
    p_actor uuid, p_grace_seconds integer, p_reason text, p_request_key text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    prior openmettle.retention_policy%ROWTYPE;
    rev bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'retention policy changes require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    PERFORM FROM openmettle.account_admin_lock WHERE id FOR NO KEY UPDATE;
    -- sessions::disable_user locks only the user row: hold it FOR SHARE so a disable in flight
    -- is waited for and rechecked, and a later one waits for this change to commit.
    PERFORM FROM openmettle.account_admins a JOIN openmettle.users u ON u.id = a.user_id
     WHERE a.user_id = p_actor AND a.active AND u.disabled_at IS NULL FOR SHARE OF u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'administrator required' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO STRICT prior FROM openmettle.retention_policy WHERE id FOR UPDATE;
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
REVOKE ALL ON FUNCTION openmettle.retention_set_grace(uuid, integer, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.retention_set_grace(uuid, integer, text, text) TO openmettle_api;

-- grace_seconds = 0 makes a revision purge-eligible at the instant it is retained.
ALTER TABLE openmettle.artifact_revisions
    ADD COLUMN retention_policy_revision bigint,
    DROP CONSTRAINT artifact_revisions_lifecycle_check,
    ADD CONSTRAINT artifact_revisions_lifecycle_check CHECK (
        (state = 'active' AND retained_at IS NULL AND purge_after IS NULL
            AND purging_at IS NULL AND purged_at IS NULL)
        OR (state = 'retained' AND retained_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= retained_at
            AND purging_at IS NULL AND purged_at IS NULL)
        OR (state = 'purging' AND retained_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= retained_at
            AND purging_at IS NOT NULL
            AND purging_at >= purge_after AND purged_at IS NULL)
        OR (state = 'purged' AND retained_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after >= retained_at
            AND purging_at IS NOT NULL AND purged_at IS NOT NULL
            AND purging_at >= purge_after AND purged_at >= purging_at)
    );
GRANT UPDATE (retention_policy_revision) ON openmettle.artifact_revisions TO openmettle_api;

-- The database sets every removal's deadline: entering 'retained' from 'active' overwrites any
-- caller-supplied retained_at, purge_after and policy stamp (the schema-27 helper wrote its own)
-- with the wall clock read after the policy lock and the current policy. FOR SHARE waits for an
-- in-flight policy change and then reads it under READ COMMITTED; under REPEATABLE READ or
-- SERIALIZABLE a change committed after the snapshot fails with 40001 rather than applying the
-- superseded grace. A missing policy row fails the removal. Only a caller allowed to write the
-- retention columns (the API, ADR 0005's role split) gets a deadline: the WHEN clause runs as the
-- caller, so a worker's 'retained' without one fails the lifecycle check.
CREATE FUNCTION openmettle.retention_stamp_deadline()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    p openmettle.retention_policy%ROWTYPE;
BEGIN
    SELECT * INTO STRICT p FROM openmettle.retention_policy WHERE id FOR SHARE;
    NEW.retained_at := clock_timestamp();
    NEW.purge_after := NEW.retained_at + p.grace_seconds * interval '1 second';
    NEW.retention_policy_revision := p.revision;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_stamp_deadline() FROM PUBLIC;
CREATE TRIGGER artifact_revisions_retention_deadline BEFORE UPDATE OF state ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (OLD.state = 'active' AND NEW.state = 'retained'
        AND pg_catalog.has_column_privilege('openmettle.artifact_revisions', 'purge_after', 'UPDATE'))
    EXECUTE FUNCTION openmettle.retention_stamp_deadline();

-- An operator hold keeps a revision from being claimed for purge. Only openmettle_owner places
-- (INSERT) or releases (DELETE) holds in this release; no application role can change them.
CREATE TABLE openmettle.artifact_retention_holds (
    scope_id uuid NOT NULL,
    artifact_revision_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, artifact_revision_id),
    FOREIGN KEY (scope_id, artifact_revision_id) REFERENCES openmettle.artifact_revisions (scope_id, id)
);

CREATE INDEX message_parts_revision_idx ON openmettle.message_parts (scope_id, artifact_revision_id)
    WHERE artifact_revision_id IS NOT NULL;

-- A new (or re-keyed) reference locks the revision it names FOR SHARE and requires one of the
-- states given as trigger arguments. A purge claim holds the same row FOR UPDATE while it
-- rechecks references, so either this reference commits first and the recheck sees it, or this
-- statement waits, sees 'purging' and fails with OMR01. Under REPEATABLE READ the wait instead
-- ends in a serialization failure. A missing revision is left to the foreign key (23503).
CREATE FUNCTION openmettle.retention_lock_referenced_revision()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    v_state text;
BEGIN
    SELECT state INTO v_state FROM openmettle.artifact_revisions
     WHERE scope_id = NEW.scope_id AND id = NEW.artifact_revision_id FOR SHARE;
    IF FOUND AND v_state <> ALL (TG_ARGV) THEN
        RAISE EXCEPTION 'artifact revision is not live' USING ERRCODE = 'OMR01';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_lock_referenced_revision() FROM PUBLIC;
CREATE TRIGGER message_parts_lock_revision
    BEFORE INSERT OR UPDATE OF scope_id, artifact_revision_id ON openmettle.message_parts
    FOR EACH ROW WHEN (NEW.artifact_revision_id IS NOT NULL)
    EXECUTE FUNCTION openmettle.retention_lock_referenced_revision('active');
CREATE TRIGGER artifact_retention_holds_lock_revision
    BEFORE INSERT OR UPDATE OF scope_id, artifact_revision_id ON openmettle.artifact_retention_holds
    FOR EACH ROW EXECUTE FUNCTION openmettle.retention_lock_referenced_revision('active', 'retained');

-- True while something may still read the revision: an attachment in any message (conversations
-- and projects have no deletion tombstone yet, so every attachment stays live), an operator
-- hold, or the run that wrote it while that run is unfinished or a linked operation (any of the
-- run's when none is linked) has no known outcome. Runs and operations only move towards an
-- outcome, so a false result cannot become true; new attachments and holds are serialized by
-- retention_lock_referenced_revision. Callers must hold the revision row lock and evaluate this
-- in a statement started after acquiring it, under READ COMMITTED.
CREATE FUNCTION openmettle.artifact_revision_pinned(p_scope uuid, p_revision uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT EXISTS (SELECT FROM openmettle.message_parts
                    WHERE scope_id = p_scope AND artifact_revision_id = p_revision)
        OR EXISTS (SELECT FROM openmettle.artifact_retention_holds
                    WHERE scope_id = p_scope AND artifact_revision_id = p_revision)
        OR EXISTS (SELECT FROM openmettle.artifact_revisions r
                     JOIN openmettle.storage_reservations s ON s.scope_id = r.scope_id AND s.id = r.reservation_id
                     JOIN openmettle.runs u ON u.scope_id = s.scope_id AND u.id = s.run_id
                    WHERE r.scope_id = p_scope AND r.id = p_revision
                      AND (u.state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
                           OR EXISTS (SELECT FROM openmettle.operations o
                                       WHERE o.scope_id = u.scope_id AND o.run_id = u.id
                                         AND (s.operation_id IS NULL OR o.id = s.operation_id)
                                         AND o.outcome IN ('intent', 'outcome_unknown'))))
$$;
REVOKE ALL ON FUNCTION openmettle.artifact_revision_pinned(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.artifact_revision_pinned(uuid, uuid) TO openmettle_worker;

-- Backstop for every application writer, including a previous worker binary during a rolling
-- upgrade: entering 'purging' or 'purged' from a live state requires READ COMMITTED (25000) and
-- no reference (OMR01). storage::begin_purge evaluates the same predicate first and defers
-- without raising. As for migration 24's pin guard, openmettle_owner is exempt: it is the
-- break-glass path for erasing a revision that is still referenced. The WHEN clause runs as the
-- caller; the journal still records every purge.
CREATE FUNCTION openmettle.retention_guard_purge_claim()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'purge claims require READ COMMITTED' USING ERRCODE = '25000';
    END IF;
    IF openmettle.artifact_revision_pinned(NEW.scope_id, NEW.id) THEN
        RAISE EXCEPTION 'artifact revision is still referenced' USING ERRCODE = 'OMR01';
    END IF;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION openmettle.retention_guard_purge_claim() FROM PUBLIC;
CREATE TRIGGER artifact_revisions_purge_claim_guard BEFORE UPDATE OF state ON openmettle.artifact_revisions
    FOR EACH ROW WHEN (NEW.state IN ('purging', 'purged') AND OLD.state NOT IN ('purging', 'purged')
        AND NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE'))
    EXECUTE FUNCTION openmettle.retention_guard_purge_claim();

-- Append-only record of irreversible deletions that a restored backup must not undo (ADR 0041).
-- This release records terminal artifact revision purges only. No application role holds any
-- privilege on the journal or its head: the only writer is the SECURITY DEFINER trigger below,
-- and src/boundaries.sql refuses any grant on these tables to a role other than the owner.
-- chain_digest = sha256(previous chain_digest || UTF-8 of the '|'-joined fields
-- 'openmettle.deletion_journal/1', journal_seq, event_kind, entity_id, scope_id, then
-- recorded_at, original_purge_after and purged_at as Unix microseconds, lowercase hex
-- content_digest and policy_revision ('' when NULL)); the chain starts from 32 zero bytes.
CREATE TABLE openmettle.deletion_journal (
    journal_seq bigint PRIMARY KEY CHECK (journal_seq > 0),
    recorded_at timestamptz NOT NULL,
    event_kind text NOT NULL CHECK (event_kind = 'artifact_revision.purged'),
    entity_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    original_purge_after timestamptz NOT NULL,
    purged_at timestamptz NOT NULL,
    content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
    policy_revision bigint,
    chain_digest bytea NOT NULL CHECK (octet_length(chain_digest) = 32),
    CONSTRAINT deletion_journal_entity_key UNIQUE (event_kind, entity_id)
);

-- The single append point: serializes appends and holds the last sequence and chain digest.
CREATE TABLE openmettle.deletion_journal_head (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    journal_seq bigint NOT NULL CHECK (journal_seq >= 0),
    chain_digest bytea NOT NULL CHECK (octet_length(chain_digest) = 32)
);
INSERT INTO openmettle.deletion_journal_head VALUES (true, 0, decode(repeat('00', 32), 'hex'));

CREATE FUNCTION openmettle.deletion_journal_append_purge()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    head openmettle.deletion_journal_head%ROWTYPE;
    e openmettle.deletion_journal%ROWTYPE;
BEGIN
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
    e.chain_digest := sha256(head.chain_digest || convert_to(concat_ws('|',
        'openmettle.deletion_journal/1', e.journal_seq, e.event_kind, e.entity_id, e.scope_id,
        (extract(epoch FROM e.recorded_at) * 1000000)::bigint,
        (extract(epoch FROM e.original_purge_after) * 1000000)::bigint,
        (extract(epoch FROM e.purged_at) * 1000000)::bigint,
        encode(e.content_digest, 'hex'), coalesce(e.policy_revision::text, '')), 'UTF8'));
    INSERT INTO openmettle.deletion_journal SELECT e.*;
    UPDATE openmettle.deletion_journal_head SET journal_seq = e.journal_seq, chain_digest = e.chain_digest
     WHERE id;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION openmettle.deletion_journal_append_purge() FROM PUBLIC;
-- Deferred to commit, so the head lock is the confirming transaction's last lock and a
-- rolled-back confirmation (or savepoint) queues nothing. Any transition into 'purged' appends.
CREATE CONSTRAINT TRIGGER artifact_revisions_purge_journal
    AFTER UPDATE OF state ON openmettle.artifact_revisions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.state = 'purged' AND OLD.state <> 'purged')
    EXECUTE FUNCTION openmettle.deletion_journal_append_purge();

GRANT SELECT ON openmettle.retention_policy TO openmettle_api;
