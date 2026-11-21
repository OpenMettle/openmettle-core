-- ADR 0036. Legacy branch identities and message skeletons acquire no inferred history.
ALTER TABLE openmettle.messages ADD UNIQUE (scope_id, conversation_id, id);
ALTER TABLE openmettle.runs ADD UNIQUE (scope_id, conversation_id, id);
CREATE INDEX runs_branch_live_idx ON openmettle.runs (branch_id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');

CREATE TABLE openmettle.branch_heads (
    scope_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    branch_id uuid PRIMARY KEY,
    parent_branch_id uuid CHECK (parent_branch_id <> branch_id),
    head_message_id uuid,
    FOREIGN KEY (scope_id, conversation_id, branch_id)
        REFERENCES openmettle.conversation_branches (scope_id, conversation_id, id),
    FOREIGN KEY (scope_id, conversation_id, parent_branch_id)
        REFERENCES openmettle.conversation_branches (scope_id, conversation_id, id),
    FOREIGN KEY (conversation_id, head_message_id) REFERENCES openmettle.messages (conversation_id, id)
);
CREATE UNIQUE INDEX branch_heads_root_idx ON openmettle.branch_heads (conversation_id)
    WHERE parent_branch_id IS NULL;
CREATE INDEX branch_heads_conversation_idx ON openmettle.branch_heads (conversation_id, head_message_id);

CREATE TABLE openmettle.message_turns (
    scope_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    message_id uuid PRIMARY KEY,
    author_user_id uuid REFERENCES openmettle.users (id),
    run_id uuid UNIQUE,
    reasoning_blocks jsonb,
    reasoning_bytes integer NOT NULL DEFAULT 0,
    input_count bigint CHECK (input_count >= 0),
    output_count bigint CHECK (output_count >= 0),
    UNIQUE (scope_id, conversation_id, message_id),
    FOREIGN KEY (scope_id, conversation_id, message_id) REFERENCES openmettle.messages (scope_id, conversation_id, id),
    FOREIGN KEY (scope_id, conversation_id, run_id) REFERENCES openmettle.runs (scope_id, conversation_id, id),
    CHECK ((author_user_id IS NULL) <> (run_id IS NULL)),
    CHECK (run_id IS NOT NULL OR (reasoning_blocks IS NULL AND input_count IS NULL AND output_count IS NULL)),
    CHECK (reasoning_blocks IS NULL OR (jsonb_typeof(reasoning_blocks) = 'array'
        AND jsonb_array_length(reasoning_blocks) BETWEEN 1 AND 128
        AND NOT jsonb_path_exists(reasoning_blocks, '$[*] ? (@.type() != "object")'))),
    CHECK ((reasoning_blocks IS NULL AND reasoning_bytes = 0)
        OR (reasoning_blocks IS NOT NULL AND reasoning_bytes = octet_length(reasoning_blocks::text)
            AND reasoning_bytes BETWEEN 1 AND 65536))
);

CREATE TABLE openmettle.message_parts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    message_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 127),
    kind text NOT NULL,
    text_value text,
    artifact_revision_id uuid,
    UNIQUE (message_id, ordinal),
    FOREIGN KEY (scope_id, conversation_id, message_id)
        REFERENCES openmettle.message_turns (scope_id, conversation_id, message_id),
    FOREIGN KEY (scope_id, artifact_revision_id) REFERENCES openmettle.artifact_revisions (scope_id, id),
    CHECK ((kind = 'text' AND text_value IS NOT NULL AND octet_length(text_value) <= 65536
            AND artifact_revision_id IS NULL)
        OR (kind = 'attachment' AND text_value IS NULL AND artifact_revision_id IS NOT NULL))
);

-- An answer belongs to the run whose user input it actually follows.
CREATE FUNCTION openmettle.check_turn_producer() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM openmettle.messages m
        JOIN openmettle.runs r ON r.input_message_id = m.parent_message_id
        JOIN openmettle.message_turns u ON u.message_id = r.input_message_id
        WHERE m.id = NEW.message_id AND r.id = NEW.run_id AND u.author_user_id IS NOT NULL) THEN
        RAISE EXCEPTION 'answer does not follow producing run input' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER turn_producer BEFORE INSERT ON openmettle.message_turns
    FOR EACH ROW WHEN (NEW.run_id IS NOT NULL) EXECUTE FUNCTION openmettle.check_turn_producer();

-- A published turn remains either a head or a parent. Head updates can only extend a path.
CREATE FUNCTION openmettle.check_part_unpublished() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM openmettle.message_turns WHERE message_id = NEW.message_id) THEN
        RAISE EXCEPTION 'turn must precede its parts' USING ERRCODE = '23503';
    END IF;
    IF EXISTS (SELECT FROM openmettle.branch_heads WHERE conversation_id = NEW.conversation_id
        AND head_message_id = NEW.message_id) OR EXISTS (SELECT FROM openmettle.messages
        WHERE conversation_id = NEW.conversation_id AND parent_message_id = NEW.message_id) THEN
        RAISE EXCEPTION 'message already published' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER part_unpublished BEFORE INSERT ON openmettle.message_parts
    FOR EACH ROW EXECUTE FUNCTION openmettle.check_part_unpublished();

CREATE FUNCTION openmettle.check_branch_head() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    producer uuid;
    parts integer;
    last_ordinal integer;
    visible_bytes bigint;
    attachments integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (SELECT FROM openmettle.conversation_branches b
            WHERE b.id = NEW.branch_id AND b.fork_message_id IS NOT DISTINCT FROM NEW.head_message_id)
            OR (NEW.parent_branch_id IS NULL AND NEW.head_message_id IS NOT NULL) THEN
            RAISE EXCEPTION 'invalid initial head' USING ERRCODE = '23514';
        END IF;
        IF NEW.parent_branch_id IS NOT NULL AND NOT EXISTS (
            WITH RECURSIVE path(id) AS (
                SELECT head_message_id FROM openmettle.branch_heads WHERE branch_id = NEW.parent_branch_id
                UNION ALL SELECT m.parent_message_id FROM path p JOIN openmettle.messages m ON m.id = p.id
            ) SELECT FROM path WHERE id IS NOT DISTINCT FROM NEW.head_message_id
        ) THEN
            RAISE EXCEPTION 'fork outside managed path' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT t.run_id INTO producer FROM openmettle.message_turns t
        JOIN openmettle.messages m ON m.id = t.message_id
        WHERE t.message_id = NEW.head_message_id
          AND m.parent_message_id IS NOT DISTINCT FROM OLD.head_message_id;
    IF NOT FOUND OR (producer IS NOT NULL AND NOT EXISTS (SELECT FROM openmettle.runs
        WHERE id = producer AND branch_id = NEW.branch_id)) THEN
        RAISE EXCEPTION 'invalid head advance' USING ERRCODE = '23514';
    END IF;
    SELECT count(*), max(ordinal), coalesce(sum(octet_length(text_value)), 0),
           count(artifact_revision_id) INTO parts, last_ordinal, visible_bytes, attachments
        FROM openmettle.message_parts WHERE message_id = NEW.head_message_id;
    IF visible_bytes > 65536 OR last_ordinal <> parts - 1
        OR (producer IS NULL AND visible_bytes = 0 AND attachments = 0) THEN
        RAISE EXCEPTION 'incomplete message parts' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER branch_head_publication BEFORE INSERT OR UPDATE ON openmettle.branch_heads
    FOR EACH ROW EXECUTE FUNCTION openmettle.check_branch_head();

-- A committed turn is already sealed. This also prevents a second transaction inserting
-- parts concurrently with first publication. Multiple turns may be published in one commit.
CREATE FUNCTION openmettle.check_turn_published() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (
        WITH RECURSIVE path(id) AS (
            SELECT head_message_id FROM openmettle.branch_heads
                WHERE conversation_id = NEW.conversation_id
            UNION SELECT m.parent_message_id FROM path p JOIN openmettle.messages m ON m.id = p.id
        ) SELECT FROM path WHERE id = NEW.message_id
    ) THEN
        RAISE EXCEPTION 'turn must be published in its transaction' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER turn_published AFTER INSERT ON openmettle.message_turns
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openmettle.check_turn_published();

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
        'conversation.create', 'branch.create')),
    DROP CONSTRAINT authorization_audit_target_kind_check,
    ADD CONSTRAINT authorization_audit_target_kind_check CHECK (target_kind IN
        ('user', 'project', 'conversation', 'artifact', 'local_group', 'capability', 'scope', 'branch'));

GRANT SELECT, INSERT (scope_id, conversation_id, branch_id, parent_branch_id, head_message_id)
    ON openmettle.branch_heads TO openmettle_api;
GRANT SELECT ON openmettle.branch_heads, openmettle.message_turns TO openmettle_worker;
GRANT UPDATE (head_message_id) ON openmettle.branch_heads TO openmettle_api, openmettle_worker;
GRANT SELECT (scope_id, conversation_id, message_id, author_user_id, run_id, reasoning_bytes, input_count, output_count),
    INSERT (scope_id, conversation_id, message_id, author_user_id)
    ON openmettle.message_turns TO openmettle_api;
GRANT INSERT (scope_id, conversation_id, message_id, run_id, reasoning_blocks, reasoning_bytes, input_count, output_count)
    ON openmettle.message_turns TO openmettle_worker;
GRANT SELECT, INSERT (scope_id, conversation_id, message_id, ordinal, kind, text_value, artifact_revision_id)
    ON openmettle.message_parts TO openmettle_api, openmettle_worker;
