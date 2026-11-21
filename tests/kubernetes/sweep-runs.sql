-- Two synthetic legacy runs with NULL deadlines, both immediately due under ADR 0033.
BEGIN;
INSERT INTO openmettle.users DEFAULT VALUES RETURNING id AS actor \gset
INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', :'actor')
RETURNING id AS scope \gset
INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id)
VALUES (:'scope', 'personal', :'actor') RETURNING id AS conversation \gset
INSERT INTO openmettle.messages (scope_id, conversation_id) VALUES (:'scope', :'conversation')
RETURNING id AS message \gset
INSERT INTO openmettle.conversation_branches (scope_id, conversation_id, fork_message_id)
VALUES (:'scope', :'conversation', :'message') RETURNING id AS branch \gset
INSERT INTO openmettle.runs (
    scope_id, actor_user_id, conversation_id, branch_id, input_message_id,
    idempotency_key, snapshot_format, snapshot_version, input_snapshot, config_snapshot,
    request_identity, request_digest, state
)
SELECT :'scope', :'actor', :'conversation', :'branch', :'message',
       :'phase' || '-' || state, 'synthetic', 1, '', '', '', decode(repeat('00', 32), 'hex'), state
FROM (VALUES ('queued'), ('running')) AS fixture(state);
COMMIT;
