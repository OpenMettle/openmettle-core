-- V1-02 migration 2: scope-owned conversations and parent-linked message graph skeleton.
-- Released migrations are immutable; additive only. Message content, roles and branch
-- semantics belong to V1-07. Read access to a conversation is an application authorization
-- decision (V1-05); these constraints only keep references inside one owner scope.

-- owner_user_id is the private owner in both scope kinds. In a personal scope it must be the
-- scope's user; in a project scope it records the creator and does not publish the
-- conversation to other project members.
CREATE TABLE openmettle.conversations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    scope_kind text NOT NULL,
    owner_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    personal_owner_user_id uuid GENERATED ALWAYS AS (
        CASE WHEN scope_kind = 'personal' THEN owner_user_id END
    ) STORED,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT conversations_scope_fkey
        FOREIGN KEY (scope_id, scope_kind) REFERENCES openmettle.scopes (id, kind),
    CONSTRAINT conversations_personal_owner_fkey
        FOREIGN KEY (scope_id, personal_owner_user_id)
        REFERENCES openmettle.scopes (id, personal_user_id),
    CONSTRAINT conversations_scope_id_key UNIQUE (scope_id, id)
);
CREATE INDEX conversations_scope_owner_idx
    ON openmettle.conversations (scope_id, owner_user_id, created_at);
CREATE INDEX conversations_owner_idx ON openmettle.conversations (owner_user_id);

-- A message stays in its conversation's scope, and its parent is in the same conversation.
CREATE TABLE openmettle.messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    parent_message_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT messages_conversation_fkey FOREIGN KEY (scope_id, conversation_id)
        REFERENCES openmettle.conversations (scope_id, id),
    CONSTRAINT messages_conversation_id_key UNIQUE (conversation_id, id),
    CONSTRAINT messages_parent_fkey FOREIGN KEY (conversation_id, parent_message_id)
        REFERENCES openmettle.messages (conversation_id, id),
    CONSTRAINT messages_parent_not_self_check CHECK (parent_message_id <> id)
);
CREATE INDEX messages_scope_conversation_idx
    ON openmettle.messages (scope_id, conversation_id, created_at);
CREATE INDEX messages_parent_idx ON openmettle.messages (conversation_id, parent_message_id);

GRANT SELECT, INSERT ON openmettle.conversations, openmettle.messages TO openmettle_api;
GRANT SELECT ON openmettle.conversations TO openmettle_worker;
GRANT SELECT, INSERT ON openmettle.messages TO openmettle_worker;
