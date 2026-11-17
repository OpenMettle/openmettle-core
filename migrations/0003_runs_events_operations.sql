-- V1-02 persistence only. No admission, execution or authorization policy.
CREATE TABLE openmettle.conversation_branches (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    fork_message_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, conversation_id, id),
    FOREIGN KEY (scope_id, conversation_id) REFERENCES openmettle.conversations (scope_id, id),
    FOREIGN KEY (conversation_id, fork_message_id) REFERENCES openmettle.messages (conversation_id, id)
);
CREATE TABLE openmettle.runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    conversation_id uuid NOT NULL,
    branch_id uuid NOT NULL,
    input_message_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    snapshot_format text NOT NULL CHECK (octet_length(snapshot_format) BETWEEN 1 AND 128),
    snapshot_version integer NOT NULL CHECK (snapshot_version > 0),
    input_snapshot bytea NOT NULL,
    config_snapshot bytea NOT NULL,
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) <= 270336),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN
        ('queued','running','waiting','cancelling','reconciling','succeeded','failed','cancelled','interrupted')),
    wait_reason text CHECK (octet_length(wait_reason) BETWEEN 1 AND 128),
    last_event_sequence bigint NOT NULL DEFAULT 0 CHECK (last_event_sequence >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(input_snapshot) + octet_length(config_snapshot) <= 262144),
    UNIQUE (scope_id, id),
    UNIQUE (scope_id, actor_user_id, idempotency_key),
    FOREIGN KEY (scope_id, conversation_id, branch_id)
        REFERENCES openmettle.conversation_branches (scope_id, conversation_id, id),
    FOREIGN KEY (conversation_id, input_message_id) REFERENCES openmettle.messages (conversation_id, id)
);
CREATE INDEX runs_scope_conversation_idx ON openmettle.runs (scope_id, conversation_id, created_at, id);
CREATE INDEX runs_actor_idx ON openmettle.runs (actor_user_id, created_at, id);
CREATE TABLE openmettle.run_events (
    scope_id uuid NOT NULL,
    run_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    append_key text NOT NULL CHECK (octet_length(append_key) BETWEEN 1 AND 128),
    format text NOT NULL CHECK (octet_length(format) BETWEEN 1 AND 128),
    format_version integer NOT NULL CHECK (format_version > 0),
    payload bytea NOT NULL CHECK (octet_length(payload) <= 65536),
    identity bytea NOT NULL CHECK (octet_length(identity) <= 73728),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, sequence),
    UNIQUE (run_id, append_key),
    FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id)
);
CREATE INDEX run_events_scope_run_idx ON openmettle.run_events (scope_id, run_id, sequence);
CREATE TABLE openmettle.operations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    run_id uuid NOT NULL,
    logical_key text NOT NULL CHECK (octet_length(logical_key) BETWEEN 1 AND 128),
    target text NOT NULL CHECK (octet_length(target) BETWEEN 1 AND 512),
    capability text NOT NULL CHECK (capability IN ('repeatable_read','idempotent','lookup','non_repeatable')),
    format text NOT NULL CHECK (octet_length(format) BETWEEN 1 AND 128),
    format_version integer NOT NULL CHECK (format_version > 0),
    request bytea NOT NULL CHECK (octet_length(request) <= 65536),
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) <= 73728),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    outcome text NOT NULL DEFAULT 'intent' CHECK (outcome IN ('intent','outcome_unknown','succeeded','failed')),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    downstream_handle text CHECK (octet_length(downstream_handle) BETWEEN 1 AND 2048),
    observation_format text,
    observation_version integer,
    evidence bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, logical_key),
    UNIQUE (scope_id, run_id, id),
    FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id),
    CHECK ((outcome = 'intent' AND revision = 0 AND observation_format IS NULL
            AND observation_version IS NULL AND evidence IS NULL AND downstream_handle IS NULL)
        OR (outcome <> 'intent' AND revision > 0 AND observation_format IS NOT NULL
            AND octet_length(observation_format) BETWEEN 1 AND 128
            AND observation_version IS NOT NULL AND observation_version > 0
            AND evidence IS NOT NULL AND octet_length(evidence) <= 65536)),
    CHECK (outcome NOT IN ('succeeded','failed') OR octet_length(evidence) > 0)
);
CREATE INDEX operations_scope_run_idx ON openmettle.operations (scope_id, run_id, id);
GRANT SELECT, INSERT ON openmettle.conversation_branches TO openmettle_api;
GRANT SELECT ON openmettle.runs TO openmettle_api;
GRANT SELECT ON openmettle.conversation_branches, openmettle.runs TO openmettle_worker;
GRANT SELECT, INSERT ON openmettle.run_events TO openmettle_api, openmettle_worker;
GRANT SELECT ON openmettle.operations TO openmettle_api;
GRANT SELECT ON openmettle.operations TO openmettle_worker;
GRANT UPDATE (last_event_sequence) ON openmettle.runs TO openmettle_api, openmettle_worker;
GRANT UPDATE (outcome, revision, downstream_handle, observation_format, observation_version, evidence)
    ON openmettle.operations TO openmettle_worker;
GRANT INSERT (id, scope_id, actor_user_id, conversation_id, branch_id, input_message_id, idempotency_key, snapshot_format, snapshot_version, input_snapshot, config_snapshot, request_identity, request_digest) ON openmettle.runs TO openmettle_api;
GRANT INSERT (id, scope_id, run_id, logical_key, target, capability, format, format_version, request, request_identity, request_digest) ON openmettle.operations TO openmettle_worker;
