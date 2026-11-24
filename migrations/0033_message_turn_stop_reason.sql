-- ADR 0038 / ADR 0044 (increment 3c): record when an assistant turn stopped at its output token
-- limit so partial answers stay distinct from normal completions on history reads.
ALTER TABLE openmettle.message_turns
    ADD COLUMN stop_reason text,
    ADD CONSTRAINT message_turns_stop_reason_check CHECK (
        stop_reason IS NULL OR (author_user_id IS NULL AND stop_reason IN ('limit'))
    );

GRANT SELECT (stop_reason) ON openmettle.message_turns TO openmettle_api;
GRANT INSERT (stop_reason) ON openmettle.message_turns TO openmettle_worker;
