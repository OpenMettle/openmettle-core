-- One owner-only receipt per committed restoration of a retired login provider.
-- Revision history supplies the configuration provenance without copying identity data.
CREATE TABLE openmettle.provider_recoveries (
    request_id uuid PRIMARY KEY,
    operator_id uuid NOT NULL,
    provider_id uuid NOT NULL REFERENCES openmettle.login_providers(id),
    source_epoch bigint NOT NULL REFERENCES openmettle.login_provider_revisions(epoch),
    retired_epoch bigint NOT NULL REFERENCES openmettle.login_provider_revisions(epoch),
    restored_epoch bigint NOT NULL UNIQUE REFERENCES openmettle.login_provider_revisions(epoch),
    access_generation bigint NOT NULL CHECK (access_generation >= 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (0 < source_epoch AND source_epoch < retired_epoch AND retired_epoch < restored_epoch)
);
