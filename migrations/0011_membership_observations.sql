-- One immutable owner receipt per enrollment, reset, replacement or suspension.
CREATE TABLE openmettle.membership_configuration_changes (
    revision bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    approval_id uuid NOT NULL REFERENCES openmettle.local_identity_approvals(id),
    previous_revision bigint NOT NULL CHECK (previous_revision >= 0 AND previous_revision < revision),
    rule_id uuid NOT NULL,
    rule_revision bigint NOT NULL,
    project_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    max_age_seconds integer NOT NULL CHECK (max_age_seconds BETWEEN 1 AND 3600),
    enabled boolean NOT NULL,
    baseline_change uuid REFERENCES openmettle.grant_changes(id),
    floor_ms bigint,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor uuid NOT NULL,
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 512),
    FOREIGN KEY (rule_id,rule_revision) REFERENCES openmettle.grant_mapping_revisions(rule_id,revision),
    FOREIGN KEY (project_id,scope_id) REFERENCES openmettle.projects(id,scope_id)
);

-- change_id names immutable v5 history, including its assignment, revision and cycle.
CREATE TYPE openmettle.membership_evidence AS (state text, change_id uuid);
REVOKE USAGE ON TYPE openmettle.membership_evidence FROM PUBLIC;
CREATE TABLE openmettle.membership_observations (
    approval_id uuid PRIMARY KEY REFERENCES openmettle.local_identity_approvals(id),
    config_revision bigint NOT NULL UNIQUE REFERENCES openmettle.membership_configuration_changes(revision),
    enabled boolean NOT NULL,
    floor_ms bigint,
    rule_id uuid NOT NULL,
    rule_revision bigint NOT NULL,
    project_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    max_age_seconds integer NOT NULL CHECK (max_age_seconds BETWEEN 1 AND 3600),
    issued_ms bigint,
    expires_ms bigint,
    observation openmettle.membership_evidence NOT NULL,
    epoch bigint REFERENCES openmettle.login_provider_revisions(epoch),
    approval_generation bigint,
    user_generation bigint,
    FOREIGN KEY (rule_id,rule_revision) REFERENCES openmettle.grant_mapping_revisions(rule_id,revision),
    FOREIGN KEY (project_id,scope_id) REFERENCES openmettle.projects(id,scope_id),
    CHECK ((observation).state IS NOT NULL AND
           (observation).state IN ('present','absent','missing','partial','ambiguous','stale','failed')),
    CHECK ((observation).state <> 'present' OR (observation).change_id IS NOT NULL),
    CHECK (num_nonnulls(issued_ms,expires_ms,epoch,approval_generation,user_generation) IN (0,5)),
    CHECK (issued_ms IS NOT NULL OR (observation).state = 'missing'),
    CHECK (issued_ms > floor_ms)
);
GRANT SELECT ON openmettle.membership_observations TO openmettle_api;
GRANT UPDATE (issued_ms, expires_ms, observation, epoch, approval_generation, user_generation)
    ON openmettle.membership_observations TO openmettle_api;
