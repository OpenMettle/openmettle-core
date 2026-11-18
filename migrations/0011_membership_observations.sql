-- Owner enrollment pins an existing approval to one immutable mapping revision and project.
-- The API may advance the observation only. An empty table leaves exact approval unchanged.
CREATE TABLE openmettle.membership_observations (
    approval_id uuid PRIMARY KEY REFERENCES openmettle.local_identity_approvals(id),
    rule_id uuid NOT NULL,
    rule_revision bigint NOT NULL,
    project_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    max_age_seconds integer NOT NULL CHECK (max_age_seconds BETWEEN 1 AND 3600),
    issued_ms bigint,
    expires_ms bigint,
    observation text CHECK (observation IN ('present','absent','missing','partial','ambiguous','stale','failed')),
    epoch bigint REFERENCES openmettle.login_provider_revisions(epoch),
    approval_generation bigint,
    user_generation bigint,
    FOREIGN KEY (rule_id,rule_revision) REFERENCES openmettle.grant_mapping_revisions(rule_id,revision),
    FOREIGN KEY (project_id,scope_id) REFERENCES openmettle.projects(id,scope_id),
    CHECK (num_nonnulls(issued_ms,expires_ms,observation,epoch,approval_generation,user_generation) IN (0,6))
);
GRANT SELECT ON openmettle.membership_observations TO openmettle_api;
GRANT UPDATE (issued_ms, expires_ms, observation, epoch, approval_generation, user_generation)
    ON openmettle.membership_observations TO openmettle_api;
