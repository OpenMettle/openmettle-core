-- V1-02: provenance and persistence only. No permission meanings or authorization service.
CREATE TABLE openmettle.grant_mapping_rules (
    id uuid PRIMARY KEY,
    provider_config_id uuid NOT NULL,
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    created_by_user_id uuid NOT NULL REFERENCES openmettle.users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0)
);
CREATE TABLE openmettle.grant_mapping_revisions (
    rule_id uuid NOT NULL REFERENCES openmettle.grant_mapping_rules(id),
    revision bigint NOT NULL CHECK (revision > 0),
    actor_user_id uuid NOT NULL REFERENCES openmettle.users(id),
    request_key text NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    enabled boolean NOT NULL,
    selector_kind text NOT NULL CHECK (selector_kind IN ('group','app_role')),
    claim_name text NOT NULL CHECK (octet_length(claim_name) BETWEEN 1 AND 128),
    claim_value text NOT NULL CHECK (octet_length(claim_value) BETWEEN 1 AND 1024),
    binding_format text NOT NULL CHECK (octet_length(binding_format) BETWEEN 1 AND 128),
    binding_version integer NOT NULL CHECK (binding_version > 0),
    binding bytea NOT NULL CHECK (octet_length(binding) <= 16384),
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) BETWEEN 1 AND 32768),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, revision),
    UNIQUE (rule_id, actor_user_id, request_key)
);
CREATE TABLE openmettle.grant_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES openmettle.scopes(id),
    target_kind text NOT NULL CHECK (target_kind IN ('project','conversation','artifact')),
    project_id uuid,
    conversation_id uuid,
    artifact_id uuid,
    target_id uuid GENERATED ALWAYS AS (coalesce(project_id,conversation_id,artifact_id)) STORED,
    grantee_user_id uuid NOT NULL REFERENCES openmettle.users(id),
    assignment_format text NOT NULL CHECK (octet_length(assignment_format) BETWEEN 1 AND 128),
    assignment_version integer NOT NULL CHECK (assignment_version > 0),
    assignment_key text NOT NULL CHECK (octet_length(assignment_key) BETWEEN 1 AND 128),
    source_kind text NOT NULL CHECK (source_kind IN ('direct','mapped')),
    mapping_rule_id uuid REFERENCES openmettle.grant_mapping_rules(id),
    created_by_user_id uuid NOT NULL REFERENCES openmettle.users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0),
    CHECK ((target_kind='project' AND project_id IS NOT NULL AND conversation_id IS NULL AND artifact_id IS NULL)
        OR (target_kind='conversation' AND conversation_id IS NOT NULL AND project_id IS NULL AND artifact_id IS NULL)
        OR (target_kind='artifact' AND artifact_id IS NOT NULL AND project_id IS NULL AND conversation_id IS NULL)),
    CHECK ((source_kind='direct' AND mapping_rule_id IS NULL)
        OR (source_kind='mapped' AND mapping_rule_id IS NOT NULL)),
    FOREIGN KEY (project_id,scope_id) REFERENCES openmettle.projects(id,scope_id),
    FOREIGN KEY (scope_id,conversation_id) REFERENCES openmettle.conversations(scope_id,id),
    FOREIGN KEY (scope_id,artifact_id) REFERENCES openmettle.artifacts(scope_id,id),
    UNIQUE NULLS NOT DISTINCT (scope_id,target_kind,target_id,grantee_user_id,assignment_format,assignment_version,assignment_key,mapping_rule_id),
    UNIQUE (scope_id,id,source_kind),
    UNIQUE (id,mapping_rule_id)
);
CREATE INDEX grant_assignments_grantee_idx ON openmettle.grant_assignments(scope_id,grantee_user_id,id);
CREATE INDEX grant_assignments_mapping_idx ON openmettle.grant_assignments(mapping_rule_id,grantee_user_id,id) WHERE mapping_rule_id IS NOT NULL;
CREATE TABLE openmettle.grant_changes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    assignment_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    source_kind text NOT NULL CHECK (source_kind IN ('direct','mapped')),
    mapping_rule_id uuid,
    mapping_revision bigint,
    actor_user_id uuid NOT NULL REFERENCES openmettle.users(id),
    request_key text NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
    decision text NOT NULL CHECK (decision IN ('grant','revoke')),
    cycle_id uuid,
    cycle_kind text GENERATED ALWAYS AS (CASE WHEN cycle_id IS NOT NULL THEN 'grant' END) STORED,
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) BETWEEN 1 AND 32768),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (decision <> 'grant' OR (cycle_id IS NOT NULL AND cycle_id=id)),
    CHECK ((source_kind='direct' AND mapping_rule_id IS NULL AND mapping_revision IS NULL)
        OR (source_kind='mapped' AND mapping_rule_id IS NOT NULL AND mapping_revision IS NOT NULL AND mapping_revision>0)),
    UNIQUE (assignment_id,revision),
    UNIQUE (scope_id,actor_user_id,request_key),
    UNIQUE (assignment_id,id,decision),
    FOREIGN KEY (scope_id,assignment_id,source_kind) REFERENCES openmettle.grant_assignments(scope_id,id,source_kind),
    FOREIGN KEY (assignment_id,mapping_rule_id) REFERENCES openmettle.grant_assignments(id,mapping_rule_id),
    FOREIGN KEY (mapping_rule_id,mapping_revision) REFERENCES openmettle.grant_mapping_revisions(rule_id,revision),
    FOREIGN KEY (assignment_id,cycle_id,cycle_kind) REFERENCES openmettle.grant_changes(assignment_id,id,decision)
);
CREATE INDEX grant_changes_scope_assignment_idx ON openmettle.grant_changes(scope_id,assignment_id,revision);

GRANT SELECT ON openmettle.grant_mapping_rules,openmettle.grant_mapping_revisions,
    openmettle.grant_assignments,openmettle.grant_changes TO openmettle_api,openmettle_worker;
GRANT INSERT (id,provider_config_id,issuer,created_by_user_id) ON openmettle.grant_mapping_rules TO openmettle_api;
GRANT UPDATE (last_revision) ON openmettle.grant_mapping_rules TO openmettle_api;
GRANT INSERT (rule_id,revision,actor_user_id,request_key,enabled,selector_kind,claim_name,claim_value,binding_format,binding_version,binding,request_identity,request_digest) ON openmettle.grant_mapping_revisions TO openmettle_api;
GRANT INSERT (scope_id,target_kind,project_id,conversation_id,artifact_id,grantee_user_id,assignment_format,assignment_version,assignment_key,source_kind,mapping_rule_id,created_by_user_id) ON openmettle.grant_assignments TO openmettle_api;
GRANT UPDATE (last_revision) ON openmettle.grant_assignments TO openmettle_api;
GRANT INSERT (id,scope_id,assignment_id,revision,source_kind,mapping_rule_id,mapping_revision,actor_user_id,request_key,decision,cycle_id,request_identity,request_digest) ON openmettle.grant_changes TO openmettle_api;
