-- V1-05 migration 16 (ADR 0027 PR4a): group and project-wide grantees on ADR 0006 assignments,
-- and an inert project row lock for the API. Additive only. Every version 5 to 15 row is a
-- user grantee and keeps its values: grantee_kind defaults to 'user' and the new columns are
-- NULL. Writers that name only grantee_user_id keep working unchanged.

ALTER TABLE openmettle.grant_assignments
    ADD COLUMN grantee_kind text NOT NULL DEFAULT 'user'
        CONSTRAINT grant_assignments_grantee_kind_check
        CHECK (grantee_kind IN ('user', 'local_group', 'oidc_group', 'project')),
    ADD COLUMN grantee_local_group_id uuid REFERENCES openmettle.local_groups (id),
    -- An OIDC group is the exact claim value (ADR 0021), bounded like a mapping claim value.
    ADD COLUMN grantee_oidc_group_id text
        CONSTRAINT grant_assignments_grantee_oidc_group_id_check
        CHECK (octet_length(grantee_oidc_group_id) BETWEEN 1 AND 1024
            AND grantee_oidc_group_id COLLATE "C" !~ '[[:cntrl:]]'),
    ALTER COLUMN grantee_user_id DROP NOT NULL;

-- Exactly the column of the grantee kind is set. A project-wide grantee names no column.
ALTER TABLE openmettle.grant_assignments
    ADD CONSTRAINT grant_assignments_grantee_check CHECK (
        (grantee_kind = 'user' AND grantee_user_id IS NOT NULL
            AND grantee_local_group_id IS NULL AND grantee_oidc_group_id IS NULL)
        OR (grantee_kind = 'local_group' AND grantee_local_group_id IS NOT NULL
            AND grantee_user_id IS NULL AND grantee_oidc_group_id IS NULL)
        OR (grantee_kind = 'oidc_group' AND grantee_oidc_group_id IS NOT NULL
            AND grantee_user_id IS NULL AND grantee_local_group_id IS NULL)
        OR (grantee_kind = 'project' AND grantee_user_id IS NULL
            AND grantee_local_group_id IS NULL AND grantee_oidc_group_id IS NULL)),
    -- A project-wide share applies to a resource, never to the project itself.
    ADD CONSTRAINT grant_assignments_project_grantee_target_check
        CHECK (grantee_kind <> 'project' OR target_kind IN ('conversation', 'artifact'));

-- Replace the migration 5 natural key, whose generated name is not part of any contract. The
-- exact column list identifies it; STRICT fails the migration unless exactly one matches.
DO $$
DECLARE
    old_key name;
BEGIN
    SELECT c.conname INTO STRICT old_key
      FROM pg_constraint AS c
     WHERE c.conrelid = 'openmettle.grant_assignments'::regclass
       AND c.contype = 'u'
       AND c.conkey = (
           SELECT array_agg(a.attnum ORDER BY k.ord)
             FROM unnest(ARRAY['scope_id', 'target_kind', 'target_id', 'grantee_user_id',
                               'assignment_format', 'assignment_version', 'assignment_key',
                               'mapping_rule_id']) WITH ORDINALITY AS k(name, ord)
             JOIN pg_attribute AS a
               ON a.attrelid = c.conrelid AND a.attname = k.name AND NOT a.attisdropped);
    EXECUTE format('ALTER TABLE openmettle.grant_assignments DROP CONSTRAINT %I', old_key);
END
$$;
ALTER TABLE openmettle.grant_assignments
    ADD CONSTRAINT grant_assignments_unique_key UNIQUE NULLS NOT DISTINCT
        (scope_id, target_kind, target_id, grantee_kind, grantee_user_id, grantee_local_group_id,
         grantee_oidc_group_id, assignment_format, assignment_version, assignment_key,
         mapping_rule_id);
CREATE INDEX grant_assignments_local_group_idx
    ON openmettle.grant_assignments (grantee_local_group_id, scope_id, id)
    WHERE grantee_local_group_id IS NOT NULL;
CREATE INDEX grant_assignments_oidc_group_idx
    ON openmettle.grant_assignments (grantee_oidc_group_id, scope_id, id)
    WHERE grantee_oidc_group_id IS NOT NULL;

-- Project membership and share changes lock the project row FOR NO KEY UPDATE, which needs an
-- UPDATE privilege. The API can take the lock only through this inert guard column (ADR 0008).
ALTER TABLE openmettle.projects
    ADD COLUMN lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false);

GRANT INSERT (grantee_kind, grantee_local_group_id, grantee_oidc_group_id)
    ON openmettle.grant_assignments TO openmettle_api;
GRANT UPDATE (lock_guard) ON openmettle.projects TO openmettle_api;
