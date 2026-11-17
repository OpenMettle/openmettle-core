-- V1-02 migration 1: database boundary, user identities and ownership scopes.
-- Released migrations are immutable. Runs once per release as openmettle_owner in one
-- transaction with search_path pg_catalog,pg_temp; see docs/adr/0003-schema-migrations.md.
-- Roles are provisioned outside migrations. openmettle-migrate checks identity, role
-- memberships, privileges and default privileges (src/boundaries.sql) before this runs; this
-- migration grants object privileges only and never creates, alters or grants cluster roles.

DO $$
BEGIN
    -- Dedicated database: only the application roles may connect; nobody else gets TEMP.
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO openmettle_api, openmettle_worker',
        current_database());
END
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA openmettle FROM PUBLIC;
GRANT USAGE ON SCHEMA openmettle TO openmettle_api, openmettle_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Internal account. Email and display names are not identity keys.
CREATE TABLE openmettle.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    CONSTRAINT users_disabled_after_created_check
        CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

-- Validated OIDC issuer/subject pairs, compared exactly. Linking is explicit: one internal
-- user may have several pairs, and each pair maps to exactly one user.
CREATE TABLE openmettle.user_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES openmettle.users (id),
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_identities_issuer_check
        CHECK (issuer <> '' AND octet_length(issuer) <= 2048),
    CONSTRAINT user_identities_subject_check
        CHECK (subject <> '' AND octet_length(subject) <= 255),
    CONSTRAINT user_identities_issuer_subject_key UNIQUE (issuer, subject)
);
CREATE INDEX user_identities_user_idx ON openmettle.user_identities (user_id);

-- Stable ownership and accounting scope: exactly one personal user or exactly one project.
-- A scope is an ownership key, not an access grant: project scope does not let members read
-- each other's private conversations.
CREATE TABLE openmettle.scopes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL,
    personal_user_id uuid REFERENCES openmettle.users (id),
    project_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scopes_kind_owner_check CHECK (
        (kind = 'personal' AND personal_user_id IS NOT NULL AND project_id IS NULL)
        OR (kind = 'project' AND project_id IS NOT NULL AND personal_user_id IS NULL)
    ),
    CONSTRAINT scopes_personal_user_key UNIQUE (personal_user_id),
    CONSTRAINT scopes_project_key UNIQUE (project_id),
    CONSTRAINT scopes_id_kind_key UNIQUE (id, kind),
    CONSTRAINT scopes_id_personal_user_key UNIQUE (id, personal_user_id),
    CONSTRAINT scopes_id_project_key UNIQUE (id, project_id)
);

CREATE TABLE openmettle.projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT projects_scope_key UNIQUE (scope_id),
    CONSTRAINT projects_id_scope_key UNIQUE (id, scope_id)
);
CREATE INDEX projects_created_by_idx ON openmettle.projects (created_by_user_id);

-- A project and its scope point at each other; both must be inserted in one transaction.
ALTER TABLE openmettle.scopes ADD CONSTRAINT scopes_project_fkey
    FOREIGN KEY (project_id, id) REFERENCES openmettle.projects (id, scope_id)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE openmettle.projects ADD CONSTRAINT projects_scope_fkey
    FOREIGN KEY (scope_id, id) REFERENCES openmettle.scopes (id, project_id)
    DEFERRABLE INITIALLY DEFERRED;

-- No DELETE, TRUNCATE, ownership-key UPDATE or DDL for application roles.
GRANT SELECT, INSERT ON openmettle.users, openmettle.user_identities,
    openmettle.scopes, openmettle.projects TO openmettle_api;
GRANT UPDATE (disabled_at) ON openmettle.users TO openmettle_api;
GRANT SELECT ON openmettle.users, openmettle.scopes, openmettle.projects TO openmettle_worker;
