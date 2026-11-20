-- AUTHSEC-01 migration 18 (ADR 0030): session issuance moves from openmettle_api to the
-- separately provisioned openmettle_issuance role, so SQL limited to openmettle_api can no
-- longer insert a session, mark a login issued, record membership evidence, create a native
-- handoff or redeem a home invitation. Roles are provisioned outside migrations: this
-- migration refuses, and rolls back, when openmettle_issuance does not exist. Every existing
-- row is kept; existing sessions stay valid.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openmettle_issuance') THEN
        RAISE EXCEPTION 'role openmettle_issuance is missing; provision it before migration 18';
    END IF;
    EXECUTE pg_catalog.format('GRANT CONNECT ON DATABASE %I TO openmettle_issuance',
        pg_catalog.current_database());
END
$$;
GRANT USAGE ON SCHEMA openmettle TO openmettle_issuance;

-- Inert row-lock guards (ADR 0013): PostgreSQL requires UPDATE on some column for a locking
-- SELECT, and the issuance role never holds UPDATE on a column it does not write.
ALTER TABLE openmettle.users
    ADD COLUMN lock_guard boolean NOT NULL DEFAULT false
        CONSTRAINT users_lock_guard_check CHECK (lock_guard = false);
ALTER TABLE openmettle.grant_mapping_rules
    ADD COLUMN lock_guard boolean NOT NULL DEFAULT false
        CONSTRAINT grant_mapping_rules_lock_guard_check CHECK (lock_guard = false);

-- Issuance-only writes leave the API role.
REVOKE INSERT (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
    issued_client, issued_epoch, issued_revision, provider_generation, approval_generation,
    user_generation, created_ms, expires_ms)
    ON openmettle.local_sessions FROM openmettle_api;
REVOKE UPDATE (session_issued) ON openmettle.login_transactions FROM openmettle_api;
REVOKE UPDATE (issued_ms, expires_ms, observation, epoch, approval_generation, user_generation)
    ON openmettle.membership_observations FROM openmettle_api;
REVOKE INSERT (session_id, code_hash, registration, audience, challenge, sealed, expires_ms)
    ON openmettle.native_handoffs FROM openmettle_api;
REVOKE EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)
    FROM openmettle_api;

-- The same writes, now held only by the issuance role.
GRANT INSERT (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
    issued_client, issued_epoch, issued_revision, provider_generation, approval_generation,
    user_generation, created_ms, expires_ms)
    ON openmettle.local_sessions TO openmettle_issuance;
GRANT UPDATE (session_issued) ON openmettle.login_transactions TO openmettle_issuance;
GRANT UPDATE (issued_ms, expires_ms, observation, epoch, approval_generation, user_generation)
    ON openmettle.membership_observations TO openmettle_issuance;
GRANT INSERT (session_id, code_hash, registration, audience, challenge, sealed, expires_ms)
    ON openmettle.native_handoffs TO openmettle_issuance;
GRANT EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)
    TO openmettle_issuance;

-- Reads and row locks of the issuance transaction, shared with the API role.
GRANT SELECT ON openmettle.login_transactions, openmettle.login_providers,
    openmettle.login_provider_revisions, openmettle.user_identities, openmettle.users,
    openmettle.scopes, openmettle.local_identity_approvals, openmettle.local_sessions,
    openmettle.membership_observations, openmettle.grant_mapping_rules,
    openmettle.grant_mapping_revisions, openmettle.grant_assignments, openmettle.grant_changes
    TO openmettle_issuance;
GRANT UPDATE (lock_guard) ON openmettle.login_providers, openmettle.local_identity_approvals,
    openmettle.users, openmettle.grant_mapping_rules TO openmettle_issuance;

-- The mapped-membership grant writer (grants::change_grant), shared with the API role.
GRANT INSERT (scope_id, target_kind, project_id, conversation_id, artifact_id, grantee_kind,
    grantee_user_id, grantee_local_group_id, grantee_oidc_group_id, assignment_format,
    assignment_version, assignment_key, source_kind, mapping_rule_id, created_by_user_id)
    ON openmettle.grant_assignments TO openmettle_issuance;
GRANT UPDATE (last_revision) ON openmettle.grant_assignments TO openmettle_issuance;
GRANT INSERT (id, scope_id, assignment_id, revision, source_kind, mapping_rule_id,
    mapping_revision, actor_user_id, request_key, decision, cycle_id, request_identity,
    request_digest)
    ON openmettle.grant_changes TO openmettle_issuance;
