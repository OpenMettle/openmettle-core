-- Read-only database boundary check (ADR 0003). openmettle-migrate runs it before SQLx creates
-- any schema or history object, and again after migrations. It returns one row per violation.
-- $1: the highest successfully applied migration version (0 before migration 1). Migration 1
-- revokes the PUBLIC database/public-schema defaults, which are tolerated only before that.
-- Each version's explicit grants are allowed only once that version is recorded as applied.
-- Principals are openmettle_api, openmettle_worker, every role that is directly or indirectly
-- a member of either (for example their login roles), and PUBLIC. They may hold only the
-- privileges in `contract`, CONNECT on the database and USAGE on schema openmettle.
WITH RECURSIVE
privilege_roles AS (
    SELECT oid FROM pg_roles WHERE rolname IN ('openmettle_api', 'openmettle_worker')
),
owner_role AS (
    SELECT oid FROM pg_roles WHERE rolname = 'openmettle_owner'
),
application (oid, base) AS (
    SELECT oid, oid FROM privilege_roles
    UNION
    SELECT m.member, a.base FROM pg_auth_members AS m JOIN application AS a ON m.roleid = a.oid
),
principals (oid) AS (
    SELECT oid FROM application
    UNION
    SELECT 0::oid
),
contract (relation, role, privilege) AS (
    VALUES
        ('users', 'openmettle_api', 'SELECT'),
        ('users', 'openmettle_api', 'INSERT'),
        ('user_identities', 'openmettle_api', 'SELECT'),
        ('user_identities', 'openmettle_api', 'INSERT'),
        ('scopes', 'openmettle_api', 'SELECT'),
        ('scopes', 'openmettle_api', 'INSERT'),
        ('projects', 'openmettle_api', 'SELECT'),
        ('projects', 'openmettle_api', 'INSERT'),
        ('conversations', 'openmettle_api', 'SELECT'),
        ('conversations', 'openmettle_api', 'INSERT'),
        ('messages', 'openmettle_api', 'SELECT'),
        ('messages', 'openmettle_api', 'INSERT'),
        ('users', 'openmettle_worker', 'SELECT'),
        ('scopes', 'openmettle_worker', 'SELECT'),
        ('projects', 'openmettle_worker', 'SELECT'),
        ('conversations', 'openmettle_worker', 'SELECT'),
        ('messages', 'openmettle_worker', 'SELECT'),
        ('messages', 'openmettle_worker', 'INSERT')
    UNION ALL
    SELECT * FROM (VALUES
        ('conversation_branches', 'openmettle_api', 'SELECT'),
        ('conversation_branches', 'openmettle_api', 'INSERT'),
        ('conversation_branches', 'openmettle_worker', 'SELECT'),
        ('runs', 'openmettle_api', 'SELECT'),
        ('runs', 'openmettle_worker', 'SELECT'),
        ('run_events', 'openmettle_api', 'SELECT'), ('run_events', 'openmettle_api', 'INSERT'),
        ('run_events', 'openmettle_worker', 'SELECT'), ('run_events', 'openmettle_worker', 'INSERT'),
        ('operations', 'openmettle_api', 'SELECT'),
        ('operations', 'openmettle_worker', 'SELECT')
    ) AS durable(relation, role, privilege) WHERE $1 >= 3
    UNION ALL
    SELECT relation, role, privilege FROM (VALUES
        ('storage_instance'), ('storage_accounts'), ('artifacts'), ('storage_reservations'),
        ('artifact_revisions')
    ) AS storage(relation),
    (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role),
    (VALUES ('SELECT')) AS p(privilege)
    WHERE $1 >= 4
    UNION ALL
    SELECT relation, role, 'SELECT' FROM (VALUES
        ('grant_mapping_rules'), ('grant_mapping_revisions'),
        ('grant_assignments'), ('grant_changes')
    ) AS g(relation), (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role)
    WHERE $1 >= 5
    UNION ALL
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('login_transactions'), ('login_nonce_reservations')
    ) AS login(relation) WHERE $1 >= 6
    UNION ALL
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('login_providers'), ('login_provider_revisions')
    ) AS authority(relation) WHERE $1 >= 7
    UNION ALL
    SELECT relation, 'openmettle_api', 'SELECT' FROM (VALUES
        ('local_identity_approvals'), ('local_sessions')
    ) AS sessions(relation) WHERE $1 >= 8
),
column_contract (relation, attribute, role, privilege) AS (
    VALUES ('users', 'disabled_at', 'openmettle_api', 'UPDATE')
    UNION ALL
    SELECT relation, attribute, 'openmettle_api', privilege FROM (VALUES
        ('login_providers','lock_guard','UPDATE'),
        ('users','session_generation','UPDATE'),
        ('login_transactions','session_issued','UPDATE'),
        ('local_identity_approvals','lock_guard','UPDATE'),
        ('local_sessions','revoked','UPDATE'),
        ('local_sessions','id','INSERT'), ('local_sessions','secret_hash','INSERT'),
        ('local_sessions','login_id','INSERT'), ('local_sessions','provider_id','INSERT'),
        ('local_sessions','identity_id','INSERT'), ('local_sessions','approval_id','INSERT'),
        ('local_sessions','user_id','INSERT'), ('local_sessions','issued_client','INSERT'), ('local_sessions','issued_epoch','INSERT'),
        ('local_sessions','issued_revision','INSERT'), ('local_sessions','provider_generation','INSERT'),
        ('local_sessions','approval_generation','INSERT'), ('local_sessions','user_generation','INSERT'),
        ('local_sessions','created_ms','INSERT'), ('local_sessions','expires_ms','INSERT')
    ) AS sessions(relation,attribute,privilege) WHERE $1 >= 8
    UNION ALL
    SELECT relation, attribute, 'openmettle_api', privilege FROM (VALUES
        ('login_nonce_reservations','key_id','INSERT'),
        ('login_nonce_reservations','nonce','INSERT'),
        ('login_transactions','id','INSERT'),
        ('login_transactions','binding','INSERT'),
        ('login_transactions','expires_ms','INSERT'),
        ('login_transactions','state_hash','INSERT'),
        ('login_transactions','nonce_hash','INSERT'),
        ('login_transactions','caller_hash','INSERT'),
        ('login_transactions','key_id','INSERT'),
        ('login_transactions','nonce','INSERT'),
        ('login_transactions','ciphertext','INSERT'),
        ('login_transactions','consumed','UPDATE'),
        ('login_transactions','ciphertext','UPDATE')
    ) AS login(relation,attribute,privilege) WHERE $1 >= 6
    UNION ALL
    SELECT * FROM (VALUES
        ('runs', 'id', 'openmettle_api', 'INSERT'),
        ('runs', 'scope_id', 'openmettle_api', 'INSERT'),
        ('runs', 'actor_user_id', 'openmettle_api', 'INSERT'),
        ('runs', 'conversation_id', 'openmettle_api', 'INSERT'),
        ('runs', 'branch_id', 'openmettle_api', 'INSERT'),
        ('runs', 'input_message_id', 'openmettle_api', 'INSERT'),
        ('runs', 'idempotency_key', 'openmettle_api', 'INSERT'),
        ('runs', 'snapshot_format', 'openmettle_api', 'INSERT'),
        ('runs', 'snapshot_version', 'openmettle_api', 'INSERT'),
        ('runs', 'input_snapshot', 'openmettle_api', 'INSERT'),
        ('runs', 'config_snapshot', 'openmettle_api', 'INSERT'),
        ('runs', 'request_identity', 'openmettle_api', 'INSERT'),
        ('runs', 'request_digest', 'openmettle_api', 'INSERT'),
        ('operations', 'id', 'openmettle_worker', 'INSERT'),
        ('operations', 'scope_id', 'openmettle_worker', 'INSERT'),
        ('operations', 'run_id', 'openmettle_worker', 'INSERT'),
        ('operations', 'logical_key', 'openmettle_worker', 'INSERT'),
        ('operations', 'target', 'openmettle_worker', 'INSERT'),
        ('operations', 'capability', 'openmettle_worker', 'INSERT'),
        ('operations', 'format', 'openmettle_worker', 'INSERT'),
        ('operations', 'format_version', 'openmettle_worker', 'INSERT'),
        ('operations', 'request', 'openmettle_worker', 'INSERT'),
        ('operations', 'request_identity', 'openmettle_worker', 'INSERT'),
        ('operations', 'request_digest', 'openmettle_worker', 'INSERT'),
        ('runs', 'last_event_sequence', 'openmettle_api', 'UPDATE'),
        ('runs', 'last_event_sequence', 'openmettle_worker', 'UPDATE'),
        ('operations', 'outcome', 'openmettle_worker', 'UPDATE'),
        ('operations', 'revision', 'openmettle_worker', 'UPDATE'),
        ('operations', 'downstream_handle', 'openmettle_worker', 'UPDATE'),
        ('operations', 'observation_format', 'openmettle_worker', 'UPDATE'),
        ('operations', 'observation_version', 'openmettle_worker', 'UPDATE'),
        ('operations', 'evidence', 'openmettle_worker', 'UPDATE')
    ) AS durable(relation, attribute, role, privilege) WHERE $1 >= 3
    UNION ALL
    SELECT relation, attribute, role, privilege FROM (VALUES
        ('storage_instance', 'active_bytes', 'UPDATE'),
        ('storage_instance', 'retained_bytes', 'UPDATE'),
        ('storage_instance', 'reserved_bytes', 'UPDATE'),
        ('storage_accounts', 'active_bytes', 'UPDATE'),
        ('storage_accounts', 'retained_bytes', 'UPDATE'),
        ('storage_accounts', 'reserved_bytes', 'UPDATE'),
        ('storage_accounts', 'scope_id', 'INSERT'),
        ('artifacts', 'id', 'INSERT'),
        ('artifacts', 'scope_id', 'INSERT'),
        ('artifacts', 'scope_kind', 'INSERT'),
        ('artifacts', 'owner_user_id', 'INSERT'),
        ('artifacts', 'last_revision', 'UPDATE'),
        ('storage_reservations', 'id', 'INSERT'),
        ('storage_reservations', 'scope_id', 'INSERT'),
        ('storage_reservations', 'actor_user_id', 'INSERT'),
        ('storage_reservations', 'idempotency_key', 'INSERT'),
        ('storage_reservations', 'artifact_id', 'INSERT'),
        ('storage_reservations', 'max_bytes', 'INSERT'),
        ('storage_reservations', 'run_id', 'INSERT'),
        ('storage_reservations', 'operation_id', 'INSERT'),
        ('storage_reservations', 'request_identity', 'INSERT'),
        ('storage_reservations', 'request_digest', 'INSERT'),
        ('storage_reservations', 'state', 'UPDATE'),
        ('storage_reservations', 'settled_bytes', 'UPDATE'),
        ('storage_reservations', 'closed_at', 'UPDATE'),
        ('artifact_revisions', 'id', 'INSERT'),
        ('artifact_revisions', 'scope_id', 'INSERT'),
        ('artifact_revisions', 'artifact_id', 'INSERT'),
        ('artifact_revisions', 'revision', 'INSERT'),
        ('artifact_revisions', 'reservation_id', 'INSERT'),
        ('artifact_revisions', 'size_bytes', 'INSERT'),
        ('artifact_revisions', 'content_digest', 'INSERT'),
        ('artifact_revisions', 'media_type', 'INSERT'),
        ('artifact_revisions', 'created_by_user_id', 'INSERT'),
        ('artifact_revisions', 'state', 'UPDATE')
    ) AS storage(relation, attribute, privilege),
    (VALUES ('openmettle_api'), ('openmettle_worker')) AS r(role)
    WHERE $1 >= 4
    UNION ALL
    SELECT * FROM (VALUES
        ('artifact_revisions', 'retained_at', 'openmettle_api', 'UPDATE'),
        ('artifact_revisions', 'purge_after', 'openmettle_api', 'UPDATE'),
        ('artifact_revisions', 'purging_at', 'openmettle_worker', 'UPDATE'),
        ('artifact_revisions', 'purged_at', 'openmettle_worker', 'UPDATE')
    ) AS retention(relation, attribute, role, privilege) WHERE $1 >= 4
    UNION ALL
    SELECT * FROM (VALUES
        ('grant_mapping_rules', 'id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'provider_config_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'issuer', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'created_by_user_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_rules', 'last_revision', 'openmettle_api', 'UPDATE'),
        ('grant_mapping_revisions', 'rule_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'revision', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'actor_user_id', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'request_key', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'enabled', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'selector_kind', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'claim_name', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'claim_value', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'binding_format', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'binding_version', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'binding', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'request_identity', 'openmettle_api', 'INSERT'),
        ('grant_mapping_revisions', 'request_digest', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'scope_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'target_kind', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'project_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'conversation_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'artifact_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'grantee_user_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'assignment_format', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'assignment_version', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'assignment_key', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'source_kind', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'mapping_rule_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'created_by_user_id', 'openmettle_api', 'INSERT'),
        ('grant_assignments', 'last_revision', 'openmettle_api', 'UPDATE'),
        ('grant_changes', 'id', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'scope_id', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'assignment_id', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'revision', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'source_kind', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'mapping_rule_id', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'mapping_revision', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'actor_user_id', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'request_key', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'decision', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'cycle_id', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'request_identity', 'openmettle_api', 'INSERT'),
        ('grant_changes', 'request_digest', 'openmettle_api', 'INSERT')
    ) AS grants(relation, attribute, role, privilege) WHERE $1 >= 5
),
user_schemas AS (
    SELECT oid, nspname, nspowner, nspacl FROM pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema')
      AND nspname NOT LIKE 'pg\_toast%'
      AND nspname NOT LIKE 'pg\_temp\_%'
),
grants (target, kind, schema_name, object_name, column_name, grantee, privilege, is_grantable) AS (
    SELECT 'the database', 'database', NULL::name, NULL::name, NULL::name,
           a.grantee, a.privilege_type, a.is_grantable
    FROM pg_database AS d,
         aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) AS a
    WHERE d.datname = current_database()
    UNION ALL
    SELECT 'schema ' || s.nspname, 'schema', s.nspname, NULL, NULL,
           a.grantee, a.privilege_type, a.is_grantable
    FROM user_schemas AS s,
         aclexplode(coalesce(s.nspacl, acldefault('n', s.nspowner))) AS a
    UNION ALL
    SELECT s.nspname || '.' || c.relname, 'relation', s.nspname, c.relname, NULL,
           a.grantee, a.privilege_type, a.is_grantable
    FROM pg_class AS c
    JOIN user_schemas AS s ON s.oid = c.relnamespace,
         aclexplode(coalesce(c.relacl, acldefault(
             CASE c.relkind WHEN 'S' THEN 's'::"char" ELSE 'r'::"char" END, c.relowner))) AS a
    UNION ALL
    SELECT s.nspname || '.' || c.relname || '.' || t.attname, 'column', s.nspname, c.relname,
           t.attname, a.grantee, a.privilege_type, a.is_grantable
    FROM pg_attribute AS t
    JOIN pg_class AS c ON c.oid = t.attrelid
    JOIN user_schemas AS s ON s.oid = c.relnamespace,
         aclexplode(t.attacl) AS a
    WHERE t.attnum > 0 AND NOT t.attisdropped AND t.attacl IS NOT NULL
    UNION ALL
    SELECT 'function ' || p.oid::regprocedure::text, 'function', s.nspname, p.proname, NULL,
           a.grantee, a.privilege_type, a.is_grantable
    FROM pg_proc AS p
    JOIN user_schemas AS s ON s.oid = p.pronamespace,
         aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) AS a
    WHERE s.nspname = 'openmettle'
),
violations (violation) AS (
    -- Identity: SQLx must not bootstrap anything under another login or database owner.
    SELECT format('migrations must log in as openmettle_owner, not %s', session_user)
    WHERE session_user <> 'openmettle_owner' OR current_user <> 'openmettle_owner'
    UNION ALL
    SELECT 'the database must be owned by openmettle_owner'
    FROM pg_database
    WHERE datname = current_database() AND pg_get_userbyid(datdba) <> 'openmettle_owner'
    UNION ALL
    SELECT format('role %s is missing', r)
    FROM unnest(ARRAY['openmettle_owner', 'openmettle_api', 'openmettle_worker']) AS r
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r)
    UNION ALL
    -- Role attributes of the owner and every application principal.
    SELECT format('role %s must not be superuser or hold CREATEROLE, CREATEDB, REPLICATION '
                  'or BYPASSRLS', rolname)
    FROM pg_roles
    WHERE (oid IN (SELECT oid FROM application) OR oid IN (SELECT oid FROM owner_role))
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    UNION ALL
    -- Memberships: any membership, inherited or only assumable with SET ROLE, can carry
    -- privileges (for example pg_write_all_data) outside the contract.
    SELECT format('role %s must not be a member of %s',
                  pg_get_userbyid(m.member), pg_get_userbyid(m.roleid))
    FROM pg_auth_members AS m
    WHERE m.member IN (SELECT oid FROM privilege_roles UNION ALL SELECT oid FROM owner_role)
    UNION ALL
    SELECT format('role %s, a member of an application role, must not be a member of %s',
                  pg_get_userbyid(m.member), pg_get_userbyid(m.roleid))
    FROM pg_auth_members AS m
    WHERE m.member IN (SELECT oid FROM application)
      AND m.member NOT IN (SELECT oid FROM privilege_roles)
      AND m.roleid NOT IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('role %s has both API and worker privileges', pg_get_userbyid(oid))
    FROM application
    GROUP BY oid
    HAVING count(DISTINCT base) > 1
    UNION ALL
    -- Object privileges held by principals outside the contract.
    SELECT format('%s has %s on %s',
                  CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END,
                  g.privilege, g.target)
    FROM grants AS g
    WHERE g.grantee IN (SELECT oid FROM principals)
      AND NOT (g.kind = 'database' AND g.grantee <> 0 AND g.privilege = 'CONNECT')
      AND NOT (g.kind = 'database' AND g.grantee = 0 AND $1 < 1
               AND g.privilege IN ('CONNECT', 'TEMPORARY'))
      AND NOT (g.kind = 'schema' AND g.schema_name = 'openmettle' AND g.privilege = 'USAGE'
               AND g.grantee IN (SELECT oid FROM privilege_roles))
      AND NOT (g.kind = 'schema' AND g.schema_name = 'public' AND g.grantee = 0 AND $1 < 1
               AND g.privilege = 'USAGE')
      AND NOT (g.kind = 'relation' AND g.schema_name = 'openmettle'
               AND (g.object_name::text, pg_get_userbyid(g.grantee)::text, g.privilege)
                   IN (SELECT relation, role, privilege FROM contract))
      AND NOT (g.kind = 'column' AND g.schema_name = 'openmettle'
               AND (g.object_name::text, g.column_name::text,
                    pg_get_userbyid(g.grantee)::text, g.privilege)
                   IN (SELECT relation, attribute, role, privilege FROM column_contract))
    UNION ALL
    -- Even permitted privileges must not be delegable to another application principal.
    SELECT format('%s has grant option for %s on %s',
                  CASE g.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END,
                  g.privilege, g.target)
    FROM grants AS g
    WHERE g.grantee IN (SELECT oid FROM principals) AND g.is_grantable
    UNION ALL
    -- Default privileges would grant future migration objects outside the contract.
    SELECT format('default privileges of openmettle_owner%s grant %s on new %s to %s',
                  coalesce(' in schema ' || s.nspname, ''), a.privilege_type,
                  CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences'
                      WHEN 'f' THEN 'functions' WHEN 'T' THEN 'types'
                      WHEN 'n' THEN 'schemas' ELSE 'objects' END,
                  CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END)
    FROM pg_default_acl AS d
    LEFT JOIN pg_namespace AS s ON s.oid = d.defaclnamespace,
         aclexplode(d.defaclacl) AS a
    WHERE d.defaclrole IN (SELECT oid FROM owner_role)
      AND a.grantee IN (SELECT oid FROM principals)
    UNION ALL
    -- Ownership grants DDL; principals own nothing and the owner owns schema openmettle.
    SELECT format('%s owns schema %s', pg_get_userbyid(nspowner), nspname)
    FROM user_schemas
    WHERE nspowner IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('%s owns %s.%s', pg_get_userbyid(c.relowner), s.nspname, c.relname)
    FROM pg_class AS c
    JOIN pg_namespace AS s ON s.oid = c.relnamespace
    WHERE c.relowner IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('%s owns function %s', pg_get_userbyid(proowner), oid::regprocedure)
    FROM pg_proc
    WHERE proowner IN (SELECT oid FROM application)
    UNION ALL
    SELECT format('%s owns type %s', pg_get_userbyid(typowner), oid::regtype)
    FROM pg_type
    WHERE typowner IN (SELECT oid FROM application) AND typrelid = 0
    UNION ALL
    SELECT 'schema openmettle must be owned by openmettle_owner'
    FROM pg_namespace
    WHERE nspname = 'openmettle' AND pg_get_userbyid(nspowner) <> 'openmettle_owner'
    UNION ALL
    SELECT format('openmettle.%s must be owned by openmettle_owner', c.relname)
    FROM pg_class AS c
    JOIN pg_namespace AS s ON s.oid = c.relnamespace
    WHERE s.nspname = 'openmettle' AND pg_get_userbyid(c.relowner) <> 'openmettle_owner'
)
SELECT DISTINCT violation FROM violations ORDER BY violation LIMIT 20
