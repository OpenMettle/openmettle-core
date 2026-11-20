use super::*;

const CREATE: &str = include_str!("../../docs/operator/home-invitation-create.psql");
const WITHDRAW: &str = include_str!("../../docs/operator/home-invitation-withdraw.psql");
/// Invitations are migration 12 and their one-time codes migration 13 (ADR 0022).
const INVITATIONS: usize = 12;
const PROVIDER: &str = "00000000-0000-0000-0000-0000000000c1";
const INVITATION: &str = "00000000-0000-0000-0000-0000000000c2";
const OPERATOR: &str = "00000000-0000-0000-0000-0000000000c3";
const WITHDRAWN: &str = "00000000-0000-0000-0000-0000000000c4";
const ISSUER: &str = "https://Invitation.example.test/Realm";
/// Deterministic absolute cutoffs (2100-01-01), independent of the test clock. The table
/// accepts them; the create command caps its window at seven days.
const FUTURE: &str = "4102444800000";
const LATER: &str = "4102444800001";
const SEARCH_PATH: &str = "search_path=pg_catalog, pg_temp";
/// The redemption function of schema 12, without a code, and of schema 13, with one.
const CODELESS: &str = "openmettle.redeem_home_invitation(uuid,text,text,text,bigint)";
const CODED: &str = "openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)";
const GATE: &str = "openmettle.check_home_redemption()";
/// A ten-minute redemption window from primary time, set before the create command runs.
const WINDOW: &str = "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 600000 AS redeem_before_ms, floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 900000 AS approval_until_ms \\gset\n";

type Contract = (String, String, bool, Vec<String>, Vec<String>);
async fn function_contract(owner: &mut PgConnection) -> Vec<Contract> {
    sqlx::query_as(
        "SELECT p.oid::regprocedure::text, pg_get_userbyid(p.proowner)::text, p.prosecdef,
                coalesce(p.proconfig, '{}')::text[],
                ARRAY(SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END
                             || ' ' || a.privilege_type || ' by ' || pg_get_userbyid(a.grantor)
                             || CASE WHEN a.is_grantable THEN ' grantable' ELSE '' END
                        FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a ORDER BY 1)
           FROM pg_proc p
          WHERE p.pronamespace = 'openmettle'::regnamespace
            AND p.proname IN ('redeem_home_invitation', 'check_home_redemption')
          ORDER BY 1",
    )
    .fetch_all(owner)
    .await
    .unwrap()
}
/// Owner, security mode, pinned search path and the complete effective ACL of both functions.
fn contract(redemption: &str) -> Vec<Contract> {
    let owned = |name: &str, definer: bool, acl: &[&str]| {
        (
            name.to_owned(),
            OWNER.to_owned(),
            definer,
            vec![SEARCH_PATH.to_owned()],
            acl.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(),
        )
    };
    vec![
        owned(
            GATE,
            false,
            &["openmettle_owner EXECUTE by openmettle_owner"],
        ),
        owned(
            redemption,
            true,
            &[
                "openmettle_api EXECUTE by openmettle_owner",
                "openmettle_owner EXECUTE by openmettle_owner",
            ],
        ),
    ]
}
/// The other signature, owned by the owner and granted to the API role alone.
async fn stub(owner: &mut PgConnection, signature: &str) {
    for sql in [
        format!("CREATE FUNCTION {signature} RETURNS int LANGUAGE sql AS 'SELECT 1'"),
        format!("REVOKE ALL ON FUNCTION {signature} FROM PUBLIC"),
        format!("GRANT EXECUTE ON FUNCTION {signature} TO openmettle_api"),
    ] {
        owner.execute(AssertSqlSafe(sql)).await.unwrap();
    }
}
async fn provider(owner: &mut PgConnection) -> i64 {
    sqlx::query("INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason) VALUES ($1::uuid, $2, 'synthetic', 'fixture-owner', 'synthetic provider')")
        .bind(PROVIDER).bind(ISSUER).execute(&mut *owner).await.unwrap();
    sqlx::query_scalar("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, 'v1') RETURNING epoch")
        .bind(PROVIDER).fetch_one(owner).await.unwrap()
}

// Starts from the real eleven migrations, including membership. Authentic v11 and v12
// release-binary qualification with populated rows is populated_upgrade in grants.rs.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn upgrades_preserve_state_and_allow_exactly_one_redemption_signature_per_version() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    let (v11, v12) = (&MIGRATIONS[..INVITATIONS - 1], &MIGRATIONS[..INVITATIONS]);
    migrate::apply(&settings, v11).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("INSERT INTO openmettle.users DEFAULT VALUES")
        .await
        .unwrap();
    let previous = first_approval::everything(&db).await;

    // Schema 12: only the code-less function, and the boundary check refuses the other one.
    migrate::apply(&settings, v12).await.unwrap();
    assert_eq!(function_contract(&mut owner).await, contract(CODELESS));
    stub(&mut owner, CODED).await;
    let violation = |signature: &str| format!("openmettle_api has EXECUTE on function {signature}");
    refused_with(&settings, v12, &violation(CODED)).await;
    owner
        .execute(AssertSqlSafe(format!("DROP FUNCTION {CODED}")))
        .await
        .unwrap();
    migrate::apply(&settings, v12).await.unwrap();

    // Schema 13 and later: the code-less function is gone and only the function with a
    // code remains. Migration 14 replaces its body and keeps this contract (see below).
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(MIGRATIONS[INVITATIONS].version, 13);
    let current = first_approval::everything(&db).await;
    for (table, rows) in previous {
        if table != "_sqlx_migrations" {
            assert_eq!(rows, current[&table], "{table}");
        }
    }
    assert!(current["home_invitations"].is_empty());
    assert_eq!(function_contract(&mut owner).await, contract(CODED));
    let trigger: (bool, bool, bool, String) = sqlx::query_as(
        "SELECT tgconstraint <> 0, tgdeferrable, tginitdeferred, tgfoid::regprocedure::text
           FROM pg_trigger WHERE tgrelid = 'openmettle.home_invitations'::regclass
            AND tgname = 'home_redemption_session'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(trigger, (true, true, true, GATE.into()));
    for role in [API, WORKER, CAPPED, "public"] {
        let privileges: (bool,bool,bool,bool) = sqlx::query_as("SELECT
            has_function_privilege($1, 'openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)', 'EXECUTE'),
            has_function_privilege($1, 'openmettle.check_home_redemption()', 'EXECUTE'),
            has_table_privilege($1, 'openmettle.home_invitations', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
            OR has_any_column_privilege($1,'openmettle.home_invitations','SELECT,INSERT,UPDATE,REFERENCES'),
            has_any_column_privilege($1, 'openmettle.local_identity_approvals', 'INSERT')")
            .bind(role).fetch_one(&mut owner).await.unwrap();
        assert_eq!(
            privileges,
            (role == API || role == CAPPED, false, false, false),
            "{role}"
        );
    }
    // The API role can neither read the stored hash nor reach a code-less redemption.
    let mut api = connect(&db.0, API).await;
    expect_state(
        &mut api,
        "SELECT code_hash FROM openmettle.home_invitations",
        "42501",
    )
    .await;
    expect_state(
        &mut api,
        "SELECT * FROM openmettle.redeem_home_invitation('00000000-0000-0000-0000-0000000000c1'::uuid, 'i'::text, 's'::text, 'l'::text, 1::bigint)",
        "42883",
    )
    .await;
    for (grant, revoke) in [
        (
            "GRANT SELECT ON openmettle.home_invitations TO openmettle_api".to_owned(),
            "REVOKE SELECT ON openmettle.home_invitations FROM openmettle_api".to_owned(),
        ),
        (
            "GRANT SELECT (code_hash) ON openmettle.home_invitations TO openmettle_api".to_owned(),
            "REVOKE SELECT (code_hash) ON openmettle.home_invitations FROM openmettle_api"
                .to_owned(),
        ),
        (
            format!("GRANT EXECUTE ON FUNCTION {CODED} TO openmettle_worker"),
            format!("REVOKE EXECUTE ON FUNCTION {CODED} FROM openmettle_worker"),
        ),
        (
            format!("GRANT EXECUTE ON FUNCTION {CODED} TO PUBLIC"),
            format!("REVOKE EXECUTE ON FUNCTION {CODED} FROM PUBLIC"),
        ),
        (
            format!("GRANT EXECUTE ON FUNCTION {GATE} TO PUBLIC"),
            format!("REVOKE EXECUTE ON FUNCTION {GATE} FROM PUBLIC"),
        ),
    ] {
        owner.execute(AssertSqlSafe(grant.clone())).await.unwrap();
        assert!(
            matches!(
                migrate::apply(&settings, MIGRATIONS).await,
                Err(Failure::Refused(_))
            ),
            "{grant}"
        );
        owner.execute(AssertSqlSafe(revoke)).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    // A code-less function granted to the API role again is the one violation reported.
    stub(&mut owner, CODELESS).await;
    refused_with(&settings, MIGRATIONS, &violation(CODELESS)).await;
}

// Migration 14 (ADR 0023) replaces the redemption function in place, so that a login started
// by a native sign-in can redeem, and adds the native delivery table. The function keeps its
// signature, owner, security mode, search path and complete ACL. The new table's grants are
// outside the contract until version 14 is recorded, and then exactly the contract.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_14_keeps_the_redemption_contract_and_gates_the_native_grants() {
    const NATIVE: usize = 13;
    const TABLE: &str = "openmettle.native_handoffs";
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    let v13 = &MIGRATIONS[..NATIVE];
    migrate::apply(&settings, v13).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    assert_eq!(function_contract(&mut owner).await, contract(CODED));
    let body = "SELECT position('openmettle/native-managed-login/1' IN prosrc) > 0,
                       position('openmettle/managed-login/2' IN prosrc) > 0
                  FROM pg_proc WHERE oid = 'openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)'::regprocedure";
    let layouts: (bool, bool) = sqlx::query_as(body).fetch_one(&mut owner).await.unwrap();
    assert_eq!(
        layouts,
        (false, true),
        "schema 13 admits the managed layout only"
    );

    // A grant on the new relation before version 14 is recorded is the one violation.
    owner
        .execute(AssertSqlSafe(format!(
            "CREATE TABLE {TABLE}(sealed bytea); GRANT SELECT ON {TABLE} TO openmettle_api"
        )))
        .await
        .unwrap();
    refused_with(
        &settings,
        v13,
        &format!("openmettle_api has SELECT on {TABLE}"),
    )
    .await;
    owner
        .execute(AssertSqlSafe(format!("DROP TABLE {TABLE}")))
        .await
        .unwrap();

    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(MIGRATIONS[NATIVE].version, 14);
    assert_eq!(db.history().await, all_versions());
    assert_eq!(function_contract(&mut owner).await, contract(CODED));
    let layouts: (bool, bool) = sqlx::query_as(body).fetch_one(&mut owner).await.unwrap();
    assert_eq!(layouts, (true, true), "schema 14 admits both layouts");

    // The API role reads rows, inserts whole rows and clears one column. Nobody else, and
    // nothing more: no other update, no delete and no table-wide write.
    for role in [API, WORKER, CAPPED, "public"] {
        let privileges: (bool, bool, bool, bool, bool) = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT has_table_privilege($1, '{TABLE}', 'SELECT'),
                (SELECT bool_and(has_column_privilege($1, '{TABLE}', a.attname::text, 'INSERT'))
                   FROM pg_attribute a WHERE a.attrelid = '{TABLE}'::regclass
                    AND a.attnum > 0 AND NOT a.attisdropped),
                has_column_privilege($1, '{TABLE}', 'sealed', 'UPDATE'),
                (SELECT bool_or(has_column_privilege($1, '{TABLE}', a.attname::text, 'UPDATE'))
                   FROM pg_attribute a WHERE a.attrelid = '{TABLE}'::regclass
                    AND a.attnum > 0 AND NOT a.attisdropped AND a.attname <> 'sealed'),
                has_table_privilege($1, '{TABLE}', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')"
        )))
        .bind(role)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let api = role == API || role == CAPPED;
        assert_eq!(privileges, (api, api, api, false, false), "{role}");
    }
    let columns: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT attname::text FROM pg_attribute WHERE attrelid = '{TABLE}'::regclass
            AND attnum > 0 AND NOT attisdropped ORDER BY attnum"
    )))
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        columns,
        [
            "session_id",
            "code_hash",
            "registration",
            "audience",
            "challenge",
            "sealed",
            "expires_ms"
        ]
    );
    for (grant, revoke, violation) in [
        (
            format!("GRANT UPDATE (expires_ms) ON {TABLE} TO openmettle_api"),
            format!("REVOKE UPDATE (expires_ms) ON {TABLE} FROM openmettle_api"),
            format!("openmettle_api has UPDATE on {TABLE}.expires_ms"),
        ),
        (
            format!("GRANT DELETE ON {TABLE} TO openmettle_api"),
            format!("REVOKE DELETE ON {TABLE} FROM openmettle_api"),
            format!("openmettle_api has DELETE on {TABLE}"),
        ),
        (
            format!("GRANT SELECT ON {TABLE} TO openmettle_worker"),
            format!("REVOKE SELECT ON {TABLE} FROM openmettle_worker"),
            format!("openmettle_worker has SELECT on {TABLE}"),
        ),
    ] {
        owner.execute(AssertSqlSafe(grant)).await.unwrap();
        refused_with(&settings, MIGRATIONS, &violation).await;
        owner.execute(AssertSqlSafe(revoke)).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
}

// Schema 12 wrote invitations without a code. A pending one could never be redeemed on schema
// 13, so the migration refuses and leaves schema 12 intact until the operator withdraws it.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn pending_invitation_without_a_code_blocks_migration_13_until_withdrawn() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, &MIGRATIONS[..INVITATIONS])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    let epoch = provider(&mut owner).await;
    // One pending decision and one already withdrawn, as the schema-12 commands left them.
    for (id, subject, withdrawn) in [
        (INVITATION, "synthetic-pending", false),
        (WITHDRAWN, "synthetic-withdrawn", true),
    ] {
        sqlx::query("INSERT INTO openmettle.home_invitations (id, provider_id, provider_generation, provider_epoch, issuer, subject, redeem_before_ms, approval_until_ms, created_by, withdrawn_by, withdrawn_at)
            VALUES ($1::uuid, $2::uuid, 0, $3, $4, $5, $6, $7, $8::uuid,
                    CASE WHEN $9 THEN $8::uuid END, CASE WHEN $9 THEN clock_timestamp() END)")
            .bind(id).bind(PROVIDER).bind(epoch).bind(ISSUER).bind(subject)
            .bind(FUTURE.parse::<i64>().unwrap()).bind(LATER.parse::<i64>().unwrap())
            .bind(OPERATOR).bind(withdrawn).execute(&mut owner).await.unwrap();
    }
    let before = first_approval::everything(&db).await;

    let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
    assert!(
        matches!(
            &failure,
            Failure::Migrate(MigrateError::ExecuteMigration(_, 13))
        ) && failure.to_string().contains("SQLSTATE 23514"),
        "{failure}"
    );
    // Rolled back whole: history, every row, the code-less function and the table shape.
    assert_eq!(db.history().await, versions_through(12));
    assert_eq!(first_approval::everything(&db).await, before);
    assert_eq!(function_contract(&mut owner).await, contract(CODELESS));
    let hash_columns = "SELECT count(*) FROM pg_attribute WHERE attname = 'code_hash'
        AND attrelid = 'openmettle.home_invitations'::regclass AND NOT attisdropped";
    let columns: i64 = sqlx::query_scalar(hash_columns)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(columns, 0);
    db.wait_no_migration_session().await;

    // The documented precondition, with the unchanged withdrawal command.
    let out = psql(
        &db,
        WITHDRAW,
        &[("invitation", INVITATION), ("operator", OPERATOR)],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());
    assert_eq!(function_contract(&mut owner).await, contract(CODED));
    // Both closed decisions survive, with no code and no way to become pending again.
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT id::text, withdrawn_at IS NOT NULL, code_hash IS NULL
           FROM openmettle.home_invitations ORDER BY id",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            (INVITATION.into(), true, true),
            (WITHDRAWN.into(), true, true)
        ]
    );
    expect_state(
        &mut owner,
        "UPDATE openmettle.home_invitations SET withdrawn_by = NULL, withdrawn_at = NULL",
        "23514",
    )
    .await;
    // A new pending row needs a 32-byte hash.
    for (hash, state) in [
        ("NULL", Some("23514")),
        ("decode(repeat('00', 31), 'hex')", Some("23514")),
        ("decode(repeat('00', 33), 'hex')", Some("23514")),
        ("decode(repeat('00', 32), 'hex')", None),
    ] {
        let mut tx = owner.begin().await.unwrap();
        let result = tx.execute(AssertSqlSafe(format!(
            "INSERT INTO openmettle.home_invitations (id, provider_id, provider_generation, provider_epoch, issuer, subject, redeem_before_ms, approval_until_ms, created_by, code_hash)
             VALUES (gen_random_uuid(), '{PROVIDER}', 0, {epoch}, '{ISSUER}', 'synthetic-new', {FUTURE}, {LATER}, '{OPERATOR}', {hash})"
        ))).await;
        match state {
            Some(state) => assert_eq!(sqlstate(result), state, "{hash}"),
            None => drop(result.unwrap()),
        }
        tx.rollback().await.unwrap();
    }
}

// Migration 13 admits the aes256gcm-v2 length beside v1 and nothing else. Schema 12 is the
// control: the same 76-byte insert is refused there.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn ciphertext_check_accepts_only_the_sealed_lengths_of_each_schema() {
    for (sources, accepted) in [
        (&MIGRATIONS[..INVITATIONS], &[59][..]),
        (MIGRATIONS, &[59, 76][..]),
    ] {
        let db = TestDb::new().await;
        migrate::apply(&db.settings(Duration::from_secs(5)), sources)
            .await
            .unwrap();
        let mut api = connect(&db.0, API).await;
        for (n, length) in [0, 1, 58, 59, 60, 75, 76, 77, 4096].into_iter().enumerate() {
            let mark = u8::try_from(n).unwrap();
            sqlx::query(
                "INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ('k', $1)",
            )
            .bind(vec![mark; 12])
            .execute(&mut api)
            .await
            .unwrap();
            let result = sqlx::query("INSERT INTO openmettle.login_transactions (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext) VALUES ($1,'b'::bytea,1,$2,$2,$2,'k',$3,$4)")
                .bind(format!("{n:a>43}"))
                .bind(vec![mark; 32])
                .bind(vec![mark; 12])
                .bind(vec![0u8; length])
                .execute(&mut api)
                .await;
            if accepted.contains(&length) {
                result.unwrap();
            } else {
                assert_eq!(sqlstate(result), "23514", "{length} bytes");
            }
        }
        // Consumption still clears the ciphertext at either length.
        expect_state(
            &mut api,
            "UPDATE openmettle.login_transactions SET consumed = true",
            "23514",
        )
        .await;
        let cleared = sqlx::query(
            "UPDATE openmettle.login_transactions SET consumed = true, ciphertext = NULL",
        )
        .execute(&mut api)
        .await
        .unwrap();
        assert_eq!(cleared.rows_affected(), accepted.len() as u64);
    }
}

// The create command and the table constraint apply one byte predicate where the server does
// not validate client bytes.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn create_command_and_table_refuse_high_bit_subjects_on_sql_ascii() {
    let db = TestDb::create(
        "SELECT pg_advisory_lock_shared($1)",
        "TEMPLATE template0 ENCODING 'SQL_ASCII' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'",
    )
    .await;
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    let epoch = provider(&mut owner).await;
    let script = format!("{WINDOW}{CREATE}");
    let vars = |subject: &'static str| {
        [
            ("invitation", INVITATION),
            ("operator", OPERATOR),
            ("provider", PROVIDER),
            ("issuer", ISSUER),
            ("subject", subject),
            ("expected_generation", "0"),
        ]
    };
    let high = "Synthetic Subjéct";
    let out = psql(&db, &script, &vars(high));
    // Standard output is never formatted into a message: it is where a code would appear.
    let text = stderr(&out);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "a refused command wrote to stdout");
    assert!(text.contains("home invitation creation refused"), "{text}");
    for value in [INVITATION, OPERATOR, PROVIDER, ISSUER, "Synthetic Subj"] {
        assert!(!text.contains(value), "output repeats an input value");
    }
    let insert = |subject: &'static str| {
        sqlx::query("INSERT INTO openmettle.home_invitations (id, provider_id, provider_generation, provider_epoch, issuer, subject, redeem_before_ms, approval_until_ms, created_by, code_hash) VALUES ($1::uuid, $2::uuid, 0, $3, $4, $5, $6, $7, $8::uuid, decode(repeat('00', 32), 'hex'))")
            .bind(INVITATION).bind(PROVIDER).bind(epoch).bind(ISSUER).bind(subject)
            .bind(FUTURE.parse::<i64>().unwrap()).bind(LATER.parse::<i64>().unwrap()).bind(OPERATOR)
    };
    // A direct owner write meets the same byte predicate, in a transaction that is discarded.
    let mut tx = owner.begin().await.unwrap();
    let err = insert(high).execute(&mut *tx).await.unwrap_err();
    assert!(
        matches!(&err, sqlx::Error::Database(e) if e.code().as_deref() == Some("23514")),
        "{err:?}"
    );
    tx.rollback().await.unwrap();
    let mut tx = owner.begin().await.unwrap();
    insert("Synthetic Subject").execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();

    let out = psql(&db, &script, &vars("Synthetic Subject"));
    assert!(out.status.success(), "{}", stderr(&out));
    // Line 1, then the code line: `omh1-` and eight hyphenated groups of four digits.
    let code = std::str::from_utf8(&out.stdout).ok().and_then(|text| {
        text.strip_prefix(
            "home invitation created\ninvitation code (shown once; deliver privately): omh1-",
        )
    });
    assert!(
        code.is_some_and(|code| code.len() == 40 && code.ends_with('\n')),
        "create output is not the two documented lines"
    );
    let row: (String, i64, Vec<u8>, i32) = sqlx::query_as(
        "SELECT id::text, provider_epoch, convert_to(subject, 'SQL_ASCII'), octet_length(code_hash)
           FROM openmettle.home_invitations",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        row,
        (INVITATION.into(), epoch, b"Synthetic Subject".to_vec(), 32)
    );
}
