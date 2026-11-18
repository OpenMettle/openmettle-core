use super::cancellation::{ResponseBarrier, cancel_at_response};
use super::*;
use openmettle_core::{
    auth::{Policy, TrustedProvider},
    login::{self, Callback, Error, KeyRing, Provider, ProviderDefinition, Started},
};
#[path = "../login_support/mod.rs"]
mod fixture;
fn provider(revision: &str, enabled: bool) -> Arc<Provider> {
    Arc::new(
        Provider::new(
            TrustedProvider::new(
                fixture::ID,
                fixture::ISSUER,
                fixture::CLIENT,
                &fixture::jwks(),
            )
            .unwrap(),
            ProviderDefinition {
                revision,
                enabled,
                authorization_endpoint: fixture::AUTH,
                token_endpoint: fixture::TOKEN,
                callback: fixture::CALLBACK,
                destination: "home",
            },
        )
        .unwrap(),
    )
}
fn keys() -> KeyRing {
    KeyRing::new(vec![("test-v1".into(), [7; 32])]).unwrap()
}
fn callback<'a>(start: &'a Started, code: &'a str) -> Callback<'a> {
    Callback {
        state: start.state.expose(),
        caller_binding: start.caller_binding.expose(),
        issuer: fixture::ISSUER,
        callback: fixture::CALLBACK,
        code,
    }
}
async fn begin(db: &TestDb, p: &Provider) -> Started {
    login::begin(
        &mut connect(&db.0, API).await,
        p,
        &keys(),
        Duration::from_secs(60),
    )
    .await
    .unwrap()
}
async fn counts(db: &TestDb) -> (i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM openmettle.login_nonce_reservations),(SELECT count(*) FROM openmettle.login_transactions),(SELECT count(*) FROM openmettle.login_transactions WHERE consumed AND ciphertext IS NULL)")
        .fetch_one(&mut db.admin().await).await.unwrap()
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn bound_exchange_denials_rotation_and_single_use_race() {
    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    let fake = fixture::FakeProvider::new();
    let start = begin(&db, &p).await;
    let code = fake.authorize(start.authorization_url.expose(), start.state.expose());
    for which in 0..7 {
        let mut c = callback(&start, &code);
        let wrong_state = format!(
            "{}.{}",
            start.state.expose().split_once('.').unwrap().0,
            "x".repeat(43)
        );
        let wrong_caller = "x".repeat(43);
        let configured = match which {
            4 => provider("v2", true),
            5 => provider("v1", false),
            _ => p.clone(),
        };
        match which {
            0 => c.state = &wrong_state,
            1 => c.caller_binding = &wrong_caller,
            2 => c.issuer = "https://wrong.example.test",
            3 => c.callback = "https://wrong.example.test/callback",
            6 => c.issuer = "",
            _ => (),
        }
        assert!(matches!(
            login::consume(&mut connect(&db.0, API).await, configured, &keys(), c).await,
            Err(Error::Rejected)
        ));
        assert_eq!(counts(&db).await, (1, 1, 0));
    }
    let missing = KeyRing::new(vec![("missing".into(), [9; 32])]).unwrap();
    assert!(matches!(
        login::consume(
            &mut connect(&db.0, API).await,
            p.clone(),
            &missing,
            callback(&start, &code)
        )
        .await,
        Err(Error::Protection)
    ));
    let wrong = KeyRing::new(vec![("test-v1".into(), [9; 32])]).unwrap();
    assert!(matches!(
        login::consume(
            &mut connect(&db.0, API).await,
            p.clone(),
            &wrong,
            callback(&start, &code)
        )
        .await,
        Err(Error::Protection)
    ));
    let rotated = KeyRing::new(vec![
        ("test-v2".into(), [9; 32]),
        ("test-v1".into(), [7; 32]),
    ])
    .unwrap();
    let mut a = connect(&db.0, API).await;
    let mut b = connect(&db.0, API).await;
    let (a_result, b_result) = tokio::join!(
        login::consume(&mut a, p.clone(), &rotated, callback(&start, &code)),
        login::consume(&mut b, p.clone(), &rotated, callback(&start, &code))
    );
    // The rejected consumer drops its transaction, which queues SQLx rollback.
    // Close the owned connections before network work or a fresh replay probe;
    // shadowing them would leave the loser's row lock held until scope exit.
    a.close().await.unwrap();
    b.close().await.unwrap();
    let permit = match (a_result, b_result) {
        (Ok(p), Err(Error::Rejected)) | (Err(Error::Rejected), Ok(p)) => p,
        _ => panic!("one winner required"),
    };
    let http = |request| std::future::ready(fake.exchange(request));
    let identity = permit
        .exchange(&http, &Policy::default(), fixture::now)
        .await
        .unwrap();
    assert_eq!(identity.subject(), "synthetic-subject");
    assert_eq!(counts(&db).await, (1, 1, 1));
    assert_eq!(
        login::consume(
            &mut connect(&db.0, API).await,
            p,
            &rotated,
            callback(&start, &code)
        )
        .await
        .unwrap_err(),
        Error::Rejected
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM openmettle.users")
            .fetch_one(&mut db.admin().await)
            .await
            .unwrap(),
        0
    );
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn reservation_commit_uncertainty_and_consumption_cancellation() {
    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    // COMMIT has executed but its acknowledgement never reaches the caller. No begin result,
    // no ciphertext, and no transaction row: encryption must follow the reservation ACK.
    let mut barrier = ResponseBarrier::new(b"COMMIT\0");
    let options = role_options(&db.0, API)
        .host("127.0.0.1")
        .port(barrier.port)
        .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    cancel_at_response(
        &mut barrier,
        login::begin(&mut cn, &p, &keys(), Duration::from_secs(60)),
    )
    .await;
    drop(cn);
    drop(barrier);
    assert_eq!(counts(&db).await, (1, 0, 0));
    for (command, spent) in [
        (b"UPDATE 1\0".as_slice(), false),
        (b"COMMIT\0".as_slice(), true),
    ] {
        let start = begin(&db, &p).await;
        let before = counts(&db).await;
        let mut barrier = ResponseBarrier::new(command);
        let options = role_options(&db.0, API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut cn = PgConnection::connect_with(&options).await.unwrap();
        cancel_at_response(
            &mut barrier,
            login::consume(
                &mut cn,
                p.clone(),
                &keys(),
                callback(&start, "synthetic-code"),
            ),
        )
        .await;
        drop(cn);
        drop(barrier);
        let mut cn = connect(&db.0, API).await;
        let result = login::consume(
            &mut cn,
            p.clone(),
            &keys(),
            callback(&start, "synthetic-code"),
        )
        .await;
        assert_eq!(result.is_err(), spent);
        assert_eq!(counts(&db).await.2, before.2 + 1);
    }
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn expiry_is_observed_after_waiting_for_row_lock() {
    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    let start = login::begin(
        &mut connect(&db.0, API).await,
        &p,
        &keys(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    let id = start.state.expose().split_once('.').unwrap().0;
    let mut owner = db.admin().await;
    let mut lock = owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.login_transactions WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let mut cn = connect(&db.0, API).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut cn)
        .await
        .unwrap();
    let hold = async {
        let mut observer = db.admin().await;
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(&mut observer).await.unwrap();
                if waiting {break;}
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        // Wait for this row's real expiry, not an assumed scheduler delay.
        sqlx::query("SELECT pg_sleep(GREATEST(0, expires_ms / 1000.0 - extract(epoch FROM clock_timestamp()))) FROM openmettle.login_transactions WHERE id=$1")
            .bind(id).execute(&mut *lock).await.unwrap();
        lock.commit().await.unwrap();
    };
    let keys = keys();
    let (result, ()) = tokio::join!(
        login::consume(&mut cn, p, &keys, callback(&start, "code")),
        hold
    );
    assert!(matches!(result, Err(Error::Rejected)));
    assert_eq!(counts(&db).await, (1, 1, 0));
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn authenticated_row_tampering_cannot_consume_login() {
    use sha2::{Digest, Sha256};

    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    let all_keys = KeyRing::new(vec![
        ("test-v1".into(), [7; 32]),
        ("test-v2".into(), [8; 32]),
    ])
    .unwrap();
    let mut admin = db.admin().await;
    for change in ["expiry", "state", "caller", "encrypted-row"] {
        let start = begin(&db, &p).await;
        let id = start.state.expose().split_once('.').unwrap().0;
        let attacker_state = format!("{id}.{}", "A".repeat(43));
        let attacker_caller = "B".repeat(43);
        let mut presented = callback(&start, "synthetic-code");
        match change {
            "expiry" => {
                sqlx::query("UPDATE openmettle.login_transactions SET expires_ms=expires_ms+60000 WHERE id=$1")
                    .bind(id).execute(&mut admin).await.unwrap();
            }
            "state" | "caller" => {
                // Matching attacker-controlled callback values pass the plain digest
                // comparisons, so only authenticated decryption can reject this edit.
                let (statement, value) = if change == "state" {
                    presented.state = &attacker_state;
                    (
                        "UPDATE openmettle.login_transactions SET state_hash=$1 WHERE id=$2",
                        attacker_state.as_str(),
                    )
                } else {
                    presented.caller_binding = &attacker_caller;
                    (
                        "UPDATE openmettle.login_transactions SET caller_hash=$1 WHERE id=$2",
                        attacker_caller.as_str(),
                    )
                };
                sqlx::query(statement)
                    .bind(Sha256::digest(value.as_bytes()).to_vec())
                    .bind(id)
                    .execute(&mut admin)
                    .await
                    .unwrap();
            }
            "encrypted-row" => {
                let donor = login::begin(
                    &mut connect(&db.0, API).await,
                    &p,
                    &KeyRing::new(vec![("test-v2".into(), [8; 32])]).unwrap(),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();
                let donor_id = donor.state.expose().split_once('.').unwrap().0;
                let encrypted: (String, Vec<u8>, Vec<u8>) = sqlx::query_as(
                    "SELECT key_id,nonce,ciphertext FROM openmettle.login_transactions WHERE id=$1",
                )
                .bind(donor_id)
                .fetch_one(&mut admin)
                .await
                .unwrap();
                // Owner-only deletion frees the unique encrypted-row tuple; the
                // durable nonce reservation remains. Both keys are valid and loaded.
                sqlx::query("DELETE FROM openmettle.login_transactions WHERE id=$1")
                    .bind(donor_id)
                    .execute(&mut admin)
                    .await
                    .unwrap();
                sqlx::query("UPDATE openmettle.login_transactions SET key_id=$1,nonce=$2,ciphertext=$3 WHERE id=$4")
                    .bind(encrypted.0).bind(encrypted.1).bind(encrypted.2).bind(id)
                    .execute(&mut admin).await.unwrap();
            }
            _ => unreachable!(),
        }
        let ciphertext: Vec<u8> =
            sqlx::query_scalar("SELECT ciphertext FROM openmettle.login_transactions WHERE id=$1")
                .bind(id)
                .fetch_one(&mut admin)
                .await
                .unwrap();
        assert_eq!(
            login::consume(
                &mut connect(&db.0, API).await,
                p.clone(),
                &all_keys,
                presented
            )
            .await
            .unwrap_err(),
            Error::Protection,
            "tampering case: {change}",
        );
        let after: (bool, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT consumed,ciphertext FROM openmettle.login_transactions WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert_eq!(after, (false, Some(ciphertext)), "tampering case: {change}");
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn tampering_reservations_and_role_boundaries() {
    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    let start = begin(&db, &p).await;
    let id = start.state.expose().split_once('.').unwrap().0;
    let mut admin = db.admin().await;
    for column in [
        "binding",
        "state_hash",
        "nonce_hash",
        "caller_hash",
        "ciphertext",
    ] {
        let old: Vec<u8> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT {column} FROM openmettle.login_transactions WHERE id=$1"
        )))
        .bind(id)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        let mut bad = old.clone();
        bad[0] ^= 1;
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE openmettle.login_transactions SET {column}=$1 WHERE id=$2"
        )))
        .bind(bad)
        .bind(id)
        .execute(&mut admin)
        .await
        .unwrap();
        assert!(
            login::consume(
                &mut connect(&db.0, API).await,
                p.clone(),
                &keys(),
                callback(&start, "code")
            )
            .await
            .is_err()
        );
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE openmettle.login_transactions SET {column}=$1 WHERE id=$2"
        )))
        .bind(old)
        .bind(id)
        .execute(&mut admin)
        .await
        .unwrap();
    }
    let mut api = connect(&db.0, API).await;
    // Exact nonce collision cannot overwrite the first reservation.
    let inserted=sqlx::query("INSERT INTO openmettle.login_nonce_reservations SELECT key_id,nonce FROM openmettle.login_nonce_reservations ON CONFLICT DO NOTHING").execute(&mut api).await.unwrap();
    assert_eq!(inserted.rows_affected(), 0);
    for statement in [
        "DELETE FROM openmettle.login_nonce_reservations",
        "DELETE FROM openmettle.login_transactions",
        "UPDATE openmettle.login_transactions SET expires_ms=1",
        "UPDATE openmettle.login_transactions SET binding='x'::bytea",
        "UPDATE openmettle.login_nonce_reservations SET key_id='replacement'",
    ] {
        assert!(api.execute(statement).await.is_err());
    }
    let mut worker = connect(&db.0, WORKER).await;
    for statement in [
        "SELECT * FROM openmettle.login_transactions",
        "SELECT * FROM openmettle.login_nonce_reservations",
    ] {
        assert!(worker.execute(statement).await.is_err());
    }
    admin
        .execute("GRANT SELECT ON openmettle.login_transactions TO openmettle_worker")
        .await
        .unwrap();
    assert!(matches!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
}

// Subprocess entry used only by the process-kill test. All inputs are synthetic CI data.
#[tokio::test]
#[ignore = "subprocess fixture only"]
async fn consume_child() {
    let Ok(database) = std::env::var("LOGIN_TEST_DATABASE") else {
        return;
    };
    let port: u16 = std::env::var("LOGIN_TEST_PORT").unwrap().parse().unwrap();
    let state = std::env::var("LOGIN_TEST_STATE").unwrap();
    let caller = std::env::var("LOGIN_TEST_CALLER").unwrap();
    let mut cn = PgConnection::connect_with(
        &role_options(&database, API)
            .host("127.0.0.1")
            .port(port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable),
    )
    .await
    .unwrap();
    let _permit = login::consume(
        &mut cn,
        provider("v1", true),
        &keys(),
        Callback {
            state: &state,
            caller_binding: &caller,
            issuer: fixture::ISSUER,
            callback: fixture::CALLBACK,
            code: "synthetic-code",
        },
    )
    .await
    .unwrap();
    panic!("child must be killed before receiving a permit");
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn killed_consumer_rolls_back_without_releasing_permit() {
    use std::os::unix::process::ExitStatusExt;
    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    for (command, spent) in [
        (b"UPDATE 1\0".as_slice(), false),
        (b"COMMIT\0".as_slice(), true),
    ] {
        let start = begin(&db, &p).await;
        let mut barrier = ResponseBarrier::new(command);
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durable::login::consume_child", "--ignored"])
            .env("LOGIN_TEST_DATABASE", &db.0)
            .env("LOGIN_TEST_PORT", barrier.port.to_string())
            .env("LOGIN_TEST_STATE", start.state.expose())
            .env("LOGIN_TEST_CALLER", start.caller_binding.expose())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = Process(child);
        barrier.wait_reached().await;
        signal(&child.0, "-KILL");
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        drop(barrier);
        let result = login::consume(
            &mut connect(&db.0, API).await,
            p.clone(),
            &keys(),
            callback(&start, "synthetic-code"),
        )
        .await;
        assert_eq!(result.is_err(), spent);
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_six_failure_rolls_back_reservations_and_retries() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..5])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("CREATE TABLE openmettle.login_transactions (conflict text)")
        .await
        .unwrap();
    assert!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
            .await
            .is_err()
    );
    assert_eq!(db.history().await, [1, 2, 3, 4, 5]);
    assert!(!db.exists("openmettle.login_nonce_reservations").await);
    owner
        .execute("DROP TABLE openmettle.login_transactions")
        .await
        .unwrap();
    migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(
        db.history().await,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn failed_begin_retains_reserved_nonce_without_partial_transaction() {
    let db = TestDb::migrated().await;
    db.admit(64).await;
    let p = provider("v1", true);
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute(
            "ALTER TABLE openmettle.login_transactions ADD CONSTRAINT inject_failure CHECK (false)",
        )
        .await
        .unwrap();
    assert!(
        login::begin(
            &mut connect(&db.0, API).await,
            &p,
            &keys(),
            Duration::from_secs(60)
        )
        .await
        .is_err()
    );
    assert_eq!(counts(&db).await, (1, 0, 0));
    owner
        .execute("ALTER TABLE openmettle.login_transactions DROP CONSTRAINT inject_failure")
        .await
        .unwrap();
    let _start = begin(&db, &p).await;
    assert_eq!(counts(&db).await, (2, 1, 0));
}

#[test]
fn released_login_migrations_are_frozen() {
    use sha2::{Digest, Sha256};
    for (sql, expected) in [
        (
            MIGRATIONS[5].sql,
            "6ebaec059411b63e6b787ca7bb72de9e152809174c462c48a2173bdf7b10e078",
        ),
        (
            MIGRATIONS[6].sql,
            "42e5ef4abffbbd6023f6e65a954a6f6ebedbdbcf46439f28f64e61260280842d",
        ),
    ] {
        assert_eq!(format!("{:x}", Sha256::digest(sql.as_bytes())), expected);
    }
}

const AUTHORITY_TABLES: [&str; 2] = [
    "openmettle.login_providers",
    "openmettle.login_provider_revisions",
];

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_seven_authority_is_operator_owned() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..7])
        .await
        .unwrap();
    let mut admin = db.admin().await;
    for table in AUTHORITY_TABLES {
        for (role, privilege, expected) in [
            (API, "SELECT", true),
            (API, "INSERT", false),
            (API, "UPDATE", false),
            (API, "DELETE", false),
            (API, "TRUNCATE", false),
            (API, "REFERENCES", false),
            (API, "TRIGGER", false),
            (WORKER, "SELECT", false),
            (WORKER, "INSERT", false),
            ("public", "SELECT", false),
        ] {
            let granted: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
                .bind(role)
                .bind(table)
                .bind(privilege)
                .fetch_one(&mut admin)
                .await
                .unwrap();
            assert_eq!(granted, expected, "{role} {privilege} {table}");
        }
    }
    // The identity sequence is owner-only: no application role allocates or observes epochs.
    for role in [API, WORKER, "public"] {
        for privilege in ["USAGE", "SELECT", "UPDATE"] {
            let granted: bool = sqlx::query_scalar(
                "SELECT has_sequence_privilege($1, 'openmettle.login_provider_revisions_epoch_seq', $2)",
            )
            .bind(role)
            .bind(privilege)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            assert!(!granted, "{role} {privilege} sequence");
        }
    }
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("INSERT INTO openmettle.login_providers (id, issuer, client_id) VALUES ('0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', 'https://issuer.example.test/realm', 'synthetic-client')")
        .await
        .unwrap();
    owner
        .execute("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ('0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', 'v1'), ('0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', NULL)")
        .await
        .unwrap();
    for (sql, code) in [
        // Explicit epochs are refused unless the owner deliberately overrides the identity.
        (
            "INSERT INTO openmettle.login_provider_revisions (epoch, provider_id, revision) VALUES (99, '0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', 'v1')",
            "428C9",
        ),
        (
            "INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ('1b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', 'v1')",
            "23503",
        ),
        (
            "INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ('0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', 'bad revision')",
            "23514",
        ),
        (
            "INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ('0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', '')",
            "23514",
        ),
        (
            "INSERT INTO openmettle.login_providers (id, issuer, client_id) VALUES ('2b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', 'https://issuer.example.test', repeat('c', 256))",
            "23514",
        ),
        (
            "INSERT INTO openmettle.login_providers (id, issuer, client_id) VALUES ('2b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f', '', 'c')",
            "23514",
        ),
    ] {
        expect_state(&mut owner, sql, code).await;
    }
    let mut api = connect(&db.0, API).await;
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.login_provider_revisions")
            .fetch_one(&mut api)
            .await
            .unwrap();
    assert_eq!(visible, 2);
    for sql in [
        "INSERT INTO openmettle.login_providers (id, issuer, client_id) VALUES (gen_random_uuid(), 'https://x.example.test', 'c')",
        "INSERT INTO openmettle.login_provider_revisions (provider_id, revision) SELECT id, 'v9' FROM openmettle.login_providers",
        "UPDATE openmettle.login_provider_revisions SET revision = 'v1'",
        "UPDATE openmettle.login_providers SET client_id = 'other'",
        "DELETE FROM openmettle.login_provider_revisions",
        "TRUNCATE openmettle.login_providers",
        "SELECT nextval('openmettle.login_provider_revisions_epoch_seq')",
        "SELECT last_value FROM openmettle.login_provider_revisions_epoch_seq",
        "SELECT * FROM openmettle.login_providers FOR UPDATE",
    ] {
        expect_state(&mut api, sql, "42501").await;
    }
    let mut worker = connect(&db.0, WORKER).await;
    for table in AUTHORITY_TABLES {
        expect_state(&mut worker, &format!("SELECT * FROM {table}"), "42501").await;
    }
    // Any authority privilege beyond the contract is refused by the boundary check.
    for (grant, revoke) in [
        (
            "GRANT INSERT ON openmettle.login_provider_revisions TO openmettle_api",
            "REVOKE INSERT ON openmettle.login_provider_revisions FROM openmettle_api",
        ),
        (
            "GRANT USAGE ON SEQUENCE openmettle.login_provider_revisions_epoch_seq TO openmettle_api",
            "REVOKE USAGE ON SEQUENCE openmettle.login_provider_revisions_epoch_seq FROM openmettle_api",
        ),
        (
            "GRANT SELECT ON openmettle.login_providers TO openmettle_worker",
            "REVOKE SELECT ON openmettle.login_providers FROM openmettle_worker",
        ),
    ] {
        admin.execute(AssertSqlSafe(grant)).await.unwrap();
        assert!(matches!(
            migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..7]).await,
            Err(Failure::Refused(_))
        ));
        admin.execute(AssertSqlSafe(revoke)).await.unwrap();
    }
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..7])
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_seven_is_atomic_and_gated_by_history() {
    // Version-7 permissions are not accepted before migration 7 is recorded.
    let early = TestDb::new().await;
    migrate::apply(&early.settings(Duration::from_secs(5)), &MIGRATIONS[..6])
        .await
        .unwrap();
    let mut owner = connect(&early.0, OWNER).await;
    owner
        .execute("CREATE TABLE openmettle.login_providers (id uuid); GRANT SELECT ON openmettle.login_providers TO openmettle_api")
        .await
        .unwrap();
    assert!(matches!(
        migrate::apply(&early.settings(Duration::from_secs(5)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
    assert_eq!(early.history().await, [1, 2, 3, 4, 5, 6]);
    // A failure inside migration 7 leaves no partial authority objects and can be retried.
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..6])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("CREATE TABLE openmettle.login_provider_revisions (conflict text)")
        .await
        .unwrap();
    assert!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
            .await
            .is_err()
    );
    assert_eq!(db.history().await, [1, 2, 3, 4, 5, 6]);
    assert!(!db.exists("openmettle.login_providers").await);
    owner
        .execute("DROP TABLE openmettle.login_provider_revisions")
        .await
        .unwrap();
    migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(
        db.history().await,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    );
    for table in AUTHORITY_TABLES {
        assert!(db.exists(table).await);
    }
}

#[path = "admission.rs"]
mod admission;
