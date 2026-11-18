//! ADR 0013 session cleanup: executes the exact operator script, then the exact ADR 0014 gate
//! script, with the pinned service psql (isolated CI PostgreSQL 18 and POSTGRES_CONTAINER).
//! Replay refusal after session deletion or gate absence is proven separately by
//! `provider_keys::tests::postgres::sessions::gate_binding_and_replay_survive_session_cleanup`;
//! these tests prove the script preserves the gate and marker that proof depends on.
use super::*;

const SESSION_SCRIPT: &str = include_str!("../../docs/operator/session-cleanup.psql");
const PROCEDURE: &str = include_str!("../../docs/operator/session-cleanup.md");
const README: &str = include_str!("../../README.md");
const ADR_0013: &str = include_str!("../../docs/adr/0013-local-identity-sessions.md");
const REFUSED: &str = "session cleanup refused: batch must be 1-1000; nothing deleted";
/// Deterministic absolute times: far past and 2100-01-01, independent of the test clock.
const PAST: i64 = 2;
const FUTURE: i64 = 4_102_444_800_000;
const PROVIDER: &str = "00000000-0000-0000-0000-000000000013";

#[test]
fn one_canonical_session_cleanup_procedure_is_linked() {
    assert!(README.contains("](docs/operator/session-cleanup.md)"));
    for adr in [ADR_0013, ADR] {
        assert!(adr.contains("](../operator/session-cleanup.md)"));
    }
    assert!(PROCEDURE.contains("](session-cleanup.psql)"));
    // The executable file is the only active session-deletion recipe.
    for doc in [README, ADR_0013, ADR, PROCEDURE] {
        assert!(!doc.contains("DELETE FROM openmettle.local_sessions"));
    }
}

fn session_id(name: &str) -> String {
    format!("{name:_<43}")
}
fn gate_id(name: &str) -> String {
    format!("gate-{name:_<38}")
}

/// Every row of a table as JSON text, compared as a set so no collation or order is assumed.
async fn rows(db: &TestDb, table: &str) -> BTreeSet<String> {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT to_jsonb(t)::text FROM openmettle.{table} t"
    )))
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
    .into_iter()
    .collect()
}
async fn ids(db: &TestDb, table: &str) -> BTreeSet<String> {
    sqlx::query_scalar(AssertSqlSafe(format!("SELECT id FROM openmettle.{table}")))
        .fetch_all(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
        .into_iter()
        .collect()
}
/// Tables the session script must never change.
const PROTECTED: [&str; 6] = [
    "login_transactions",
    "login_nonce_reservations",
    "local_identity_approvals",
    "users",
    "login_providers",
    "login_provider_revisions",
];
async fn protected(db: &TestDb) -> Vec<BTreeSet<String>> {
    let mut all = Vec::new();
    for table in PROTECTED {
        all.push(rows(db, table).await);
    }
    all
}

/// One provider, user, identity and approval, then one consumed, issued gate (with its nonce
/// reservation) and one session per row. All values are synthetic and absolute.
async fn seed(db: &TestDb, sessions: &[(&str, bool, i64, i64)]) {
    let mut owner = connect(&db.0, OWNER).await;
    owner.execute(AssertSqlSafe(format!("INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason) VALUES ('{PROVIDER}','https://cleanup.example.test','synthetic','fixture-owner','synthetic provider'); INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ('{PROVIDER}','v1'); INSERT INTO openmettle.users(id) VALUES ('00000000-0000-0000-0000-0000000000a1'); INSERT INTO openmettle.user_identities(id,user_id,issuer,subject) VALUES ('00000000-0000-0000-0000-0000000000b1','00000000-0000-0000-0000-0000000000a1','https://cleanup.example.test','synthetic-subject'); INSERT INTO openmettle.local_identity_approvals(id,provider_id,identity_id,active,expires_ms,changed_by,change_reason) VALUES ('00000000-0000-0000-0000-0000000000c1','{PROVIDER}','00000000-0000-0000-0000-0000000000b1',true,{FUTURE},'fixture-owner','synthetic approval')"))).await.unwrap();
    for &(name, revoked, session_expiry, gate_expiry) in sessions {
        sqlx::query("WITH r AS (INSERT INTO openmettle.login_nonce_reservations(key_id,nonce) VALUES ('fixture-v1',substring(sha256(convert_to($1,'UTF8')) FROM 1 FOR 12)) RETURNING key_id,nonce), g AS (INSERT INTO openmettle.login_transactions(id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext,consumed,session_issued) SELECT $1,'\\x01'::bytea,$3,sha256(convert_to($1||':state','UTF8')),sha256(convert_to($1||':nonce','UTF8')),sha256(convert_to($1||':caller','UTF8')),key_id,nonce,NULL,true,true FROM r RETURNING id) INSERT INTO openmettle.local_sessions(id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms,revoked) SELECT $2,sha256(convert_to($2,'UTF8')),g.id,$5::uuid,'00000000-0000-0000-0000-0000000000b1','00000000-0000-0000-0000-0000000000c1','00000000-0000-0000-0000-0000000000a1','synthetic',(SELECT max(epoch) FROM openmettle.login_provider_revisions),1,0,0,0,1,$4,$6 FROM g")
            .bind(gate_id(name))
            .bind(session_id(name))
            .bind(gate_expiry)
            .bind(session_expiry)
            .bind(PROVIDER)
            .bind(revoked)
            .execute(&mut owner)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn session_script_refuses_invalid_or_missing_batch_without_effects() {
    let db = TestDb::migrated().await;
    seed(
        &db,
        &[
            ("revoked", true, FUTURE, PAST),
            ("expired", false, PAST, PAST),
        ],
    )
    .await;
    let sessions = rows(&db, "local_sessions").await;
    let others = protected(&db).await;
    let refused = |out: Output| {
        assert!(!out.status.success());
        assert!(stderr(&out).contains(REFUSED), "{}", stderr(&out));
        assert!(out.stdout.is_empty());
    };
    for bad in [
        "",
        "0",
        "00",
        "01",
        "1001",
        "9999",
        "-1",
        "+1",
        "1.0",
        " 1",
        "1 ",
        "x",
        "1e3",
        "1 OR true",
        "1; DELETE FROM openmettle.local_sessions",
    ] {
        refused(psql(&db, SESSION_SCRIPT, &[("batch", bad)]));
    }
    refused(psql(&db, SESSION_SCRIPT, &[]));
    // A caller-supplied `valid` cannot bypass validation of a missing batch.
    refused(psql(&db, SESSION_SCRIPT, &[("valid", "true")]));
    assert_eq!(rows(&db, "local_sessions").await, sessions);
    assert_eq!(protected(&db).await, others);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn session_then_gate_cleanup_deletes_only_eligible_rows_in_bounded_batches() {
    let db = TestDb::migrated().await;
    // (name, revoked, session expiry, gate expiry)
    seed(
        &db,
        &[
            ("live", false, FUTURE, PAST),
            ("revoked", true, FUTURE, PAST),
            ("expired", false, PAST, FUTURE),
            ("both", true, PAST, PAST),
            ("held-revoked", true, FUTURE, PAST),
            ("held-expired", false, PAST, PAST),
        ],
    )
    .await;
    let set = |names: &[&str], id: fn(&str) -> String| -> BTreeSet<String> {
        names.iter().map(|n| id(n)).collect()
    };
    let gates = ids(&db, "login_transactions").await;
    let reservations = rows(&db, "login_nonce_reservations").await;
    let others = protected(&db).await;
    let run = |script: &str, batch: &str| {
        let out = psql(&db, script, &[("batch", batch)]);
        assert!(out.status.success(), "{}", stderr(&out));
        String::from_utf8(out.stdout).unwrap()
    };
    let deleted = |n: usize| format!("session cleanup committed: {n} session rows deleted\n");

    // Gate cleanup first is safe but frees nothing: every expired gate is still referenced.
    run(CLEANUP_SCRIPT, "1000");
    assert_eq!(ids(&db, "login_transactions").await, gates);

    // Concurrent validation/logout locks two eligible rows; cleanup skips them without waiting.
    let mut holder = connect(&db.0, API).await;
    holder.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT id FROM openmettle.local_sessions WHERE id IN ($1,$2) FOR SHARE")
        .bind(session_id("held-revoked"))
        .bind(session_id("held-expired"))
        .fetch_all(&mut holder)
        .await
        .unwrap();
    let held = set(&["live", "held-revoked", "held-expired"], session_id);

    assert_eq!(run(SESSION_SCRIPT, "1"), deleted(1), "exact batch limit");
    assert_eq!(ids(&db, "local_sessions").await.len(), 5);
    assert_eq!(run(SESSION_SCRIPT, "1000"), deleted(2));
    assert_eq!(ids(&db, "local_sessions").await, held);
    // Retry while rows stay locked is an idle, successful batch.
    assert_eq!(run(SESSION_SCRIPT, "1000"), deleted(0));
    assert_eq!(ids(&db, "local_sessions").await, held);

    holder.execute("ROLLBACK").await.unwrap();
    assert_eq!(run(SESSION_SCRIPT, "1000"), deleted(2), "later retry");
    assert_eq!(
        ids(&db, "local_sessions").await,
        set(&["live"], session_id),
        "only the live session remains"
    );
    assert_eq!(run(SESSION_SCRIPT, "1000"), deleted(0), "idle batch");
    // Gates (with issuance markers), nonce reservations, approvals, users and providers are
    // byte-for-byte unchanged by session cleanup.
    assert_eq!(protected(&db).await, others);

    // The separate gate transaction now removes expired gates that lost their session, and
    // keeps the expired gate a live session references and the unexpired gate.
    run(CLEANUP_SCRIPT, "1000");
    let remaining = set(&["live", "expired"], gate_id);
    assert_eq!(ids(&db, "login_transactions").await, remaining);
    let markers: BTreeSet<String> = sqlx::query_scalar(
        "SELECT id FROM openmettle.login_transactions WHERE consumed AND session_issued",
    )
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
    .into_iter()
    .collect();
    assert_eq!(
        markers, remaining,
        "surviving gates keep their issuance marker"
    );
    assert_eq!(rows(&db, "login_nonce_reservations").await, reservations);
    assert_eq!(protected(&db).await[2..], others[2..]);
}
