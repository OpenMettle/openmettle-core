//! Real operator commands and sealed online proofs against the isolated primary.
use super::sessions::{account_state, issue, seed, session_policy, statistics_observer, waiting};
use super::*;
use crate::sessions::{self as local, Error as SessionError};
use std::{io::Write, process::Output};

const CREATE: &str = include_str!("../../../../docs/operator/home-invitation-create.psql");
const WITHDRAW: &str = include_str!("../../../../docs/operator/home-invitation-withdraw.psql");
const ID: &str = "00000000-0000-0000-0000-000000000111";
const OTHER: &str = "00000000-0000-0000-0000-000000000112";
const OPERATOR: &str = "00000000-0000-0000-0000-000000000113";
const SUBJECT: &str = "synthetic-subject";

fn command(f: &Flow, role: &str, script: &str, vars: &[(&str, &str)]) -> Output {
    let mut child = psql::start(&f.db.name, role, PASSWORD, vars);
    let mut stdin = child.stdin.take().unwrap();
    // Use primary time, including in fixtures with skewed application clocks.
    if !vars.iter().any(|(name, _)| *name == "redeem_before_ms") {
        writeln!(stdin, "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 600000 AS redeem_before_ms, floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 900000 AS approval_until_ms \\gset").unwrap();
    }
    stdin.write_all(script.as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}
fn create(f: &Flow, id: &str, provider: &str, subject: &str) -> Output {
    command(
        f,
        OWNER,
        CREATE,
        &[
            ("invitation", id),
            ("provider", provider),
            ("issuer", signing::ISSUER),
            ("subject", subject),
            ("expected_generation", "0"),
            ("operator", OPERATOR),
        ],
    )
}
fn withdraw(f: &Flow, id: &str) -> Output {
    command(
        f,
        OWNER,
        WITHDRAW,
        &[("invitation", id), ("operator", OPERATOR)],
    )
}
fn invite(f: &Flow) {
    let out = create(f, ID, signing::ID, SUBJECT);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"home invitation created\n");
}
async fn refused(f: &mut Flow) {
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    assert!(matches!(
        p.issue_session(&mut f.api, proof, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
}
async fn empty(f: &mut Flow) {
    assert!(account_state(f).await.is_empty());
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
        (SELECT count(*) FROM openmettle.local_identity_approvals),
        (SELECT count(*) FROM openmettle.local_sessions),
        (SELECT count(*) FROM openmettle.home_invitations WHERE approval_id IS NOT NULL),
        (SELECT count(*) FROM openmettle.login_transactions WHERE session_issued)",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn only_exact_pending_principal_can_create_account() {
    let mut f = Flow::new().await;
    sqlx::query(
        "INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason)
        VALUES ($1::uuid,$2,'other-client','fixture','collision')",
    )
    .bind(OTHER)
    .bind(signing::ISSUER)
    .execute(&mut f.owner)
    .await
    .unwrap();
    sqlx::query(APPEND)
        .bind(OTHER)
        .bind("v1")
        .execute(&mut f.owner)
        .await
        .unwrap();
    for (id, provider, subject) in [
        (ID, OTHER, SUBJECT),
        (OTHER, signing::ID, "Synthetic-subject"),
    ] {
        assert!(create(&f, id, provider, subject).status.success());
        if provider == OTHER {
            assert!(!create(&f, OPERATOR, signing::ID, SUBJECT).status.success());
        }
        refused(&mut f).await;
        assert!(withdraw(&f, id).status.success());
    }
    assert!(create(&f, OPERATOR, signing::ID, SUBJECT).status.success());
    assert!(withdraw(&f, OPERATOR).status.success());
    refused(&mut f).await;
    empty(&mut f).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn competing_first_proofs_consume_once_then_ordinary_approval_governs() {
    let mut f = Flow::new().await;
    invite(&f);
    empty(&mut f).await;
    let p = f.h.provider.clone();
    let mut second = f.db.connect(API).await;
    let mut observer = statistics_observer(&f.db).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let other_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut second)
        .await
        .unwrap();
    let (_, a) = f.exchanged(&p).await;
    let (_, b) = f.exchanged(&p).await;
    let mut held = f.owner.begin().await.unwrap();
    held.execute("SELECT id FROM openmettle.home_invitations FOR UPDATE")
        .await
        .unwrap();
    let release = async {
        waiting(&mut observer, pid).await;
        waiting(&mut observer, other_pid).await;
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (a, b, ()) = tokio::join!(
        p.issue_session(&mut f.api, a, &policy),
        p.issue_session(&mut second, b, &policy),
        release
    );
    let first = match (a, b) {
        (Ok(first), Err(SessionError::Rejected)) | (Err(SessionError::Rejected), Ok(first)) => {
            first
        }
        _ => panic!("both proofs saw a missing identity, exactly one may redeem"),
    };
    let context = local::validate(&mut f.api, first.expose(), &policy)
        .await
        .unwrap();
    let row: (String,String,String,i64,bool) = sqlx::query_as("SELECT i.user_id::text, sc.id::text, a.changed_by, a.revision,
        a.active AND a.expires_ms = h.approval_until_ms AND a.access_generation = 0
        AND h.redeemed_at IS NOT NULL AND h.withdrawn_at IS NULL AND l.session_issued
        FROM openmettle.home_invitations h JOIN openmettle.local_identity_approvals a ON a.id=h.approval_id
        JOIN openmettle.user_identities i ON i.id=a.identity_id AND i.subject=h.subject AND i.issuer=h.issuer
        JOIN openmettle.scopes sc ON sc.personal_user_id=i.user_id AND sc.kind='personal'
        JOIN openmettle.login_transactions l ON l.id=h.login_id")
        .fetch_one(&mut f.owner).await.unwrap();
    assert_eq!(
        row,
        (
            context.user_id().into(),
            context.personal_scope_id().into(),
            OPERATOR.into(),
            1,
            true
        )
    );
    let accounts = account_state(&mut f).await;
    assert_eq!(accounts.len(), 3); // one user, one identity, one private scope, zero grants
    assert!(!withdraw(&f, ID).status.success());
    assert!(!create(&f, OTHER, signing::ID, SUBJECT).status.success());
    let second = issue(&mut f).await;
    assert_eq!(
        local::validate(&mut f.api, second.expose(), &policy)
            .await
            .unwrap()
            .user_id(),
        context.user_id()
    );
    local::disable_user(&mut f.api, context.user_id(), 0, &policy)
        .await
        .unwrap();
    refused(&mut f).await;
    assert!(
        local::validate(&mut f.api, second.expose(), &policy)
            .await
            .is_err()
    );
    f.owner
        .execute("UPDATE openmettle.users SET disabled_at=NULL")
        .await
        .unwrap();
    f.owner.execute("UPDATE openmettle.local_identity_approvals SET active=false,revision=revision+1,access_generation=access_generation+1").await.unwrap();
    refused(&mut f).await;
    assert!(
        local::validate(&mut f.api, first.expose(), &policy)
            .await
            .is_err()
    );
    assert_eq!(account_state(&mut f).await.len(), accounts.len());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn stale_invitation_cannot_adopt_an_existing_identity_or_survive_revocation() {
    let mut f = Flow::new().await;
    invite(&f);
    seed(&mut f, false, true).await;
    let accounts = account_state(&mut f).await;
    refused(&mut f).await;
    assert_eq!(account_state(&mut f).await, accounts);
    assert!(withdraw(&f, ID).status.success()); // still unconsumed
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (_, stale) = f.exchanged(&p).await;
    open_write(&mut f.owner, Some("v1")).await;
    f.owner
        .execute("UPDATE openmettle.login_providers SET access_generation=access_generation+1")
        .await
        .unwrap();
    f.owner.execute("COMMIT").await.unwrap();
    assert!(matches!(
        p.issue_session(&mut f.api, stale, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
    refused(&mut f).await;
    empty(&mut f).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn first_session_blocked_at_insert_past_invitation_expiry_rolls_back_everything() {
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let mut observer = statistics_observer(&f.db).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let (_, proof) = f.exchanged(&p).await;
    f.owner.execute("UPDATE openmettle.home_invitations SET redeem_before_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+1000").await.unwrap();
    let mut held = f.owner.begin().await.unwrap();
    held.execute("LOCK TABLE openmettle.local_sessions IN SHARE MODE")
        .await
        .unwrap();
    let release = async {
        waiting(&mut observer, pid).await;
        held.execute("SELECT pg_sleep(GREATEST(0,redeem_before_ms/1000.0-extract(epoch FROM clock_timestamp()))) FROM openmettle.home_invitations").await.unwrap();
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(p.issue_session(&mut f.api, proof, &policy), release);
    assert!(matches!(result, Err(SessionError::Rejected)));
    empty(&mut f).await;
    refused(&mut f).await;
    assert!(withdraw(&f, ID).status.success());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn detached_redemption_cannot_commit_and_ambiguous_commit_cannot_replay() {
    use crate::response_barrier::{ResponseBarrier, cancel_at_response};
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let original = proof.origin.clone();
    let mut tx = f.api.begin().await.unwrap();
    let row: (String, String, i64) =
        sqlx::query_as("SELECT * FROM openmettle.redeem_home_invitation($1::uuid,$2,$3,$4,$5)")
            .bind(signing::ID)
            .bind(signing::ISSUER)
            .bind(SUBJECT)
            .bind(locator(&started))
            .bind(proof.epoch)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(row.2 > 0);
    let err = tx.commit().await.unwrap_err();
    assert!(
        matches!(err,sqlx::Error::Database(e) if e.message()=="home invitation requires current first session")
    );
    f.api = f.db.connect(API).await;
    empty(&mut f).await;
    // Lose acknowledgement after the server commits. No credential escapes cancellation.
    let mut barrier = ResponseBarrier::new(b"COMMIT\0");
    let options =
        f.db.options(API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    cancel_at_response(
        &mut barrier,
        p.issue_session(&mut cn, proof, &session_policy()),
    )
    .await;
    cn.close().await.unwrap();
    drop(barrier);
    let accounts = account_state(&mut f).await;
    assert_eq!(accounts.len(), 3);
    let login: String = sqlx::query_scalar(
        "SELECT login_id FROM openmettle.home_invitations WHERE approval_id IS NOT NULL",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(login, locator(&started));
    // Synthetic duplicate origin, impossible to construct through the production API.
    let (_, mut duplicate) = f.exchanged(&p).await;
    duplicate.origin = original;
    assert!(matches!(
        p.issue_session(&mut f.api, duplicate, &session_policy())
            .await,
        Err(SessionError::Rejected)
    ));
    issue(&mut f).await;
    assert_eq!(account_state(&mut f).await, accounts);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn operator_commands_refuse_wrong_authority_and_invalid_decisions() {
    let mut f = Flow::new().await;
    let vars = [
        ("invitation", ID),
        ("provider", signing::ID),
        ("issuer", signing::ISSUER),
        ("subject", SUBJECT),
        ("operator", OPERATOR),
        ("expected_generation", "0"),
    ];
    for role in [API, WORKER] {
        assert!(!command(&f, role, CREATE, &vars).status.success());
    }
    for (index, value) in [
        (0, "bad-uuid"),
        (2, "https://wrong.example.test"),
        (3, ""),
        (3, "non-ASCII-☀"),
        (5, "1"),
    ] {
        let mut invalid = vars;
        invalid[index].1 = value;
        assert!(!command(&f, OWNER, CREATE, &invalid).status.success());
    }
    for (redeem, approval) in [("1", "2"), ("999999999999999999", "1"), ("invalid", "1")] {
        let mut invalid = vars.to_vec();
        invalid.extend([
            ("redeem_before_ms", redeem),
            ("approval_until_ms", approval),
        ]);
        assert!(!command(&f, OWNER, CREATE, &invalid).status.success());
    }
    invite(&f);
    assert!(!create(&f, ID, signing::ID, "different").status.success());
    for role in [API, WORKER] {
        assert!(!command(&f, role, WITHDRAW, &vars).status.success());
    }
    assert!(withdraw(&f, ID).status.success());
    assert!(!withdraw(&f, ID).status.success());
    assert!(!create(&f, ID, signing::ID, SUBJECT).status.success());
    assert!(create(&f, OTHER, signing::ID, SUBJECT).status.success());
    // A stale withdrawal against the first record cannot cancel its replacement.
    assert!(!withdraw(&f, ID).status.success());
    issue(&mut f).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn identity_insert_racing_redemption_cannot_transfer_ownership() {
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let mut held = f.owner.begin().await.unwrap();
    // This independent writer's identity is invisible at the initial identity read.
    let existing: String =
        sqlx::query_scalar("INSERT INTO openmettle.users DEFAULT VALUES RETURNING id::text")
            .fetch_one(&mut *held)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.user_identities(user_id, issuer, subject) VALUES ($1::uuid,$2,$3)",
    )
    .bind(&existing)
    .bind(signing::ISSUER)
    .bind(SUBJECT)
    .execute(&mut *held)
    .await
    .unwrap();
    let release = async {
        waiting(&mut observer, pid).await;
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(p.issue_session(&mut f.api, proof, &policy), release);
    assert!(matches!(result, Err(SessionError::Rejected)));
    let accounts = account_state(&mut f).await;
    assert_eq!(accounts.len(), 2);
    let user: String = sqlx::query_scalar("SELECT user_id::text FROM openmettle.user_identities")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(user, existing);
    refused(&mut f).await;
    assert_eq!(account_state(&mut f).await, accounts);
    assert!(withdraw(&f, ID).status.success());
}
