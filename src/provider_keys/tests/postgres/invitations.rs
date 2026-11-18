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
const CREATE_REFUSED: &str = "home invitation creation refused";
const WITHDRAW_REFUSED: &str = "home invitation withdrawal refused";
const FIRST_SESSION: &str = "home invitation requires current first session";
/// The intended fixed refusal, nothing on stdout, and no supplied value echoed back.
fn refused_with(out: &Output, message: &str, vars: &[(&str, &str)]) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(out.stdout.is_empty(), "{text}");
    assert!(text.contains(message), "{text}");
    for (name, value) in vars {
        if value.len() >= 8 {
            assert!(!text.contains(value), "output repeats {name}");
        }
    }
    for value in [SUBJECT, signing::ISSUER, signing::ID, OPERATOR] {
        assert!(!text.contains(value), "output repeats an input value");
    }
}
fn create_refused(f: &Flow, id: &str, provider: &str, subject: &str) {
    let out = create(f, id, provider, subject);
    refused_with(
        &out,
        CREATE_REFUSED,
        &[
            ("invitation", id),
            ("provider", provider),
            ("subject", subject),
        ],
    );
}
fn withdraw_refused(f: &Flow, id: &str) {
    refused_with(&withdraw(f, id), WITHDRAW_REFUSED, &[("invitation", id)]);
}
/// Direct API invocation of the owner function, outside the managed consumer.
async fn redeem_direct(
    c: &mut PgConnection,
    provider: &str,
    login: &str,
    epoch: i64,
) -> Option<(String, String, i64)> {
    sqlx::query_as("SELECT * FROM openmettle.redeem_home_invitation($1::uuid,$2,$3,$4,$5)")
        .bind(provider)
        .bind(signing::ISSUER)
        .bind(SUBJECT)
        .bind(login)
        .bind(epoch)
        .fetch_optional(c)
        .await
        .unwrap()
}
fn first_session_refused(err: sqlx::Error) {
    assert!(
        matches!(&err, sqlx::Error::Database(e)
            if e.code().as_deref() == Some("P0001") && e.message() == FIRST_SESSION),
        "{err:?}"
    );
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
            create_refused(&f, OPERATOR, signing::ID, SUBJECT);
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
    // The first session is valid immediately before the refused withdrawal and after it.
    local::validate(&mut f.api, first.expose(), &policy)
        .await
        .unwrap();
    withdraw_refused(&f, ID);
    assert_eq!(
        local::validate(&mut f.api, first.expose(), &policy)
            .await
            .unwrap()
            .user_id(),
        context.user_id()
    );
    create_refused(&f, OTHER, signing::ID, SUBJECT);
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
async fn detached_redemption_without_a_session_cannot_commit() {
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let login = locator(&started);
    let mut tx = f.api.begin().await.unwrap();
    let row = redeem_direct(&mut tx, signing::ID, &login, proof.epoch)
        .await
        .unwrap();
    assert!(row.2 > 0);
    // The issued marker is present; only the session row is missing.
    sqlx::query("UPDATE openmettle.login_transactions SET session_issued=true WHERE id=$1")
        .bind(&login)
        .execute(&mut *tx)
        .await
        .unwrap();
    first_session_refused(tx.commit().await.unwrap_err());
    empty(&mut f).await;
    // The server rolled back; the same proof still redeems through the managed path.
    p.issue_session(&mut f.api, proof, &session_policy())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn detached_redemption_without_the_issued_marker_cannot_commit() {
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let login = locator(&started);
    for marker in [false, true] {
        let mut tx = f.api.begin().await.unwrap();
        let (identity, user, _) = redeem_direct(&mut tx, signing::ID, &login, proof.epoch)
            .await
            .unwrap();
        let approval: String = sqlx::query_scalar(
            "SELECT id::text FROM openmettle.local_identity_approvals WHERE identity_id=$1::uuid",
        )
        .bind(&identity)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query("INSERT INTO openmettle.local_sessions (id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms)
            SELECT repeat('A',43),decode(repeat('00',32),'hex'),$1,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,1,0,0,0,t,t+60000
            FROM (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS t) now")
            .bind(&login).bind(signing::ID).bind(&identity).bind(&approval).bind(&user)
            .bind(signing::CLIENT).bind(proof.epoch)
            .execute(&mut *tx).await.unwrap();
        if !marker {
            // The session row is present; only the issued marker is missing.
            first_session_refused(tx.commit().await.unwrap_err());
            empty(&mut f).await;
            continue;
        }
        // Documented trust limit: arbitrary API SQL that writes both rows satisfies the gate.
        // The database cannot tell that no OIDC proof was verified.
        sqlx::query("UPDATE openmettle.login_transactions SET session_issued=true WHERE id=$1")
            .bind(&login)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(account_state(&mut f).await.len(), 3);
    let consumed: String = sqlx::query_scalar(
        "SELECT login_id FROM openmettle.home_invitations WHERE approval_id IS NOT NULL",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(consumed, login);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn ambiguous_first_session_commit_cannot_replay() {
    use crate::response_barrier::{ResponseBarrier, cancel_at_response};
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let original = proof.origin.clone();
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
async fn cutoff_passing_at_deferred_commit_is_a_definite_refusal() {
    let mut f = Flow::new().await;
    invite(&f);
    // Fixture-only deferred trigger. Same event, earlier name: it fires first at COMMIT and
    // sleeps past the cutoff, after the final pre-commit time check has already passed.
    f.owner
        .execute(
            "CREATE FUNCTION openmettle.fixture_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN PERFORM pg_sleep(GREATEST(0, NEW.redeem_before_ms / 1000.0
                 - extract(epoch FROM clock_timestamp())) + 0.05); RETURN NULL; END $$",
        )
        .await
        .unwrap();
    f.owner
        .execute(
            "CREATE CONSTRAINT TRIGGER a_fixture_commit_delay AFTER UPDATE ON openmettle.home_invitations
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openmettle.fixture_commit_delay()",
        )
        .await
        .unwrap();
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    let started = std::time::Instant::now();
    f.owner.execute("UPDATE openmettle.home_invitations SET redeem_before_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+1500").await.unwrap();
    let result = p.issue_session(&mut f.api, proof, &session_policy()).await;
    assert_eq!(result.err(), Some(SessionError::Rejected));
    // Only a transaction that reached COMMIT sleeps; a pre-commit refusal returns at once.
    assert!(started.elapsed() >= Duration::from_millis(1500));
    empty(&mut f).await;
    // The connection was not discarded and remains usable for the next attempt.
    refused(&mut f).await;
    assert!(withdraw(&f, ID).status.success());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn redemption_requires_the_login_binding_of_the_supplied_provider_and_epoch() {
    let mut f = Flow::new().await;
    invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let stale = locator(&started);
    // Routine revision: same configuration, new current epoch. The login stays bound to the old.
    let current = write(&mut f.owner, Some("v1")).await;
    let (fresh, _) = f.exchanged(&p).await;
    let mut tx = f.api.begin().await.unwrap();
    assert_eq!(
        redeem_direct(&mut tx, signing::ID, &stale, current).await,
        None
    );
    assert_eq!(
        redeem_direct(&mut tx, signing::ID, &stale, proof.epoch).await,
        None
    );
    // Control: the same call with a login bound to the current epoch redeems.
    assert!(
        redeem_direct(&mut tx, signing::ID, &locator(&fresh), current)
            .await
            .is_some()
    );
    tx.rollback().await.unwrap();
    // A second provider configuration with the same issuer, client and revision.
    sqlx::query(
        "INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason)
        VALUES ($1::uuid,$2,$3,'fixture','cross-wiring')",
    )
    .bind(OTHER)
    .bind(signing::ISSUER)
    .bind(signing::CLIENT)
    .execute(&mut f.owner)
    .await
    .unwrap();
    let other: i64 = sqlx::query_scalar(APPEND)
        .bind(OTHER)
        .bind("v1")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert!(withdraw(&f, ID).status.success());
    assert!(create(&f, OPERATOR, OTHER, SUBJECT).status.success());
    let mut tx = f.api.begin().await.unwrap();
    assert_eq!(
        redeem_direct(&mut tx, OTHER, &locator(&fresh), other).await,
        None
    );
    tx.rollback().await.unwrap();
    empty(&mut f).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn retirement_after_creation_fences_invitation_but_routine_revision_does_not() {
    // Control: a routine revision after creation preserves the decision.
    let mut f = Flow::new().await;
    invite(&f);
    write(&mut f.owner, Some("v1")).await;
    issue(&mut f).await;
    assert_eq!(account_state(&mut f).await.len(), 3);

    // Legacy retirement (NULL revision, generation unchanged), then restoration.
    let mut f = Flow::new().await;
    invite(&f);
    write(&mut f.owner, None).await;
    write(&mut f.owner, Some("v1")).await;
    let generation: i64 =
        sqlx::query_scalar("SELECT access_generation FROM openmettle.login_providers")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(generation, 0);
    refused(&mut f).await;
    empty(&mut f).await;
    // The restored provider admits a decision made after the restoration.
    assert!(withdraw(&f, ID).status.success());
    assert!(create(&f, OTHER, signing::ID, SUBJECT).status.success());
    issue(&mut f).await;
    assert_eq!(account_state(&mut f).await.len(), 3);
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
        refused_with(&command(&f, role, CREATE, &vars), CREATE_REFUSED, &vars);
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
        refused_with(
            &command(&f, OWNER, CREATE, &invalid),
            CREATE_REFUSED,
            &invalid,
        );
    }
    for (redeem, approval) in [("1", "2"), ("999999999999999999", "1"), ("invalid", "1")] {
        let mut invalid = vars.to_vec();
        invalid.extend([
            ("redeem_before_ms", redeem),
            ("approval_until_ms", approval),
        ]);
        refused_with(
            &command(&f, OWNER, CREATE, &invalid),
            CREATE_REFUSED,
            &invalid,
        );
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.home_invitations")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    invite(&f);
    create_refused(&f, ID, signing::ID, "different-subject");
    for role in [API, WORKER] {
        refused_with(&command(&f, role, WITHDRAW, &vars), WITHDRAW_REFUSED, &vars);
    }
    assert!(withdraw(&f, ID).status.success());
    withdraw_refused(&f, ID);
    create_refused(&f, ID, signing::ID, SUBJECT);
    assert!(create(&f, OTHER, signing::ID, SUBJECT).status.success());
    // A stale withdrawal against the first record cannot cancel its replacement.
    withdraw_refused(&f, ID);
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
