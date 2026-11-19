//! Real operator commands and sealed online proofs against the isolated primary.
use super::sessions::{account_state, issue, seed, session_policy, statistics_observer, waiting};
use super::*;
use crate::{
    invitation::InvitationCode,
    sessions::{self as local, Error as SessionError},
};
use sha2::{Digest, Sha256};
use std::{io::Write, process::Output};

const CREATE: &str = include_str!("../../../../docs/operator/home-invitation-create.psql");
const WITHDRAW: &str = include_str!("../../../../docs/operator/home-invitation-withdraw.psql");
const ID: &str = "00000000-0000-0000-0000-000000000111";
pub(super) const OTHER: &str = "00000000-0000-0000-0000-000000000112";
const OPERATOR: &str = "00000000-0000-0000-0000-000000000113";
const FRESH: &str = "00000000-0000-0000-0000-000000000114";
const SUBJECT: &str = "synthetic-subject";
const CREATED: &str = "home invitation created\n";
const CODE_LINE: &str = "invitation code (shown once; deliver privately): ";
const SECOND: i64 = 1000;
const DAY: i64 = 86_400 * SECOND;

fn command(f: &Flow, role: &str, script: &str, vars: &[(&str, &str)]) -> Output {
    if vars.iter().any(|(name, _)| *name == "redeem_before_ms") {
        return run(f, role, script, vars, None);
    }
    run(f, role, script, vars, Some(600 * SECOND))
}
/// Runs an exact operator script. `window_ms` sets the redemption cutoff relative to primary
/// time, including in fixtures with skewed application clocks; the approval ends 5 min later.
fn run(
    f: &Flow,
    role: &str,
    script: &str,
    vars: &[(&str, &str)],
    window_ms: Option<i64>,
) -> Output {
    let mut child = psql::start(&f.db.name, role, PASSWORD, vars);
    let mut stdin = child.stdin.take().unwrap();
    if let Some(window) = window_ms {
        writeln!(stdin, "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + ({window}) AS redeem_before_ms, floor(extract(epoch FROM clock_timestamp())*1000)::bigint + ({window}) + 300000 AS approval_until_ms \\gset").unwrap();
    }
    stdin.write_all(script.as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}
pub(super) fn create(f: &Flow, id: &str, provider: &str, subject: &str) -> Output {
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
/// The intended fixed refusal, nothing on stdout, and no supplied value echoed back. Standard
/// output is never formatted into a failure message: it is where a code would appear.
fn refused_with(out: &Output, message: &str, vars: &[(&str, &str)]) {
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{text}");
    assert!(out.stdout.is_empty(), "a refused command wrote to stdout");
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
/// Direct API invocation of the owner function, outside the managed consumer. `code` is the
/// raw argument, so a caller can also pass NULL or a value of the wrong length.
async fn redeem_raw(
    c: &mut PgConnection,
    provider: &str,
    subject: &str,
    login: &str,
    epoch: i64,
    code: Option<&[u8]>,
) -> Option<(String, String, i64)> {
    sqlx::query_as("SELECT * FROM openmettle.redeem_home_invitation($1::uuid,$2,$3,$4,$5,$6)")
        .bind(provider)
        .bind(signing::ISSUER)
        .bind(subject)
        .bind(login)
        .bind(epoch)
        .bind(code)
        .fetch_optional(c)
        .await
        .unwrap()
}
pub(super) async fn redeem_direct(
    c: &mut PgConnection,
    provider: &str,
    login: &str,
    epoch: i64,
    code: &InvitationCode,
) -> Option<(String, String, i64)> {
    redeem_raw(c, provider, SUBJECT, login, epoch, Some(code.bytes())).await
}
fn first_session_refused(err: sqlx::Error) {
    assert!(
        matches!(&err, sqlx::Error::Database(e)
            if e.code().as_deref() == Some("P0001") && e.message() == FIRST_SESSION),
        "{err:?}"
    );
}
/// The code from a successful create: exactly the two documented lines, the second in the
/// display form. No assertion here formats stdout, so a failure never prints a code.
pub(super) fn created(out: &Output) -> InvitationCode {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let display = std::str::from_utf8(&out.stdout)
        .ok()
        .and_then(|text| text.strip_prefix(CREATED))
        .and_then(|line| line.strip_prefix(CODE_LINE))
        .and_then(|code| code.strip_suffix('\n'))
        .expect("create output is not the two documented lines");
    // omh1 and eight groups of four lowercase hexadecimal digits, joined by hyphens.
    let groups: Vec<&str> = display.split('-').collect();
    let hex = |group: &&str| {
        group.len() == 4
            && group
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    assert!(
        groups.len() == 9 && groups[0] == "omh1" && groups[1..].iter().all(hex),
        "the code is not in its display form"
    );
    // Decoded here independently of the parser the sign-in route uses.
    let decoded: Vec<u8> = groups[1..]
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let code = InvitationCode::parse(display).expect("the displayed code does not parse");
    assert!(
        code.bytes().as_slice() == decoded,
        "the parser decodes other bytes than the display form shows"
    );
    code
}
pub(super) fn invite(f: &Flow) -> InvitationCode {
    created(&create(f, ID, signing::ID, SUBJECT))
}
/// The hash the database stores for a code, computed here from the documented construction.
fn code_hash(code: &InvitationCode) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"openmettle/home-invitation-code/1\0");
    hash.update(code.bytes());
    hash.finalize().to_vec()
}
/// A fresh managed sign-in that presents `code` is refused.
async fn refused(f: &mut Flow, code: Option<&InvitationCode>) {
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged_with(&p, code).await;
    assert!(matches!(
        p.issue_session(&mut f.api, proof, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
}
/// A fresh managed sign-in that presents `code` receives a session.
async fn sign_in(f: &mut Flow, code: Option<&InvitationCode>) -> local::Credential {
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged_with(&p, code).await;
    p.issue_session(&mut f.api, proof, &session_policy())
        .await
        .unwrap()
}
/// Every invitation is still pending: not redeemed and not withdrawn.
pub(super) async fn pending(f: &mut Flow, expected: i64) {
    let rows: (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE approval_id IS NULL AND withdrawn_at IS NULL
                AND redeemed_at IS NULL AND login_id IS NULL)
           FROM openmettle.home_invitations",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(rows, (expected, expected));
}
pub(super) async fn empty(f: &mut Flow) {
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
    // Each sign-in presents the real code of the invitation under test, so only the named
    // mismatch can explain its refusal.
    for (id, provider, subject) in [
        (ID, OTHER, SUBJECT),
        (OTHER, signing::ID, "Synthetic-subject"),
    ] {
        let code = created(&create(&f, id, provider, subject));
        if provider == OTHER {
            create_refused(&f, OPERATOR, signing::ID, SUBJECT);
        }
        refused(&mut f, Some(&code)).await;
        assert!(withdraw(&f, id).status.success());
    }
    let withdrawn = created(&create(&f, OPERATOR, signing::ID, SUBJECT));
    assert!(withdraw(&f, OPERATOR).status.success());
    refused(&mut f, Some(&withdrawn)).await;
    empty(&mut f).await;
    // Control: the same sign-in redeems an exact pending invitation with its own code, and
    // an earlier invitation's code does not.
    let code = created(&create(&f, FRESH, signing::ID, SUBJECT));
    refused(&mut f, Some(&withdrawn)).await;
    empty(&mut f).await;
    sign_in(&mut f, Some(&code)).await;
    assert_eq!(account_state(&mut f).await.len(), 3);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn competing_first_proofs_consume_once_then_ordinary_approval_governs() {
    let mut f = Flow::new().await;
    let code = invite(&f);
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
    let (_, a) = f.exchanged_with(&p, Some(&code)).await;
    let (_, b) = f.exchanged_with(&p, Some(&code)).await;
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
    // The code is spent. A new consumed login cannot redeem it again through the function.
    let (replay, proof) = f.exchanged(&p).await;
    let mut tx = f.api.begin().await.unwrap();
    assert_eq!(
        redeem_direct(&mut tx, signing::ID, &locator(&replay), proof.epoch, &code).await,
        None
    );
    tx.rollback().await.unwrap();
    assert_eq!(account_state(&mut f).await, accounts);
    // Presented again at sign-in, it is ignored: the identity now exists.
    let second = sign_in(&mut f, Some(&code)).await;
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
    refused(&mut f, Some(&code)).await;
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
    refused(&mut f, Some(&code)).await;
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
    let code = invite(&f);
    seed(&mut f, false, true).await;
    let accounts = account_state(&mut f).await;
    refused(&mut f, Some(&code)).await;
    assert_eq!(account_state(&mut f).await, accounts);
    assert!(withdraw(&f, ID).status.success()); // still unconsumed
    let mut f = Flow::new().await;
    let code = invite(&f);
    let p = f.h.provider.clone();
    let (_, stale) = f.exchanged_with(&p, Some(&code)).await;
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
    refused(&mut f, Some(&code)).await;
    empty(&mut f).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn first_session_blocked_at_insert_past_invitation_expiry_rolls_back_everything() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    let p = f.h.provider.clone();
    let mut observer = statistics_observer(&f.db).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let (_, proof) = f.exchanged_with(&p, Some(&code)).await;
    cutoff_in(&mut f, CUTOFF_BUDGET_MS).await;
    let mut held = f.owner.begin().await.unwrap();
    held.execute("LOCK TABLE openmettle.local_sessions IN SHARE MODE")
        .await
        .unwrap();
    let policy = session_policy();
    let mut issuing = Box::pin(p.issue_session(&mut f.api, proof, &policy));
    // An issuance refused before the insert (cutoff already passed) fails here at once.
    tokio::select! {
        result = &mut issuing => panic!("issuance ended before its session insert blocked: {:?}", result.err()),
        () = waiting(&mut observer, pid) => {}
    }
    let release = async {
        held.execute("SELECT pg_sleep(GREATEST(0,redeem_before_ms/1000.0-extract(epoch FROM clock_timestamp()))) FROM openmettle.home_invitations").await.unwrap();
        held.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(issuing, release);
    assert!(matches!(result, Err(SessionError::Rejected)));
    empty(&mut f).await;
    refused(&mut f, Some(&code)).await;
    assert!(withdraw(&f, ID).status.success());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn detached_redemption_without_a_session_cannot_commit() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged_with(&p, Some(&code)).await;
    let login = locator(&started);
    let mut tx = f.api.begin().await.unwrap();
    let row = redeem_direct(&mut tx, signing::ID, &login, proof.epoch, &code)
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
    let code = invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let login = locator(&started);
    for marker in [false, true] {
        let mut tx = f.api.begin().await.unwrap();
        let (identity, user, _) = redeem_direct(&mut tx, signing::ID, &login, proof.epoch, &code)
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
        // Documented trust limit: API SQL that holds the code and writes both rows satisfies
        // the gate. The database cannot tell that no OIDC proof was verified.
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
    let code = invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged_with(&p, Some(&code)).await;
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
    let (_, mut duplicate) = f.exchanged_with(&p, Some(&code)).await;
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

/// Fixture-only triggers on the redemption's own write, with the production WHEN, so an
/// owner edit of the invitation (approval_id stays NULL) never fires them. Each advances a
/// sequence; nextval survives the rollback that follows, so the counters record which point
/// the refused transaction reached. SECURITY DEFINER and owned by the fixture owner, so the
/// role firing the trigger (API at COMMIT, the function owner inside the redemption) needs no
/// sequence privilege.
async fn redemption_fixture(f: &mut Flow, name: &str, deferred: bool, delay: bool) {
    let sleep = if delay {
        "PERFORM pg_sleep(GREATEST(0, NEW.redeem_before_ms / 1000.0
             - extract(epoch FROM clock_timestamp())) + 0.05);"
    } else {
        ""
    };
    let timing = if deferred {
        "CONSTRAINT TRIGGER"
    } else {
        "TRIGGER"
    };
    let deferral = if deferred {
        "DEFERRABLE INITIALLY DEFERRED"
    } else {
        ""
    };
    for sql in [
        format!("CREATE SEQUENCE openmettle.{name}"),
        format!(
            "CREATE FUNCTION openmettle.{name}() RETURNS trigger LANGUAGE plpgsql
             SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
             BEGIN PERFORM nextval('openmettle.{name}'); {sleep} RETURN NULL; END $$"
        ),
        format!(
            "CREATE {timing} {name} AFTER UPDATE ON openmettle.home_invitations {deferral}
             FOR EACH ROW WHEN (OLD.approval_id IS NULL AND NEW.approval_id IS NOT NULL)
             EXECUTE FUNCTION openmettle.{name}()"
        ),
    ] {
        f.owner.execute(AssertSqlSafe(sql)).await.unwrap();
    }
}
/// How many times the named fixture trigger fired, including in rolled-back transactions.
async fn fired(f: &mut Flow, name: &str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM openmettle.{name}"
    )))
    .fetch_one(&mut f.owner)
    .await
    .unwrap()
}
/// Time to pass the redemption time check, and the longest wait of a session insert held
/// until the cutoff. Leaves 500 ms under the 2 s issuance lock_timeout for the release.
pub(super) const CUTOFF_BUDGET_MS: i64 = 1500;
/// Primary time plus the given budget. The fixture triggers ignore this owner write.
pub(super) async fn cutoff_in(f: &mut Flow, budget_ms: i64) {
    sqlx::query("UPDATE openmettle.home_invitations SET redeem_before_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+$1")
        .bind(budget_ms)
        .execute(&mut f.owner)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn cutoff_passing_at_deferred_commit_is_a_definite_refusal() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    // Deferred, and named before home_redemption_session: on the same queued event it fires
    // first at COMMIT, records that COMMIT was reached and sleeps past the cutoff. Every
    // pre-commit time check, in the redemption and in Rust, has already passed by then.
    redemption_fixture(&mut f, "a_fixture_commit_delay", true, true).await;
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged_with(&p, Some(&code)).await;
    cutoff_in(&mut f, 1500).await;
    let started = std::time::Instant::now();
    let result = p.issue_session(&mut f.api, proof, &session_policy()).await;
    // Reached COMMIT exactly once; a pre-commit refusal never fires a deferred trigger.
    assert_eq!(fired(&mut f, "a_fixture_commit_delay").await, 1);
    // Only OMH01 from home_redemption_session maps to Rejected. Any other COMMIT failure,
    // including that error unmapped, is Database.
    assert_eq!(result.err(), Some(SessionError::Rejected));
    // The cutoff passed during the COMMIT sleep, not before issuance started.
    assert!(started.elapsed() >= Duration::from_millis(1400));
    empty(&mut f).await;
    // The connection was not discarded and remains usable for the next attempt. That
    // attempt is refused inside the redemption, which writes nothing and fires nothing.
    refused(&mut f, Some(&code)).await;
    assert_eq!(fired(&mut f, "a_fixture_commit_delay").await, 1);
    assert!(withdraw(&f, ID).status.success());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn cutoff_passing_after_redemption_is_refused_before_commit() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    // Immediate: runs inside the redemption's own UPDATE, after its time check, and sleeps
    // past the cutoff. Deferred: fires only if the transaction reaches COMMIT.
    redemption_fixture(&mut f, "fixture_redeemed", false, true).await;
    redemption_fixture(&mut f, "a_fixture_commit_reached", true, false).await;
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged_with(&p, Some(&code)).await;
    cutoff_in(&mut f, 1500).await;
    let result = p.issue_session(&mut f.api, proof, &session_policy()).await;
    assert_eq!(result.err(), Some(SessionError::Rejected));
    // The redemption passed its own time check and wrote the row, then the cutoff passed.
    assert_eq!(fired(&mut f, "fixture_redeemed").await, 1);
    // The Rust final check refused and rolled back. Without it the transaction would reach
    // COMMIT and be refused there by home_redemption_session instead.
    assert_eq!(fired(&mut f, "a_fixture_commit_reached").await, 0);
    empty(&mut f).await;
    refused(&mut f, Some(&code)).await;
    assert!(withdraw(&f, ID).status.success());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn redemption_requires_the_login_binding_of_the_supplied_provider_and_epoch() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let stale = locator(&started);
    // Routine revision: same configuration, new current epoch. The login stays bound to the old.
    let current = write(&mut f.owner, Some("v1")).await;
    let (fresh, _) = f.exchanged(&p).await;
    let mut tx = f.api.begin().await.unwrap();
    assert_eq!(
        redeem_direct(&mut tx, signing::ID, &stale, current, &code).await,
        None
    );
    assert_eq!(
        redeem_direct(&mut tx, signing::ID, &stale, proof.epoch, &code).await,
        None
    );
    // Control: the same call with a login bound to the current epoch redeems.
    assert!(
        redeem_direct(&mut tx, signing::ID, &locator(&fresh), current, &code)
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
    // The other provider's own invitation and code: only the login binding differs.
    let code = created(&create(&f, OPERATOR, OTHER, SUBJECT));
    let mut tx = f.api.begin().await.unwrap();
    assert_eq!(
        redeem_direct(&mut tx, OTHER, &locator(&fresh), other, &code).await,
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
    let code = invite(&f);
    write(&mut f.owner, Some("v1")).await;
    sign_in(&mut f, Some(&code)).await;
    assert_eq!(account_state(&mut f).await.len(), 3);

    // Legacy retirement (NULL revision, generation unchanged), then restoration.
    let mut f = Flow::new().await;
    let code = invite(&f);
    write(&mut f.owner, None).await;
    write(&mut f.owner, Some("v1")).await;
    let generation: i64 =
        sqlx::query_scalar("SELECT access_generation FROM openmettle.login_providers")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(generation, 0);
    refused(&mut f, Some(&code)).await;
    empty(&mut f).await;
    // The restored provider admits a decision made after the restoration.
    assert!(withdraw(&f, ID).status.success());
    let code = created(&create(&f, OTHER, signing::ID, SUBJECT));
    sign_in(&mut f, Some(&code)).await;
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
    let first = invite(&f);
    create_refused(&f, ID, signing::ID, "different-subject");
    for role in [API, WORKER] {
        refused_with(&command(&f, role, WITHDRAW, &vars), WITHDRAW_REFUSED, &vars);
    }
    assert!(withdraw(&f, ID).status.success());
    withdraw_refused(&f, ID);
    create_refused(&f, ID, signing::ID, SUBJECT);
    let code = created(&create(&f, OTHER, signing::ID, SUBJECT));
    // A stale withdrawal against the first record cannot cancel its replacement.
    withdraw_refused(&f, ID);
    // The withdrawn invitation's code is dead; the replacement's code redeems.
    refused(&mut f, Some(&first)).await;
    sign_in(&mut f, Some(&code)).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn identity_insert_racing_redemption_cannot_transfer_ownership() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged_with(&p, Some(&code)).await;
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
    refused(&mut f, Some(&code)).await;
    assert_eq!(account_state(&mut f).await, accounts);
    assert!(withdraw(&f, ID).status.success());
}

/// A consumed login that the API role fabricates with plain SQL: the exact managed binding of
/// the provider's current epoch, and no OIDC exchange behind it.
async fn fabricated_login(f: &mut Flow) -> (String, i64) {
    let epoch: i64 = sqlx::query_scalar(
        "SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id=$1::uuid",
    )
    .bind(signing::ID)
    .fetch_one(&mut f.api)
    .await
    .unwrap();
    let binding = persisted(&f.h.provider.config().unwrap().binding, None, epoch);
    let login = "f".repeat(43);
    f.api
        .execute(
            "INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
             VALUES ('fabricated', decode(repeat('01', 12), 'hex'))",
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.login_transactions
            (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext)
         VALUES ($1,$2,floor(extract(epoch FROM clock_timestamp())*1000)::bigint+60000,
                 decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),
                 decode(repeat('04',32),'hex'),'fabricated',decode(repeat('01',12),'hex'),
                 decode(repeat('00',59),'hex'))",
    )
    .bind(&login)
    .bind(&binding)
    .execute(&mut f.api)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.login_transactions SET consumed=true,ciphertext=NULL WHERE id=$1",
    )
    .bind(&login)
    .execute(&mut f.api)
    .await
    .unwrap();
    (login, epoch)
}

// ADR 0022 trust boundary. A principal limited to openmettle_api SQL can write every row the
// redemption function checks, but it cannot read or derive the code.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn api_sql_without_the_code_cannot_redeem_a_pending_invitation() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    let other = created(&create(&f, OTHER, signing::ID, "other-subject"));
    let (login, epoch) = fabricated_login(&mut f).await;

    // Neither the stored hash nor the code-less function is reachable.
    let state = |result: Result<(), sqlx::Error>| match result {
        Err(sqlx::Error::Database(e)) => e.code().map(|code| code.into_owned()),
        _ => None,
    };
    let unreadable = sqlx::query("SELECT code_hash FROM openmettle.home_invitations")
        .fetch_all(&mut f.api)
        .await;
    assert_eq!(state(unreadable.map(drop)).as_deref(), Some("42501"));
    let codeless =
        sqlx::query("SELECT * FROM openmettle.redeem_home_invitation($1::uuid,$2,$3,$4,$5)")
            .bind(signing::ID)
            .bind(signing::ISSUER)
            .bind(SUBJECT)
            .bind(&login)
            .bind(epoch)
            .fetch_all(&mut f.api)
            .await;
    assert_eq!(state(codeless.map(drop)).as_deref(), Some("42883"));

    let mut near = *code.bytes();
    near[15] ^= 1;
    let guesses: [(&str, Option<Vec<u8>>); 9] = [
        ("NULL", None),
        ("empty", Some(vec![])),
        ("15 bytes of the code", Some(code.bytes()[..15].to_vec())),
        (
            "the code and one more byte",
            Some([code.bytes().as_slice(), &[0]].concat()),
        ),
        ("16 zero bytes", Some(vec![0; 16])),
        ("16 arbitrary bytes", Some(vec![0x5a; 16])),
        ("the code with one bit changed", Some(near.to_vec())),
        ("another invitation's code", Some(other.bytes().to_vec())),
        ("the stored hash", Some(code_hash(&code))),
    ];
    for (guess, value) in &guesses {
        let mut tx = f.api.begin().await.unwrap();
        let row = redeem_raw(
            &mut tx,
            signing::ID,
            SUBJECT,
            &login,
            epoch,
            value.as_deref(),
        )
        .await;
        assert_eq!(row, None, "{guess}");
        // Nothing was written, so the commit gate has nothing to refuse.
        tx.commit().await.unwrap();
    }
    empty(&mut f).await;
    pending(&mut f, 2).await;

    // Control: the same fabricated login redeems once the code is supplied. Every refusal
    // above was therefore caused by the code alone.
    let mut tx = f.api.begin().await.unwrap();
    assert!(
        redeem_direct(&mut tx, signing::ID, &login, epoch, &code)
            .await
            .is_some()
    );
    tx.rollback().await.unwrap();
    empty(&mut f).await;
    pending(&mut f, 2).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn the_correct_code_cannot_redeem_a_closed_or_fenced_invitation() {
    for state in [
        "withdrawn",
        "expired",
        "generation",
        "retirement",
        "redeemed",
    ] {
        let mut f = Flow::new().await;
        let code = invite(&f);
        let p = f.h.provider.clone();
        // Control: before the change, a consumed login and this code redeem.
        let (started, proof) = f.exchanged(&p).await;
        let mut tx = f.api.begin().await.unwrap();
        assert!(
            redeem_direct(&mut tx, signing::ID, &locator(&started), proof.epoch, &code)
                .await
                .is_some(),
            "{state}"
        );
        tx.rollback().await.unwrap();
        match state {
            "withdrawn" => assert!(withdraw(&f, ID).status.success()),
            "expired" => {
                f.owner.execute("UPDATE openmettle.home_invitations SET redeem_before_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint").await.unwrap();
            }
            "generation" => {
                f.owner
                    .execute(
                        "UPDATE openmettle.login_providers SET access_generation=access_generation+1",
                    )
                    .await
                    .unwrap();
            }
            "retirement" => {
                write(&mut f.owner, None).await;
                write(&mut f.owner, Some("v1")).await;
            }
            _ => drop(sign_in(&mut f, Some(&code)).await),
        }
        // A new consumed login under the current epoch, with the correct code.
        let (started, proof) = f.exchanged(&p).await;
        let mut tx = f.api.begin().await.unwrap();
        assert_eq!(
            redeem_direct(&mut tx, signing::ID, &locator(&started), proof.epoch, &code).await,
            None,
            "{state}"
        );
        tx.rollback().await.unwrap();
        if state == "redeemed" {
            assert_eq!(account_state(&mut f).await.len(), 3);
        } else {
            refused(&mut f, Some(&code)).await;
            empty(&mut f).await;
        }
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn an_existing_identity_signs_in_as_before_whatever_code_it_presents() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    let wrong = InvitationCode::parse(&"5a".repeat(16)).unwrap();
    // The identity appears after the invitation, already approved by the owner.
    let user = seed(&mut f, true, true).await;
    let accounts = account_state(&mut f).await;
    let policy = session_policy();
    for presented in [None, Some(&code), Some(&wrong)] {
        let credential = sign_in(&mut f, presented).await;
        let context = local::validate(&mut f.api, credential.expose(), &policy)
            .await
            .unwrap();
        assert_eq!(context.user_id(), user);
    }
    // Ordinary sessions for the one existing account. The code was never evaluated.
    assert_eq!(account_state(&mut f).await, accounts);
    pending(&mut f, 1).await;
    let approvals: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.local_identity_approvals")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(approvals, 1);

    // A disabled account stays refused, and the correct code creates no second account.
    local::disable_user(&mut f.api, &user, 0, &policy)
        .await
        .unwrap();
    let disabled = account_state(&mut f).await;
    refused(&mut f, Some(&code)).await;
    assert_eq!(account_state(&mut f).await, disabled);
    pending(&mut f, 1).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn a_missing_identity_without_a_code_is_refused_and_writes_nothing() {
    let mut f = Flow::new().await;
    let code = invite(&f);
    refused(&mut f, None).await;
    empty(&mut f).await;
    pending(&mut f, 1).await;
    // Control: the invitation was redeemable throughout.
    sign_in(&mut f, Some(&code)).await;
    assert_eq!(account_state(&mut f).await.len(), 3);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn create_command_prints_one_code_once_and_stores_only_its_hash() {
    let mut f = Flow::new().await;
    let vars = |id: &'static str, subject: &'static str| {
        [
            ("invitation", id),
            ("provider", signing::ID),
            ("issuer", signing::ISSUER),
            ("subject", subject),
            ("operator", OPERATOR),
            ("expected_generation", "0"),
        ]
    };
    let rows = async |f: &mut Flow| -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM openmettle.home_invitations")
            .fetch_one(&mut f.owner)
            .await
            .unwrap()
    };
    // A window that is past, or longer than seven days, is refused. The insert rolls back
    // and nothing is printed.
    for window in [-SECOND, 7 * DAY + 60 * SECOND, 30 * DAY] {
        let out = run(&f, OWNER, CREATE, &vars(ID, SUBJECT), Some(window));
        refused_with(&out, CREATE_REFUSED, &vars(ID, SUBJECT));
    }
    assert_eq!(rows(&mut f).await, 0);

    // Just inside the cap, and the default ten minutes. `created` checks the two lines.
    let first = created(&run(
        &f,
        OWNER,
        CREATE,
        &vars(ID, SUBJECT),
        Some(7 * DAY - 60 * SECOND),
    ));
    let second = created(&create(&f, OTHER, signing::ID, "other-subject"));
    assert!(
        first.bytes() != second.bytes(),
        "two invitations received the same code"
    );
    let stored: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT id::text, code_hash FROM openmettle.home_invitations ORDER BY id")
            .fetch_all(&mut f.owner)
            .await
            .unwrap();
    assert!(
        stored
            == [
                (ID.to_owned(), code_hash(&first)),
                (OTHER.to_owned(), code_hash(&second))
            ],
        "the stored hashes are not sha256(domain, 0x00, code)"
    );
    // The hash is the only trace: no column holds the code as bytes or as text.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.home_invitations t
          WHERE position(encode($1, 'hex') IN to_jsonb(t)::text) > 0",
    )
    .bind(first.bytes().as_slice())
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(leaked, 0);

    // An occupied UUID and an outstanding invitation for the same principal print nothing.
    create_refused(&f, ID, signing::ID, SUBJECT);
    create_refused(&f, FRESH, signing::ID, SUBJECT);
    assert_eq!(rows(&mut f).await, 2);
    // The printed code redeems its own invitation.
    sign_in(&mut f, Some(&first)).await;
    assert_eq!(account_state(&mut f).await.len(), 3);
}

// A login sealed in the aes256gcm-v1 format on schema 12 is still in flight when migration 13
// replaces the ciphertext check. It completes for an existing approved identity.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn login_started_on_schema_12_completes_after_the_upgrade() {
    let h = Harness::new().await;
    let db = Db::at(&migrate::MIGRATIONS[..12]).await;
    let api = db.connect(API).await;
    let mut owner = db.connect(OWNER).await;
    add_provider(&mut owner, signing::ISSUER, signing::CLIENT, "v1").await;
    admit(&mut owner, Some(64)).await;
    let mut f = Flow { h, db, api, owner };
    let user = seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    // The current 76-byte format does not pass the schema-12 check: a current start is
    // refused there and leaves no login. The fixture therefore seals this login exactly as
    // the previous release did.
    assert_eq!(
        p.begin(&mut f.api, &keys(), Duration::from_secs(300), None)
            .await
            .map(drop),
        Err(login::Error::Database)
    );
    f.api = f.db.connect(API).await;
    assert_eq!(f.rows().await, 0);
    p.fresh().await.unwrap();
    let previous = p
        .login_provider(Instant::now() + Duration::from_secs(5))
        .unwrap();
    let started = login::begin_v1(&mut f.api, &previous, &keys(), Duration::from_secs(300))
        .await
        .unwrap();
    let sealed = async |f: &mut Flow, started: &Started| -> i32 {
        sqlx::query_scalar(
            "SELECT octet_length(ciphertext) FROM openmettle.login_transactions WHERE id = $1",
        )
        .bind(locator(started))
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
    };
    assert_eq!(sealed(&mut f, &started).await, 59);
    f.db.upgrade(migrate::MIGRATIONS).await;
    f.arm(&started);
    let proof = f
        .consume(&p, &started)
        .await
        .unwrap()
        .exchange_with_keys(&p, &auth::Policy::default())
        .await
        .unwrap();
    let credential = p
        .issue_session(&mut f.api, proof, &session_policy())
        .await
        .unwrap();
    let context = local::validate(&mut f.api, credential.expose(), &session_policy())
        .await
        .unwrap();
    assert_eq!(context.user_id(), user);
    // A login started after the upgrade is sealed in the current format.
    let next = f.begin(&p).await;
    assert_eq!(sealed(&mut f, &next).await, 76);
}
