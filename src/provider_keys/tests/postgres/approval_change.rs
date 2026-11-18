//! ADR 0013 approval change end to end: the unchanged operator script (run with the pinned
//! service psql, as in the schema suite) is the only approval writer between managed logins.
//! Stored-row effects, refusals and lock waits are covered in `tests/schema/approval_change.rs`.
use super::sessions::{account_state, issue, seed, session_policy};
use super::*;
use crate::sessions::{self as local, Error as SessionError};
use std::{collections::BTreeSet, io::Write, process::Output};

const SCRIPT: &str = include_str!("../../../../docs/operator/identity-approval-change.psql");

async fn db_ms(f: &mut Flow) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}
async fn sessions(f: &mut Flow) -> BTreeSet<String> {
    sqlx::query_scalar("SELECT to_jsonb(s)::text FROM openmettle.local_sessions s")
        .fetch_all(&mut f.owner)
        .await
        .unwrap()
        .into_iter()
        .collect()
}
/// Runs the script for the only approval and returns its output. Session rows are never written.
async fn run(f: &mut Flow, counters: (i64, i64), action: &str, lifetime_ms: i64) -> Output {
    let approval: String =
        sqlx::query_scalar("SELECT id::text FROM openmettle.local_identity_approvals")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let before = sessions(f).await;
    let (revision, generation, lifetime) = (
        counters.0.to_string(),
        counters.1.to_string(),
        lifetime_ms.to_string(),
    );
    let vars = [
        ("approval", approval.as_str()),
        ("expected_revision", revision.as_str()),
        ("expected_generation", generation.as_str()),
        ("action", action),
        ("fixture_lifetime_ms", lifetime.as_str()),
        ("actor", "fixture-operator"),
        ("reason", "synthetic approval change"),
    ];
    let mut child = psql::start(&f.db.name, OWNER, PASSWORD, &vars);
    // Compute the absolute expiry on the connected primary immediately before the exact
    // script runs. The short expiry case is independent of docker and psql startup time.
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint + :'fixture_lifetime_ms'::bigint AS expires_ms \\gset").unwrap();
    stdin.write_all(SCRIPT.as_bytes()).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(sessions(f).await, before, "no session row fan-out");
    out
}
async fn change(
    f: &mut Flow,
    counters: (i64, i64),
    action: &str,
    lifetime_ms: i64,
    new: (i64, i64),
) {
    let out = run(f, counters, action, lifetime_ms).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "approval change committed: revision {} access_generation {}\n",
            new.0, new.1
        )
    );
    assert!(out.stderr.is_empty(), "{stderr}");
}
async fn validate(f: &mut Flow, credential: &local::Credential) -> Result<(), SessionError> {
    local::validate(&mut f.api, credential.expose(), &session_policy())
        .await
        .map(|_| ())
}
async fn issuance_refused(f: &mut Flow) {
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    assert!(matches!(
        p.issue_session(&mut f.api, proof, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn approval_change_script_preserves_revokes_withdraws_and_restores_sessions() {
    let mut f = Flow::new().await;
    // Existing enabled user, identity, personal scope and approval (revision 1, generation 0).
    seed(&mut f, true, true).await;
    let accounts = account_state(&mut f).await;
    let first = issue(&mut f).await;
    validate(&mut f, &first).await.unwrap();

    // Routine edit: existing session stays valid.
    let extended = 900_000;
    change(&mut f, (1, 0), "routine", extended, (2, 0)).await;
    validate(&mut f, &first).await.unwrap();

    // Revoke: existing session invalid, eligibility retained for a fresh login.
    change(&mut f, (2, 0), "revoke", extended, (3, 1)).await;
    assert_eq!(validate(&mut f, &first).await, Err(SessionError::Rejected));
    let second = issue(&mut f).await;
    validate(&mut f, &second).await.unwrap();

    // Withdraw: existing session invalid and new issuance denied.
    change(&mut f, (3, 1), "withdraw", extended, (4, 2)).await;
    assert_eq!(validate(&mut f, &second).await, Err(SessionError::Rejected));
    issuance_refused(&mut f).await;

    // Restore: a fresh login is admitted; earlier credentials stay invalid.
    let restored = 600_000;
    change(&mut f, (4, 2), "restore", restored, (5, 3)).await;
    for old in [&first, &second] {
        assert_eq!(validate(&mut f, old).await, Err(SessionError::Rejected));
    }
    let third = issue(&mut f).await;
    validate(&mut f, &third).await.unwrap();

    // A routine edit can shorten the expiry; the session stays valid until it passes.
    change(&mut f, (5, 3), "routine", 1_200, (6, 3)).await;
    let cutoff: i64 =
        sqlx::query_scalar("SELECT expires_ms FROM openmettle.local_identity_approvals")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while db_ms(&mut f).await < cutoff {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("routine change must shorten the approval expiry");
    // Expired: the session no longer validates, issuance is denied and routine no longer
    // applies. Only restoration reapproves, with a new generation.
    assert_eq!(validate(&mut f, &third).await, Err(SessionError::Rejected));
    issuance_refused(&mut f).await;
    let later = 600_000;
    let out = run(&mut f, (6, 3), "routine", later).await;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("approval change refused: action does not apply to the approval's current state; no changes committed")
    );
    change(&mut f, (6, 3), "restore", later, (7, 4)).await;
    for old in [&first, &second, &third] {
        assert_eq!(validate(&mut f, old).await, Err(SessionError::Rejected));
    }
    let fourth = issue(&mut f).await;
    validate(&mut f, &fourth).await.unwrap();

    // Neither the script nor issuance created, linked or changed accounts, scopes or grants.
    assert_eq!(account_state(&mut f).await, accounts);
}
