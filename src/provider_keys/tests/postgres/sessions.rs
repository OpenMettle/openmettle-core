//! Full managed synthetic TLS → primary PostgreSQL → local approval/session path.
use super::*;
use crate::response_barrier::{ResponseBarrier, cancel_at_response};
use crate::sessions::{self as local, Error as SessionError};
use std::{collections::BTreeSet, io::Write};

pub(super) fn session_policy() -> local::Policy {
    local::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(10)).unwrap()
}
pub(super) async fn seed(f: &mut Flow, approved: bool, scope: bool) -> String {
    let user: String =
        sqlx::query_scalar("INSERT INTO openmettle.users DEFAULT VALUES RETURNING id::text")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let identity: String = sqlx::query_scalar("INSERT INTO openmettle.user_identities(user_id,issuer,subject) VALUES ($1::uuid,$2,'synthetic-subject') RETURNING id::text")
        .bind(&user).bind(signing::ISSUER).fetch_one(&mut f.owner).await.unwrap();
    if scope {
        sqlx::query(
            "INSERT INTO openmettle.scopes(kind,personal_user_id) VALUES ('personal',$1::uuid)",
        )
        .bind(&user)
        .execute(&mut f.owner)
        .await
        .unwrap();
    }
    if approved {
        sqlx::query("INSERT INTO openmettle.local_identity_approvals(provider_id,identity_id,active,expires_ms,changed_by,change_reason) VALUES ($1::uuid,$2::uuid,true,floor(extract(epoch FROM clock_timestamp())*1000)::bigint+600000,'fixture-owner','synthetic approval')")
            .bind(signing::ID).bind(identity).execute(&mut f.owner).await.unwrap();
    }
    user
}
pub(super) async fn issue(f: &mut Flow) -> local::Credential {
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    p.issue_session(&mut f.api, proof, &session_policy())
        .await
        .unwrap()
}
// Caller holds the stable provider row FOR UPDATE in this transaction. Generation and
// a fresh epoch commit together, including explicit revoke with an unchanged revision.
async fn revoke_locked(owner: &mut PgConnection, revision: Option<&str>) -> i64 {
    sqlx::query("UPDATE openmettle.login_providers SET access_generation=access_generation+1,changed_by='fixture-owner',change_reason='explicit revoke or retire',changed_at=clock_timestamp() WHERE id=$1::uuid")
        .bind(signing::ID).execute(&mut *owner).await.unwrap();
    let epoch = sqlx::query_scalar(APPEND)
        .bind(signing::ID)
        .bind(revision)
        .fetch_one(&mut *owner)
        .await
        .unwrap();
    assert!(is_current(owner, epoch).await);
    epoch
}
async fn revoke_provider(owner: &mut PgConnection, revision: Option<&str>) -> i64 {
    let mut tx = owner.begin().await.unwrap();
    for sql in [
        "SET LOCAL lock_timeout='2s'",
        "SET LOCAL statement_timeout='5s'",
        "SET LOCAL synchronous_commit=on",
    ] {
        sqlx::query(sql).execute(&mut *tx).await.unwrap();
    }
    sqlx::query(LOCK)
        .bind(signing::ID)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let epoch = revoke_locked(&mut tx, revision).await;
    tx.commit().await.unwrap();
    epoch
}
async fn session_count(f: &mut Flow) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions")
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}
async fn write(f: &mut Flow, sql: &'static str) {
    f.owner.execute(sql).await.unwrap();
}
// pg_stat_activity hides other roles' wait details from openmettle_owner. Use the
// existing isolated-fixture administrator solely for observation, never the operation.
pub(super) async fn statistics_observer(db: &Db) -> PgConnection {
    PgConnection::connect_with(&admin_options().database(&db.name))
        .await
        .unwrap()
}
pub(super) async fn waiting(observer: &mut PgConnection, pid: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(&mut *observer).await.unwrap();
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn routine_changes_preserve_sessions_and_explicit_revocations_do_not_revive() {
    let mut f = Flow::new().await;
    let user = seed(&mut f, true, true).await;
    let credential = issue(&mut f).await;
    let requests = f.h.count();
    let context = local::validate(&mut f.api, credential.expose(), &session_policy())
        .await
        .unwrap();
    assert_eq!(context.user_id(), user);
    // Routine provider revision and approval revision retain access generations.
    open_write(&mut f.owner, Some("v2")).await;
    f.owner.execute("COMMIT").await.unwrap();
    write(&mut f,"UPDATE openmettle.local_identity_approvals SET revision=revision+1,change_reason='routine extension',expires_ms=expires_ms+1000").await;
    local::validate(&mut f.api, credential.expose(), &session_policy())
        .await
        .unwrap();
    assert_eq!(
        f.h.count(),
        requests,
        "local validation must not fetch provider documents"
    );
    revoke_provider(&mut f.owner, Some("v2")).await;
    assert!(
        local::validate(&mut f.api, credential.expose(), &session_policy())
            .await
            .is_err()
    );
    // Revert config with another epoch; restoring the old revision never resets generation.
    open_write(&mut f.owner, Some("v1")).await;
    f.owner.execute("COMMIT").await.unwrap();
    assert!(
        local::validate(&mut f.api, credential.expose(), &session_policy())
            .await
            .is_err()
    );
    for action in ["retire", "withdraw", "disable"] {
        let credential = issue(&mut f).await;
        let logout_target = issue(&mut f).await;
        match action {
            "retire" => {
                revoke_provider(&mut f.owner,None).await;
            },
            "withdraw" => write(&mut f,"UPDATE openmettle.local_identity_approvals SET active=false,revision=revision+1,access_generation=access_generation+1").await,
            _ => local::disable_user(&mut f.api,&user,0,&session_policy()).await.unwrap(),
        }
        assert!(
            local::validate(&mut f.api, credential.expose(), &session_policy())
                .await
                .is_err()
        );
        // Logout uses credential possession alone, even after eligibility is lost.
        local::logout(&mut f.api, logout_target.expose(), &session_policy())
            .await
            .unwrap();
        match action {
            "retire" => {
                open_write(&mut f.owner, Some("v1")).await;
                f.owner.execute("COMMIT").await.unwrap();
            }
            "withdraw" => write(
                &mut f,
                "UPDATE openmettle.local_identity_approvals SET active=true,revision=revision+1,access_generation=access_generation+1",
            )
            .await,
            _ => write(&mut f, "UPDATE openmettle.users SET disabled_at=NULL").await,
        }
        assert!(
            local::validate(&mut f.api, credential.expose(), &session_policy())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn unknown_unapproved_disabled_and_missing_scope_never_provision() {
    for condition in ["unknown", "unapproved", "disabled", "scope"] {
        let mut f = Flow::new().await;
        if condition != "unknown" {
            seed(&mut f, condition != "unapproved", condition != "scope").await;
        }
        if condition == "disabled" {
            write(
                &mut f,
                "UPDATE openmettle.users SET disabled_at=clock_timestamp()",
            )
            .await;
        }
        let before: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM openmettle.users),(SELECT count(*) FROM openmettle.user_identities),(SELECT count(*) FROM openmettle.scopes),(SELECT count(*) FROM openmettle.grant_assignments)").fetch_one(&mut f.owner).await.unwrap();
        let p = f.h.provider.clone();
        let (_, proof) = f.exchanged(&p).await;
        assert!(matches!(
            p.issue_session(&mut f.api, proof, &session_policy()).await,
            Err(SessionError::Rejected)
        ));
        let after=sqlx::query_as::<_,(i64,i64,i64,i64)>("SELECT (SELECT count(*) FROM openmettle.users),(SELECT count(*) FROM openmettle.user_identities),(SELECT count(*) FROM openmettle.scopes),(SELECT count(*) FROM openmettle.grant_assignments)").fetch_one(&mut f.owner).await.unwrap();
        assert_eq!(before, after);
        assert_eq!(session_count(&mut f).await, 0);
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn gate_binding_and_replay_survive_session_cleanup() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    let origin = proof.origin.clone();
    let credential = p
        .issue_session(&mut f.api, proof, &session_policy())
        .await
        .unwrap();
    local::logout(&mut f.api, credential.expose(), &session_policy())
        .await
        .unwrap();
    write(
        &mut f,
        "DELETE FROM openmettle.local_sessions WHERE revoked",
    )
    .await;
    for absent in [false, true] {
        if absent {
            sqlx::query("DELETE FROM openmettle.login_transactions WHERE id=$1")
                .bind(&origin.as_ref().unwrap().0)
                .execute(&mut f.owner)
                .await
                .unwrap();
        }
        let (_, mut duplicate) = f.exchanged(&p).await;
        // Synthetic duplicate only inside cfg(test); production proof is sealed/non-cloneable.
        duplicate.origin = origin.clone();
        assert!(matches!(
            p.issue_session(&mut f.api, duplicate, &session_policy())
                .await,
            Err(SessionError::Rejected)
        ));
        assert_eq!(session_count(&mut f).await, 0);
    }
    for tamper in ["binding", "expiry", "unconsumed"] {
        let (started, proof) = f.exchanged(&p).await;
        let sql = match tamper {
            "binding" => {
                "UPDATE openmettle.login_transactions SET binding='tampered'::bytea WHERE id=$1"
            }
            "expiry" => {
                "UPDATE openmettle.login_transactions SET expires_ms=expires_ms+1 WHERE id=$1"
            }
            _ => {
                "UPDATE openmettle.login_transactions SET consumed=false,ciphertext=decode(repeat('00',59),'hex') WHERE id=$1"
            }
        };
        sqlx::query(sql)
            .bind(locator(&started))
            .execute(&mut f.owner)
            .await
            .unwrap();
        assert!(
            p.issue_session(&mut f.api, proof, &session_policy())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn retained_cap_serializes_and_sqlx_caller_transaction_is_preserved() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let (_, a) = f.exchanged(&p).await;
    let (_, b) = f.exchanged(&p).await;
    let mut second = f.db.connect(API).await;
    let policy = local::Policy::new(Duration::from_secs(60), 1, Duration::from_secs(10)).unwrap();
    let (a, b) = tokio::join!(
        p.issue_session(&mut f.api, a, &policy),
        p.issue_session(&mut second, b, &policy)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let credential = match (a, b) {
        (Ok(c), Err(SessionError::Capacity)) | (Err(SessionError::Capacity), Ok(c)) => c,
        _ => panic!("unexpected cap outcome"),
    };
    local::logout(&mut f.api, credential.expose(), &policy)
        .await
        .unwrap();
    let (_, proof) = f.exchanged(&p).await;
    assert!(
        matches!(
            p.issue_session(&mut f.api, proof, &policy).await,
            Err(SessionError::Capacity)
        ),
        "revoked retained rows still count"
    );
    let (_, proof) = f.exchanged(&p).await;
    let mut outer = f.api.begin().await.unwrap();
    assert!(matches!(
        p.issue_session(&mut outer, proof, &policy).await,
        Err(SessionError::Rejected)
    ));
    assert!(outer.is_in_transaction());
    outer.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn precommit_cancellation_and_unknown_commit_release_no_credential() {
    for (command, committed) in [
        (b"INSERT 0 1\0".as_slice(), false),
        (b"COMMIT\0".as_slice(), true),
    ] {
        let mut f = Flow::new().await;
        seed(&mut f, true, true).await;
        let p = f.h.provider.clone();
        let (started, proof) = f.exchanged(&p).await;
        let mut barrier = ResponseBarrier::new(command);
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
        assert_eq!(session_count(&mut f).await, i64::from(committed));
        let issued: bool = sqlx::query_scalar(
            "SELECT session_issued FROM openmettle.login_transactions WHERE id=$1",
        )
        .bind(locator(&started))
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
        assert_eq!(issued, committed);
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn postcommit_ack_delay_rechecks_proof_and_database() {
    for change in ["token-expiry", "local-expiry", "revoke", "deadline"] {
        let mut f = Flow::new().await;
        seed(&mut f, true, true).await;
        f.h.script.lock().unwrap().cache = "max-age=1000".into();
        f.h.script.lock().unwrap().metadata_cache = "max-age=1000".into();
        let p = f.h.provider.clone();
        let (_, proof) = f.exchanged(&p).await;
        let deadline = proof.deadline;
        let mut barrier = ResponseBarrier::new(b"COMMIT\0");
        let options =
            f.db.options(API)
                .host("127.0.0.1")
                .port(barrier.port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut cn = PgConnection::connect_with(&options).await.unwrap();
        let result = {
            let policy = session_policy();
            let issuance = p.issue_session(&mut cn, proof, &policy);
            tokio::pin!(issuance);
            tokio::select! {
                () = barrier.wait_reached() => {},
                result = &mut issuance => panic!("issuance ended before COMMIT barrier ({change}): {result:?}"),
            }
            let control = async {
                match change {
                    "token-expiry" => f.h.advance(301),
                    "local-expiry" => {
                        f.owner
                            .execute("UPDATE openmettle.local_sessions SET expires_ms=created_ms+1")
                            .await
                            .unwrap();
                    }
                    "revoke" => {
                        f.owner.execute("UPDATE openmettle.local_identity_approvals SET active=false,access_generation=access_generation+1,revision=revision+1").await.unwrap();
                    }
                    // Keep the original exchange deadline. COMMIT is already confirmed by the
                    // barrier, so this tests delayed acknowledgement, not proxy setup time.
                    _ => tokio::time::sleep_until(deadline + Duration::from_millis(1)).await,
                }
                barrier.resume();
            };
            let (result, ()) = tokio::join!(&mut issuance, control);
            result
        };
        assert!(result.is_err(), "{change}");
        cn.close().await.unwrap();
        drop(barrier);
        assert_eq!(
            session_count(&mut f).await,
            1,
            "commit happened despite no released credential"
        );
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn approval_writer_first_waits_and_reads_new_state_or_rollback() {
    for action in ["withdraw", "routine", "rollback", "expiry"] {
        let mut f = Flow::new().await;
        seed(&mut f, true, true).await;
        let p = f.h.provider.clone();
        let (_, proof) = f.exchanged(&p).await;
        let mut owner = f.owner.begin().await.unwrap();
        sqlx::query("SELECT id FROM openmettle.local_identity_approvals FOR UPDATE")
            .execute(&mut *owner)
            .await
            .unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut f.api)
            .await
            .unwrap();
        let mut observer = statistics_observer(&f.db).await;
        let control = async {
            waiting(&mut observer, pid).await;
            if action == "routine" {
                owner
                    .execute("UPDATE openmettle.local_identity_approvals SET revision=revision+1")
                    .await
                    .unwrap();
            } else if action == "expiry" {
                owner
                    .execute("UPDATE openmettle.local_identity_approvals SET expires_ms=1")
                    .await
                    .unwrap();
            } else {
                owner.execute("UPDATE openmettle.local_identity_approvals SET active=false,access_generation=access_generation+1,revision=revision+1").await.unwrap();
            }
            if action == "rollback" {
                owner.rollback().await.unwrap();
            } else {
                owner.commit().await.unwrap();
            }
        };
        let policy = session_policy();
        let (result, ()) = tokio::join!(p.issue_session(&mut f.api, proof, &policy), control);
        assert_eq!(
            result.is_ok(),
            matches!(action, "routine" | "rollback"),
            "{action}"
        );
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn issuance_first_blocks_revocation_until_transaction_finishes() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    let mut barrier = ResponseBarrier::new(b"INSERT 0 1\0");
    let options =
        f.db.options(API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let revoke = async {
        barrier.wait_reached().await;
        let update=sqlx::query("UPDATE openmettle.local_identity_approvals SET active=false,revision=revision+1,access_generation=access_generation+1").execute(&mut f.owner);
        let release = async {
            waiting(&mut observer, pid).await;
            barrier.resume();
        };
        let (result, ()) = tokio::join!(update, release);
        result.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(p.issue_session(&mut cn, proof, &policy), revoke);
    // Depending on postcommit ordering, issuance can report denial or return a credential
    // whose later validation is denied. No validity-through-return promise is made.
    if let Ok(c) = result {
        assert!(
            local::validate(&mut f.api, c.expose(), &policy)
                .await
                .is_err()
        );
    }
    cn.close().await.unwrap();
    drop(barrier);
    assert_eq!(session_count(&mut f).await, 1);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn disable_waiter_and_generation_overflow_are_fail_closed() {
    let mut f = Flow::new().await;
    let user = seed(&mut f, true, true).await;
    let c = issue(&mut f).await;
    let mut held = f.owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.users FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let control = async {
        waiting(&mut observer, pid).await;
        held.execute("UPDATE openmettle.users SET disabled_at=clock_timestamp(),session_generation=session_generation+1").await.unwrap();
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(local::validate(&mut f.api, c.expose(), &policy), control);
    assert!(result.is_err());
    write(&mut f, "UPDATE openmettle.users SET disabled_at=NULL").await;
    assert!(
        local::validate(&mut f.api, c.expose(), &policy)
            .await
            .is_err()
    );
    assert!(
        local::disable_user(&mut f.api, &user, 0, &policy)
            .await
            .is_err()
    );
    write(
        &mut f,
        "UPDATE openmettle.users SET session_generation=9223372036854775807",
    )
    .await;
    assert!(
        local::disable_user(&mut f.api, &user, i64::MAX, &policy)
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn authority_and_disablement_are_rechecked_after_real_lock_waits() {
    for action in [
        "provider-routine",
        "provider-retire",
        "provider-rollback",
        "disable",
    ] {
        let mut f = Flow::new().await;
        seed(&mut f, true, true).await;
        let p = f.h.provider.clone();
        let (_, proof) = f.exchanged(&p).await;
        let mut held = f.owner.begin().await.unwrap();
        let lock = if action == "disable" {
            "SELECT id FROM openmettle.users FOR UPDATE"
        } else {
            "SELECT id FROM openmettle.login_providers FOR UPDATE"
        };
        sqlx::query(lock).execute(&mut *held).await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut f.api)
            .await
            .unwrap();
        let mut observer = statistics_observer(&f.db).await;
        let control = async {
            waiting(&mut observer, pid).await;
            match action {
                "disable" => {
                    held.execute("UPDATE openmettle.users SET disabled_at=clock_timestamp(),session_generation=session_generation+1").await.unwrap();
                }
                "provider-retire" => {
                    revoke_locked(&mut held, None).await;
                }
                _ => {
                    sqlx::query(APPEND)
                        .bind(signing::ID)
                        .bind("v2")
                        .execute(&mut *held)
                        .await
                        .unwrap();
                }
            }
            if action == "provider-rollback" {
                held.rollback().await.unwrap();
            } else {
                held.commit().await.unwrap();
            }
        };
        let policy = session_policy();
        let (result, ()) = tokio::join!(p.issue_session(&mut f.api, proof, &policy), control);
        assert_eq!(result.is_ok(), action == "provider-rollback", "{action}");
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn original_login_expiry_is_checked_with_primary_clock_after_wait() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let started = p
        .begin(&mut f.api, &keys(), Duration::from_secs(1))
        .await
        .unwrap();
    f.arm(&started);
    let permit = f.consume(&p, &started).await.unwrap();
    let proof = permit
        .exchange_with_keys(&p, &auth::Policy::default())
        .await
        .unwrap();
    let mut held = f.owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.users FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let control = async {
        waiting(&mut observer, pid).await;
        sqlx::query("SELECT pg_sleep(GREATEST(0,expires_ms/1000.0-extract(epoch FROM clock_timestamp()))) FROM openmettle.login_transactions WHERE id=$1")
            .bind(locator(&started)).execute(&mut *held).await.unwrap();
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(p.issue_session(&mut f.api, proof, &policy), control);
    assert!(result.is_err());
    assert_eq!(session_count(&mut f).await, 0);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn validator_waits_for_admission_and_logout_has_no_provider_lock() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let c = issue(&mut f).await;
    let mut held = f.owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.local_identity_approvals FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let control = async {
        waiting(&mut observer, pid).await;
        held.execute("UPDATE openmettle.local_identity_approvals SET active=false,access_generation=access_generation+1,revision=revision+1").await.unwrap();
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(local::validate(&mut f.api, c.expose(), &policy), control);
    assert!(result.is_err());
    let mut held = f.owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.login_providers FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    // This would time out if logout acquired provider locks or performed eligibility checks.
    local::logout(&mut f.api, c.expose(), &policy)
        .await
        .unwrap();
    held.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn validation_uses_primary_session_expiry_after_wait() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    let policy = local::Policy::new(Duration::from_secs(1), 16, Duration::from_secs(10)).unwrap();
    let c = p.issue_session(&mut f.api, proof, &policy).await.unwrap();
    let mut held = f.owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.users FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let control = async {
        waiting(&mut observer, pid).await;
        sqlx::query("SELECT pg_sleep(GREATEST(0,expires_ms/1000.0-extract(epoch FROM clock_timestamp()))) FROM openmettle.local_sessions")
            .execute(&mut *held).await.unwrap();
        held.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(local::validate(&mut f.api, c.expose(), &policy), control);
    assert!(result.is_err());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn issuance_first_blocks_provider_and_user_writers() {
    for target in ["provider", "user"] {
        let mut f = Flow::new().await;
        seed(&mut f, true, true).await;
        let p = f.h.provider.clone();
        let (_, proof) = f.exchanged(&p).await;
        let mut barrier = ResponseBarrier::new(b"INSERT 0 1\0");
        let options =
            f.db.options(API)
                .host("127.0.0.1")
                .port(barrier.port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut cn = PgConnection::connect_with(&options).await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
        let mut observer = statistics_observer(&f.db).await;
        let revoke = async {
            barrier.wait_reached().await;
            let update = async {
                if target == "provider" {
                    revoke_provider(&mut f.owner, Some("v1")).await;
                } else {
                    sqlx::query("UPDATE openmettle.users SET disabled_at=clock_timestamp(),session_generation=session_generation+1").execute(&mut f.owner).await.unwrap();
                }
            };
            let release = async {
                waiting(&mut observer, pid).await;
                barrier.resume();
            };
            let ((), ()) = tokio::join!(update, release);
        };
        let policy = session_policy();
        let (result, ()) = tokio::join!(p.issue_session(&mut cn, proof, &policy), revoke);
        if let Ok(c) = result {
            assert!(
                local::validate(&mut f.api, c.expose(), &policy)
                    .await
                    .is_err()
            );
        }
        cn.close().await.unwrap();
        drop(barrier);
        assert_eq!(session_count(&mut f).await, 1);
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn proof_expiry_after_user_wait_rolls_back_session_and_marker() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    f.h.script.lock().unwrap().cache = "max-age=1000".into();
    f.h.script.lock().unwrap().metadata_cache = "max-age=1000".into();
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let mut held = f.owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.users FOR UPDATE")
        .execute(&mut *held)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = statistics_observer(&f.db).await;
    let control = async {
        waiting(&mut observer, pid).await;
        f.h.advance(301);
        held.commit().await.unwrap();
    };
    let policy = session_policy();
    let (result, ()) = tokio::join!(p.issue_session(&mut f.api, proof, &policy), control);
    assert!(result.is_err());
    assert_eq!(session_count(&mut f).await, 0);
    let issued: bool =
        sqlx::query_scalar("SELECT session_issued FROM openmettle.login_transactions WHERE id=$1")
            .bind(locator(&started))
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert!(!issued);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn returned_errors_release_locks_while_rejected_connection_stays_idle() {
    for rejection in ["validate", "capacity", "logout", "disable"] {
        let mut f = Flow::new().await;
        let user = seed(&mut f, true, true).await;
        let credential = issue(&mut f).await;
        let policy = session_policy();
        let result = match rejection {
            "validate" => {
                write(&mut f, "UPDATE openmettle.local_sessions SET revoked=true").await;
                local::validate(&mut f.api, credential.expose(), &policy)
                    .await
                    .map(|_| ())
            }
            "capacity" => {
                let p = f.h.provider.clone();
                let (_, proof) = f.exchanged(&p).await;
                let cap = local::Policy::new(Duration::from_secs(60), 1, Duration::from_secs(10))
                    .unwrap();
                p.issue_session(&mut f.api, proof, &cap).await.map(|_| ())
            }
            "logout" => {
                // A different canonical secret with the real lookup ID reaches the row lock.
                let (id, secret) = credential.expose().split_once('.').unwrap();
                let bad = if secret == "A".repeat(43) {
                    "B".repeat(42) + "A"
                } else {
                    "A".repeat(43)
                };
                local::logout(&mut f.api, &format!("{id}.{bad}"), &policy).await
            }
            _ => local::disable_user(&mut f.api, &user, 1, &policy).await,
        };
        assert_eq!(
            result,
            Err(if rejection == "capacity" {
                SessionError::Capacity
            } else {
                SessionError::Rejected
            })
        );
        // Do not close, query, or reuse f.api: SQLx's queued Drop rollback would hide the bug.
        // The separate owner must immediately acquire every possible held lock, including
        // the session lock for bad-secret logout and the user lock for a stale disable CAS.
        let mut owner = f.owner.begin().await.unwrap();
        owner
            .execute("SET LOCAL lock_timeout='500ms'")
            .await
            .unwrap();
        for sql in [
            "SELECT id FROM openmettle.login_transactions FOR UPDATE",
            "SELECT id FROM openmettle.login_providers FOR UPDATE",
            "SELECT id FROM openmettle.local_identity_approvals FOR UPDATE",
            "SELECT id FROM openmettle.users FOR UPDATE",
            "SELECT id FROM openmettle.local_sessions FOR UPDATE",
        ] {
            tokio::time::timeout(
                Duration::from_secs(2),
                sqlx::query(sql).fetch_all(&mut *owner),
            )
            .await
            .expect("owner lock deadline")
            .expect(rejection);
        }
        owner.rollback().await.unwrap();
        assert_eq!(session_count(&mut f).await, 1);
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn explicit_provider_revoke_fences_exchanged_proof_even_with_same_revision() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let (started, proof) = f.exchanged(&p).await;
    let previous_epoch = proof.epoch;
    assert!(revoke_provider(&mut f.owner, Some("v1")).await > previous_epoch);
    assert!(matches!(
        p.issue_session(&mut f.api, proof, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
    assert_eq!(session_count(&mut f).await, 0);
    let marked: bool =
        sqlx::query_scalar("SELECT session_issued FROM openmettle.login_transactions WHERE id=$1")
            .bind(locator(&started))
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert!(!marked);
    // A new login after the revocation observes its new authority epoch and can succeed.
    let credential = issue(&mut f).await;
    local::validate(&mut f.api, credential.expose(), &session_policy())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn legacy_null_retirement_never_revives_sessions_on_restore() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let old = issue(&mut f).await;
    // Deliberately use the historical v7 protocol, with no access-generation update.
    super::write(&mut f.owner, None).await;
    assert!(matches!(
        local::validate(&mut f.api, old.expose(), &session_policy()).await,
        Err(SessionError::Rejected)
    ));
    super::write(&mut f.owner, Some("v1")).await;
    let generation: i64 = sqlx::query_scalar(
        "SELECT access_generation FROM openmettle.login_providers WHERE id=$1::uuid",
    )
    .bind(signing::ID)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        generation, 0,
        "test must exercise the legacy retirement fence alone"
    );
    assert!(matches!(
        local::validate(&mut f.api, old.expose(), &session_policy()).await,
        Err(SessionError::Rejected)
    ));
    let new = issue(&mut f).await;
    local::validate(&mut f.api, new.expose(), &session_policy())
        .await
        .unwrap();
    super::write(&mut f.owner, Some("v2")).await;
    local::validate(&mut f.api, new.expose(), &session_policy())
        .await
        .unwrap();
    assert!(
        local::validate(&mut f.api, old.expose(), &session_policy())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn expired_approval_restoration_advances_generation_and_does_not_revive() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let old = issue(&mut f).await;
    write(&mut f, "UPDATE openmettle.local_identity_approvals SET expires_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-1,revision=revision+1").await;
    assert!(
        local::validate(&mut f.api, old.expose(), &session_policy())
            .await
            .is_err()
    );
    // Restoration of an expired but active approval is a new access generation too.
    let mut tx = f.owner.begin().await.unwrap();
    tx.execute("SELECT id FROM openmettle.local_identity_approvals FOR UPDATE")
        .await
        .unwrap();
    tx.execute("UPDATE openmettle.local_identity_approvals SET expires_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+600000,revision=revision+1,access_generation=access_generation+1,changed_at=clock_timestamp(),changed_by='fixture-owner',change_reason='restore expired approval'").await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        local::validate(&mut f.api, old.expose(), &session_policy())
            .await
            .is_err()
    );
    let new = issue(&mut f).await;
    local::validate(&mut f.api, new.expose(), &session_policy())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn cancellation_during_explicit_error_rollback_returns_no_success() {
    let mut f = Flow::new().await;
    let user = seed(&mut f, true, true).await;
    let mut barrier = ResponseBarrier::new(b"ROLLBACK\0");
    let options =
        f.db.options(API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    cancel_at_response(
        &mut barrier,
        local::disable_user(&mut cn, &user, 1, &session_policy()),
    )
    .await;
    // Even cancellation during rollback acknowledgment uses the uncertain-discard contract.
    cn.close().await.unwrap();
    drop(barrier);
    let state: (bool, i64) = sqlx::query_as(
        "SELECT disabled_at IS NULL, session_generation FROM openmettle.users WHERE id=$1::uuid",
    )
    .bind(user)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(state, (true, 0));
}

/// Users, identities, scopes and grant assignments as JSON rows, compared as sets.
pub(super) async fn account_state(f: &mut Flow) -> BTreeSet<String> {
    sqlx::query_scalar(
        "SELECT 'user ' || to_jsonb(t)::text FROM openmettle.users t
         UNION ALL SELECT 'identity ' || to_jsonb(t)::text FROM openmettle.user_identities t
         UNION ALL SELECT 'scope ' || to_jsonb(t)::text FROM openmettle.scopes t
         UNION ALL SELECT 'grant ' || to_jsonb(t)::text FROM openmettle.grant_assignments t",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap()
    .into_iter()
    .collect()
}

// ADR 0013 first approval end to end: the unchanged operator script (run with the pinned service
// psql, as in the schema suite) is the only approval writer, and managed login then admits the
// existing identity into its existing user and personal scope.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn first_approval_script_admits_existing_identity_to_its_personal_scope() {
    const SCRIPT: &str = include_str!("../../../../docs/operator/first-identity-approval.psql");
    let mut f = Flow::new().await;
    // Existing enabled user, identity ('synthetic-subject' at the fixture issuer) and personal
    // scope, without an approval.
    let user = seed(&mut f, false, true).await;
    let (identity, scope): (String, String) = sqlx::query_as(
        "SELECT i.id::text, s.id::text FROM openmettle.user_identities i
           JOIN openmettle.scopes s ON s.kind='personal' AND s.personal_user_id=i.user_id
          WHERE i.user_id=$1::uuid",
    )
    .bind(&user)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    let accounts = account_state(&mut f).await;

    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    assert!(matches!(
        p.issue_session(&mut f.api, proof, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
    assert_eq!(session_count(&mut f).await, 0);

    // Explicit expiry ten minutes after the primary clock; synthetic actor and reason.
    let expires_ms: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+600000",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    let expires = expires_ms.to_string();
    let vars = [
        ("provider", signing::ID),
        ("issuer", signing::ISSUER),
        ("subject", "synthetic-subject"),
        ("expires_ms", expires.as_str()),
        ("actor", "fixture-operator"),
        ("reason", "synthetic first approval"),
    ];
    let mut child = psql::start(&f.db.name, OWNER, PASSWORD, &vars);
    // Dropping stdin after the write ends psql's input.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SCRIPT.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    // The script never prints supplied values; stderr carries only fixed or SQL error text.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "first approval committed\n"
    );
    assert!(out.stderr.is_empty(), "{stderr}");
    type Approval = (String, String, String, i64, i64, bool, i64, String, String);
    let approvals: Vec<Approval> = sqlx::query_as(
        "SELECT id::text, provider_id::text, identity_id::text, revision, access_generation,
                active, expires_ms, changed_by, change_reason
           FROM openmettle.local_identity_approvals",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(approvals.len(), 1);
    let approval_id = approvals[0].0.clone();
    assert_eq!(
        approvals[0],
        (
            approval_id.clone(),
            signing::ID.to_owned(),
            identity.clone(),
            1,
            0,
            true,
            expires_ms,
            "fixture-operator".into(),
            "synthetic first approval".into()
        )
    );

    // A fresh managed proof now issues a session for the original user and personal scope.
    let credential = issue(&mut f).await;
    let context = local::validate(&mut f.api, credential.expose(), &session_policy())
        .await
        .unwrap();
    assert_eq!(context.user_id(), user);
    assert_eq!(context.personal_scope_id(), scope);
    let sessions: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT approval_id::text, provider_id::text, identity_id::text, user_id::text
           FROM openmettle.local_sessions",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        sessions,
        [(approval_id, signing::ID.to_owned(), identity, user)]
    );
    // Neither the script nor issuance created, linked or changed accounts, scopes or grants.
    assert_eq!(account_state(&mut f).await, accounts);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn audited_provider_recovery_requires_a_new_successful_oidc_login() {
    const RESTORE: &str = include_str!("../../../../docs/operator/restore-login-provider.psql");
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    let user = seed(&mut f, true, true).await;
    let accounts = account_state(&mut f).await;
    let old = issue(&mut f).await;
    let pending = f.begin(&p).await;
    let (_, old_proof) = f.exchanged(&p).await;
    let retired = revoke_provider(&mut f.owner, None).await.to_string();
    assert_eq!(
        p.begin(&mut f.api, &keys(), Duration::from_secs(60))
            .await
            .unwrap_err(),
        login::Error::Rejected
    );

    f.h.script.lock().unwrap().mode = "failure"; // Every provider request returns HTTP 503.
    let before = f.h.count();
    let vars = [
        ("provider", signing::ID),
        ("source_epoch", "1"),
        ("retired_epoch", retired.as_str()),
        ("expected_generation", "1"),
        ("request", "00000000-0000-0000-0000-000000000012"),
        ("operator", "00000000-0000-0000-0000-000000000011"),
    ];
    let mut child = psql::start(&f.db.name, OWNER, PASSWORD, &vars);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(RESTORE.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"provider restoration committed\n");
    assert_eq!(f.h.count(), before);
    assert_eq!(session_count(&mut f).await, 1);
    assert_eq!(account_state(&mut f).await, accounts);

    assert!(
        local::validate(&mut f.api, old.expose(), &session_policy())
            .await
            .is_err()
    );
    assert_eq!(
        f.consume(&p, &pending).await.unwrap_err(),
        login::Error::Rejected
    );
    assert!(
        p.issue_session(&mut f.api, old_proof, &session_policy())
            .await
            .is_err()
    );
    let start = f.begin(&p).await;
    f.arm(&start);
    let permit = f.consume(&p, &start).await.unwrap();
    assert!(
        permit
            .exchange_with_keys(&p, &auth::Policy::default())
            .await
            .is_err()
    );
    assert_eq!(session_count(&mut f).await, 1);

    f.h.script.lock().unwrap().mode = "ok";
    let fresh = issue(&mut f).await;
    let context = local::validate(&mut f.api, fresh.expose(), &session_policy())
        .await
        .unwrap();
    assert_eq!(context.user_id(), user);
    // A valid exchange through the restored provider cannot substitute for current approval.
    write(
        &mut f,
        "UPDATE openmettle.local_identity_approvals SET active=false,
          revision=revision+1,access_generation=access_generation+1",
    )
    .await;
    let (_, denied) = f.exchanged(&p).await;
    assert!(matches!(
        p.issue_session(&mut f.api, denied, &session_policy()).await,
        Err(SessionError::Rejected)
    ));
    assert_eq!(session_count(&mut f).await, 2);
    assert_eq!(account_state(&mut f).await, accounts);
}
