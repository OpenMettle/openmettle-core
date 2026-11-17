//! Full managed synthetic TLS → primary PostgreSQL → local approval/session path.
use super::*;
use crate::response_barrier::{ResponseBarrier, cancel_at_response};
use crate::sessions::{self as local, Error as SessionError};

fn session_policy() -> local::Policy {
    local::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(10)).unwrap()
}
async fn seed(f: &mut Flow, approved: bool, scope: bool) -> String {
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
async fn issue(f: &mut Flow) -> local::Credential {
    let p = f.h.provider.clone();
    let (_, proof) = f.exchanged(&p).await;
    p.issue_session(&mut f.api, proof, &session_policy())
        .await
        .unwrap()
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
async fn waiting(observer: &mut PgConnection, pid: i32) {
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
    write(&mut f,"UPDATE openmettle.login_providers SET access_generation=access_generation+1,changed_by='fixture-owner',change_reason='explicit revoke'").await;
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
                open_write(&mut f.owner,None).await;
                f.owner.execute("UPDATE openmettle.login_providers SET access_generation=access_generation+1").await.unwrap();
                f.owner.execute("COMMIT").await.unwrap();
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
                "UPDATE openmettle.local_identity_approvals SET active=true,revision=revision+1",
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
        let (_, mut proof) = f.exchanged(&p).await;
        if change == "deadline" {
            proof.deadline = Instant::now() + Duration::from_millis(500);
        }
        let mut barrier = ResponseBarrier::new(b"COMMIT\0");
        let options =
            f.db.options(API)
                .host("127.0.0.1")
                .port(barrier.port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut cn = PgConnection::connect_with(&options).await.unwrap();
        let control = async {
            barrier.wait_reached().await;
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
                _ => tokio::time::sleep(Duration::from_millis(550)).await,
            }
            barrier.resume();
        };
        let policy = session_policy();
        let (result, ()) = tokio::join!(p.issue_session(&mut cn, proof, &policy), control);
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
        let mut observer = f.db.connect(OWNER).await;
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
    let mut observer = f.db.connect(OWNER).await;
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
    let mut observer = f.db.connect(OWNER).await;
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
        let mut observer = f.db.connect(OWNER).await;
        let control = async {
            waiting(&mut observer, pid).await;
            match action {
                "disable" => {
                    held.execute("UPDATE openmettle.users SET disabled_at=clock_timestamp(),session_generation=session_generation+1").await.unwrap();
                }
                "provider-retire" => {
                    held.execute("UPDATE openmettle.login_providers SET access_generation=access_generation+1").await.unwrap();
                    sqlx::query(APPEND)
                        .bind(signing::ID)
                        .bind(Option::<&str>::None)
                        .execute(&mut *held)
                        .await
                        .unwrap();
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
    let mut observer = f.db.connect(OWNER).await;
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
    let mut observer = f.db.connect(OWNER).await;
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
    let mut observer = f.db.connect(OWNER).await;
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
        let mut observer = f.db.connect(OWNER).await;
        let revoke = async {
            barrier.wait_reached().await;
            let sql = if target == "provider" {
                "UPDATE openmettle.login_providers SET access_generation=access_generation+1"
            } else {
                "UPDATE openmettle.users SET disabled_at=clock_timestamp(),session_generation=session_generation+1"
            };
            let update = sqlx::query(sql).execute(&mut f.owner);
            let release = async {
                waiting(&mut observer, pid).await;
                barrier.resume();
            };
            let (result, ()) = tokio::join!(update, release);
            result.unwrap();
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
    let mut observer = f.db.connect(OWNER).await;
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
