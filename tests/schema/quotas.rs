use super::*;

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn device_handoff_keeps_every_slot_charged_until_durable_release_evidence_exists() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut owner = connect(&db.0, OWNER).await;
    let actor = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &actor).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES('personal','device_reservations',1),('instance','device_reservations',1)",
        )
        .await
        .unwrap();
    let reserve = |key| {
        sqlx::query_scalar::<_,String>(
        "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,'device_reservations',1,$3,NULL,NULL,NULL,
            clock_timestamp()+interval '15 minutes')::text")
        .bind(&scope).bind(&actor).bind(key)
    };
    let hold = reserve("device").fetch_one(&mut api).await.unwrap();
    assert_eq!(hold, reserve("device").fetch_one(&mut api).await.unwrap());
    let grant: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut api)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_commit_handoff($1::uuid,$2::uuid)")
            .bind(&hold)
            .bind(&grant)
            .fetch_one(&mut api)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE openmettle.quota_reservations SET lease_expires_at=now()-interval '1 hour'
        WHERE id=$1::uuid",
    )
    .bind(&hold)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(&hold)
            .fetch_one(&mut worker)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.quota_release_device_slot($1::uuid,$2::uuid)")
                .bind(&hold)
                .bind(&grant)
                .execute(&mut worker)
                .await
        ),
        "OMQ06"
    );
    assert_eq!(
        sqlstate(reserve("second").fetch_one(&mut api).await),
        "OMQ01"
    );
    let charges: Vec<(String, String)> = sqlx::query_as(
        "SELECT active_used::text,reserved_held::text
        FROM openmettle.quota_budgets ORDER BY target_kind",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(charges, vec![("0".into(), "1".into()); 2]);
    let state: (String, i64) = sqlx::query_as(
        "SELECT state,held_units FROM openmettle.quota_reservations
        WHERE id=$1::uuid",
    )
    .bind(&hold)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(state, ("handoff_committed".into(), 1));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn empty_upgrade_requires_operator_adoption_and_metering_activation() {
    for fresh in [false, true] {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        if !fresh {
            migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        }
        migrate::apply(&settings, MIGRATIONS).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        let markers: (bool, bool, bool, bool) = sqlx::query_as(
            "SELECT metering_enforced,bootstrap_auto_pin_allowed,
            volume_id IS NULL,adoption_run_id IS NULL FROM openmettle.quota_enforcement
            CROSS JOIN openmettle.storage_volume_control",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(markers, (fresh, fresh, true, true));
        let mut worker = connect(&db.0, WORKER).await;
        assert_eq!(
            sqlstate(
                sqlx::query("SELECT openmettle.storage_lock_pinned_volume()")
                    .execute(&mut worker)
                    .await
            ),
            "OMQ03"
        );
        assert_eq!(
            sqlstate(
                sqlx::query("SELECT openmettle.storage_pin_volume_id(gen_random_uuid())")
                    .execute(&mut worker)
                    .await
            ),
            "42501"
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn competing_project_holds_charge_project_actor_and_instance_atomically() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let mut other = connect(&db.0, API).await;
    let mut owner = connect(&db.0, OWNER).await;
    let actor = new_user(&mut api).await;
    personal_scope(&mut api, &actor).await;
    let (_, scope) = project(&mut api, &actor).await;
    owner.execute("INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES ('project','device_reservations',5),('personal','device_reservations',1),('instance','device_reservations',7)").await.unwrap();
    let reserve = |key| {
        sqlx::query_scalar::<_, String>(
            "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,
        'device_reservations',1,$3,NULL,NULL,NULL,clock_timestamp()+interval '1 hour')::text",
        )
        .bind(&scope)
        .bind(&actor)
        .bind(key)
    };
    let (a, b) = tokio::join!(
        reserve("one").fetch_one(&mut api),
        reserve("two").fetch_one(&mut other)
    );
    let (id, key) = match (a, b) {
        (Ok(id), Err(e)) => {
            assert_eq!(sqlstate::<()>(Err(e)), "OMQ01");
            (id, "one")
        }
        (Err(e), Ok(id)) => {
            assert_eq!(sqlstate::<()>(Err(e)), "OMQ01");
            (id, "two")
        }
        result => panic!("expected exactly one admission, got {result:?}"),
    };
    assert_eq!(reserve(key).fetch_one(&mut api).await.unwrap(), id);
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.quota_reservations),
        (SELECT count(*) FROM openmettle.quota_reservation_charges),
        (SELECT count(*) FROM openmettle.quota_budgets WHERE reserved_held=1)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(counts, (1, 3, 3));
    let drift: i64 = sqlx::query_scalar(
        "SELECT budget_mismatches FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(drift, 0);
    let mut worker = connect(&db.0, WORKER).await;
    let warnings: Vec<(String,String,String,i16)> = sqlx::query_as(
        "SELECT target_kind,scope_kind,resource_kind,threshold_pct FROM openmettle.quota_take_warnings(10) ORDER BY threshold_pct")
        .fetch_all(&mut worker).await.unwrap();
    for ((target, kind, resource, pct), expected) in warnings.iter().zip([80, 90, 100]) {
        assert_eq!(
            (target.as_str(), kind.as_str(), resource.as_str(), *pct),
            ("scope", "personal", "device_reservations", expected)
        );
    }
    assert_eq!(warnings.len(), 3);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.quota_take_warnings(10)")
            .fetch_one(&mut worker)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    for released in [true, false] {
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
                .bind(&id)
                .fetch_one(&mut api)
                .await
                .unwrap(),
            released
        );
    }
    let outstanding: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM openmettle.quota_budgets WHERE reserved_held<>0)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(!outstanding);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_release_waits_for_a_locked_unexpired_hold_and_sweep_skips_it() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let actor = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &actor).await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES('personal','device_reservations',1),('instance','device_reservations',1)",
        )
        .await
        .unwrap();
    let hold: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,
        'device_reservations',1,'slot',NULL,NULL,NULL,clock_timestamp()+interval '1 hour')::text",
    )
    .bind(scope)
    .bind(actor)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    let sweep = || {
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid,NULL,true)")
            .bind(&hold)
    };
    assert_eq!(sqlstate(sweep().fetch_one(&mut api).await), "42501");
    assert!(!sweep().fetch_one(&mut worker).await.unwrap());
    let mut lock = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.quota_reservations WHERE id=$1::uuid FOR UPDATE")
        .bind(&hold)
        .execute(&mut *lock)
        .await
        .unwrap();
    let release = sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
        .bind(&hold)
        .fetch_one(&mut worker);
    tokio::pin!(release);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut release)
            .await
            .is_err()
    );
    lock.commit().await.unwrap();
    assert!(release.await.unwrap());
    let source: String = sqlx::query_scalar("SELECT source_key FROM openmettle.quota_reconciliations WHERE reservation_id=$1::uuid AND kind='release'")
        .bind(&hold).fetch_one(&mut owner).await.unwrap();
    assert_eq!(source, "release");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn run_renewal_preserves_storage_settlement_margin_for_late_reservations() {
    use openmettle_core::{
        runs::WriteTransaction,
        storage::{ReservationInput, reserve},
    };
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let actor =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &actor).await;
    let req = run_admission::request(&db, &scope, "personal", &actor, "renewal").await;
    let run = run_admission::admitted(&db, &req).await;
    let claim = openmettle_core::authz::runs::claim_next(
        &mut run_admission::worker(&db).await,
        &run_admission::OPEN,
        &run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claim.run_id, run);
    owner.execute("UPDATE openmettle.storage_instance SET personal_limit_bytes=1000,instance_budget_bytes=1000").await.unwrap();
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let hold = reserve(
        &mut tx,
        &ReservationInput {
            scope: &scope,
            actor: &actor.user,
            key: "late",
            artifact: "00000000-0000-4000-8000-000000000015",
            max_bytes: 10,
            run: Some(&run),
            operation: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // created_at before the deadline, with the producer's 60 second settlement margin.
    let lease = || {
        sqlx::query_scalar::<_, String>(
            "SELECT lease_expires_at::text FROM openmettle.storage_reservations WHERE id=$1::uuid",
        )
        .bind(&hold.id)
    };
    let before = lease().fetch_one(&mut owner).await.unwrap();
    sqlx::query("UPDATE openmettle.runs SET lease_expires_at=lease_expires_at WHERE id=$1::uuid")
        .bind(&run)
        .execute(&mut owner)
        .await
        .unwrap();
    assert_eq!(lease().fetch_one(&mut owner).await.unwrap(), before);
    // An already elapsed execution deadline may precede the storage row's creation.
    sqlx::query("UPDATE openmettle.runs SET execution_expires_at=now()-interval '1 hour',lease_expires_at=now()-interval '1 hour' WHERE id=$1::uuid")
        .bind(&run).execute(&mut owner).await.unwrap();
    assert_eq!(lease().fetch_one(&mut owner).await.unwrap(), before);
}
