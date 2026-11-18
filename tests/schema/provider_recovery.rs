//! Exact owner command, primary receipts and transaction failure cases on hosted PostgreSQL.
use super::first_approval::everything;
use super::*;

const SCRIPT: &str = include_str!("../../docs/operator/restore-login-provider.psql");
const PROVIDER: &str = "00000000-0000-0000-0000-000000000010";
const OPERATOR: &str = "00000000-0000-0000-0000-000000000011";
const FIRST: &str = "00000000-0000-0000-0000-000000000012";
const SECOND: &str = "00000000-0000-0000-0000-000000000013";

async fn retired(db: &TestDb) {
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query("INSERT INTO openmettle.login_providers(id,issuer,client_id,access_generation,changed_by,change_reason)
        VALUES ($1::uuid,'https://recovery.example.test','synthetic',1,'fixture','fixture retirement')")
        .bind(PROVIDER).execute(&mut owner).await.unwrap();
    for revision in [Some("obsolete"), Some("v2"), None] {
        sqlx::query("INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ($1::uuid,$2)")
            .bind(PROVIDER).bind(revision).execute(&mut owner).await.unwrap();
    }
}

fn variables<'a>(
    request: &'a str,
    retired_epoch: &'a str,
    source: &'a str,
    generation: &'a str,
) -> [(&'a str, &'a str); 6] {
    [
        ("provider", PROVIDER),
        ("request", request),
        ("operator", OPERATOR),
        ("retired_epoch", retired_epoch),
        ("source_epoch", source),
        ("expected_generation", generation),
    ]
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn only_owner_can_recover_and_only_once_from_inspected_retirement() {
    let db = TestDb::migrated().await;
    retired(&db).await;
    let before = everything(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    for role in [API, WORKER, CAPPED, "public"] {
        let accessible: bool = sqlx::query_scalar("SELECT has_table_privilege($1,'openmettle.provider_recoveries',
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
            OR has_any_column_privilege($1,'openmettle.provider_recoveries','SELECT,INSERT,UPDATE,REFERENCES')")
            .bind(role).fetch_one(&mut owner).await.unwrap();
        assert!(!accessible, "{role}");
    }
    let vars = variables(FIRST, "3", "2", "1");
    for role in [API, WORKER] {
        let mut child = psql_transport::start(&db.0, role, PASSWORD, &vars);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(SCRIPT.as_bytes())
            .unwrap();
        assert!(!child.wait().unwrap().success());
    }
    for vars in [
        variables(FIRST, "1", "2", "1"),
        variables(FIRST, "3", "1", "1"),
        variables(FIRST, "3", "2", "0"),
        variables("private-marker", "3", "2", "1"),
    ] {
        let out = psql(&db, SCRIPT, &vars);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert!(!stderr(&out).contains("private-marker"));
    }
    assert_eq!(everything(&db).await, before);

    // Hold the protocol lock until the first request is waiting. The two clients race to
    // restore the same observed retirement; only the winner may append a revision and receipt.
    owner.execute("BEGIN").await.unwrap();
    owner
        .execute("SELECT id FROM openmettle.login_providers FOR UPDATE")
        .await
        .unwrap();
    let mut first = psql_spawn(&db, SCRIPT, &vars);
    first_approval::wait_for_psql(&db, &mut first, "Lock", "openmettle.login_providers").await;
    let second = psql_spawn(&db, SCRIPT, &variables(SECOND, "3", "2", "1"));
    owner.execute("COMMIT").await.unwrap();
    let results = [
        (FIRST, first.wait_with_output().unwrap()),
        (SECOND, second.wait_with_output().unwrap()),
    ];
    let mut winners = vec![];
    for (request, out) in results {
        if out.status.success() {
            assert_eq!(out.stdout, b"provider restoration committed\n");
            winners.push(request);
        } else {
            assert!(stderr(&out).contains("provider restoration refused"));
            assert!(out.stdout.is_empty());
        }
    }
    assert_eq!(winners.len(), 1);
    let receipt: (String,String,String,i64,i64,i64,i64,String) = sqlx::query_as(
        "SELECT request_id::text, operator_id::text, r.provider_id::text, source_epoch, retired_epoch,
                restored_epoch, access_generation, v.revision FROM openmettle.provider_recoveries r
         JOIN openmettle.login_provider_revisions v ON v.epoch=r.restored_epoch")
        .fetch_one(&mut owner).await.unwrap();
    assert_eq!(
        receipt,
        (
            winners[0].into(),
            OPERATOR.into(),
            PROVIDER.into(),
            2,
            3,
            4,
            1,
            "v2".into()
        )
    );

    let provider_state: (i64, String, String) = sqlx::query_as(
        "SELECT access_generation, changed_by, change_reason FROM openmettle.login_providers WHERE id=$1::uuid")
        .bind(PROVIDER).fetch_one(&mut owner).await.unwrap();
    assert_eq!(
        provider_state,
        (1, OPERATOR.into(), "restore last active revision".into())
    );

    let after = everything(&db).await;
    assert_eq!(after["provider_recoveries"].len(), 1);
    assert_eq!(after["login_provider_revisions"].len(), 4);
    for (table, rows) in &before {
        if !matches!(
            table.as_str(),
            "provider_recoveries" | "login_provider_revisions" | "login_providers"
        ) {
            assert_eq!(&after[table], rows, "unexpected recovery change to {table}");
        }
    }

    // A new retirement makes another recovery eligible. Reusing the committed request UUID
    // fails during the receipt INSERT, after epoch allocation. All table changes roll back.
    owner
        .execute(
            "BEGIN; SELECT id FROM openmettle.login_providers FOR UPDATE;
        UPDATE openmettle.login_providers SET access_generation=2;
        INSERT INTO openmettle.login_provider_revisions(provider_id,revision)
          SELECT id,NULL FROM openmettle.login_providers; COMMIT",
        )
        .await
        .unwrap();
    let before_failure = everything(&db).await;
    let out = psql(&db, SCRIPT, &variables(winners[0], "5", "4", "2"));
    assert!(!out.status.success());
    assert!(stderr(&out).contains("duplicate key"));
    assert!(!stderr(&out).contains(winners[0]));
    assert_eq!(everything(&db).await, before_failure);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn commit_failure_rolls_back_and_lost_success_is_reconciled_after_a_later_change() {
    let db = TestDb::migrated().await;
    retired(&db).await;
    let vars = variables(FIRST, "3", "2", "1");
    // Force failure at COMMIT, after the real script has written both revision and receipt.
    let mut owner = connect(&db.0, OWNER).await;
    owner.execute("CREATE TABLE openmettle.fixture_requests(id uuid PRIMARY KEY);
        ALTER TABLE openmettle.provider_recoveries ADD CONSTRAINT fixture_commit_check
        FOREIGN KEY(request_id) REFERENCES openmettle.fixture_requests(id) DEFERRABLE INITIALLY DEFERRED")
        .await.unwrap();
    let initial = everything(&db).await;
    let failed = psql(&db, SCRIPT, &vars);
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert!(stderr(&failed).contains("fixture_commit_check"));
    assert_eq!(everything(&db).await, initial);
    sqlx::query("INSERT INTO openmettle.fixture_requests(id) VALUES($1::uuid)")
        .bind(FIRST)
        .execute(&mut owner)
        .await
        .unwrap();

    let mut child = psql_start(&db, &vars);
    // Remove the operator's receipt channel before running the exact procedure.
    drop(child.stdout.take());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SCRIPT.as_bytes())
        .unwrap();
    let _unknown = child.wait().unwrap();
    owner.execute("UPDATE openmettle.login_providers SET changed_by='later',change_reason='later maintenance'").await.unwrap();
    let found: (String,String,i64,i64,i64,i64) = sqlx::query_as("SELECT operator_id::text,provider_id::text,
        source_epoch,retired_epoch,restored_epoch,access_generation FROM openmettle.provider_recoveries WHERE request_id=$1::uuid")
        .bind(FIRST).fetch_one(&mut owner).await.unwrap();
    assert_eq!(found, (OPERATOR.into(), PROVIDER.into(), 2, 3, 5, 1));
    let before = everything(&db).await;
    assert!(!psql(&db, SCRIPT, &vars).status.success());
    assert_eq!(everything(&db).await, before);
}
