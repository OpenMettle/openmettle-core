//! ADR 0013 first local identity approval: executes the exact operator script with the pinned
//! service psql (isolated CI PostgreSQL 18 and POSTGRES_CONTAINER). These tests prove which rows
//! the script creates, refuses and preserves under real lock waits. Session issuance after the
//! script is tested separately in `provider_keys::tests::postgres::sessions`.
use super::*;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};

const SCRIPT: &str = include_str!("../../docs/operator/first-identity-approval.psql");
const RUNBOOK: &str = include_str!("../../docs/operator/first-identity-approval.md");
const ADR_0013: &str = include_str!("../../docs/adr/0013-local-identity-sessions.md");
const ADR_0012: &str = include_str!("../../docs/adr/0012-login-provider-authority.md");
const README: &str = include_str!("../../README.md");

// Synthetic values only. The subject keeps case, an apostrophe, a double and a trailing space.
const PROVIDER: &str = "00000000-0000-0000-0000-0000000000f1";
const RETIRED: &str = "00000000-0000-0000-0000-0000000000f2";
const UNREVISED: &str = "00000000-0000-0000-0000-0000000000f3";
const OTHER: &str = "00000000-0000-0000-0000-0000000000f4";
const ISSUER: &str = "https://Approval.example.test/Realm";
const OTHER_ISSUER: &str = "https://other.example.test";
const SUBJECT: &str = "Synthetic O'Neil  Subject ";
const LOWER_SUBJECT: &str = "synthetic o'neil  subject ";
const ACTOR: &str = "fixture-operator";
const REASON: &str = "synthetic first approval";
/// Deterministic absolute times: far past and 2100-01-01, independent of the test clock.
const PAST: &str = "2";
const FUTURE: &str = "4102444800000";
const LATER: &str = "4102444800001";

const INVALID: &str = "first approval refused: missing or invalid input; nothing changed";
const NO_PROVIDER: &str = "first approval refused: provider is missing, retired or has a different issuer; no changes committed";
const NO_IDENTITY: &str =
    "first approval refused: no identity has exactly this issuer and subject; no changes committed";
const INELIGIBLE: &str = "first approval refused: identity user is disabled or has no personal scope; no changes committed";
const EXISTS: &str = "first approval refused: an approval already exists for this provider and identity; no changes committed";
const EXPIRED: &str =
    "first approval refused: expiry is not after the primary database clock; no changes committed";
const COMMITTED: &str = "first approval committed\n";

fn user(n: u8) -> String {
    format!("00000000-0000-0000-0000-0000000000a{n}")
}
fn identity(n: u8) -> String {
    format!("00000000-0000-0000-0000-0000000000b{n}")
}

/// (account, issuer, subject, personal scope, disabled)
const ACCOUNTS: [(u8, &str, &str, bool, bool); 7] = [
    (1, ISSUER, SUBJECT, true, false),
    (2, ISSUER, LOWER_SUBJECT, true, false),
    (3, ISSUER, "synthetic-disabled", true, true),
    (4, ISSUER, "synthetic-no-scope", false, false),
    (5, OTHER_ISSUER, SUBJECT, true, false),
    (6, ISSUER, "synthetic-withdrawn", true, false),
    (7, ISSUER, "synthetic-expired", true, false),
];

/// Active, retired and never-revised providers for one issuer, an active provider for another,
/// the accounts above, and existing withdrawn (6) and expired (7) approvals.
async fn seed(db: &TestDb) {
    let mut owner = connect(&db.0, OWNER).await;
    for (id, issuer, revisions) in [
        (PROVIDER, ISSUER, &[Some("v1")][..]),
        (RETIRED, ISSUER, &[Some("v1"), None][..]),
        (UNREVISED, ISSUER, &[][..]),
        (OTHER, OTHER_ISSUER, &[Some("v1")][..]),
    ] {
        sqlx::query("INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason) VALUES ($1::uuid, $2, 'synthetic', 'fixture-owner', 'synthetic provider')")
            .bind(id).bind(issuer).execute(&mut owner).await.unwrap();
        for revision in revisions {
            sqlx::query("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, $2)")
                .bind(id).bind(revision).execute(&mut owner).await.unwrap();
        }
    }
    for (n, issuer, subject, scope, disabled) in ACCOUNTS {
        sqlx::query("INSERT INTO openmettle.users (id, disabled_at) VALUES ($1::uuid, CASE WHEN $2 THEN clock_timestamp() END)")
            .bind(user(n)).bind(disabled).execute(&mut owner).await.unwrap();
        sqlx::query("INSERT INTO openmettle.user_identities (id, user_id, issuer, subject) VALUES ($1::uuid, $2::uuid, $3, $4)")
            .bind(identity(n)).bind(user(n)).bind(issuer).bind(subject).execute(&mut owner).await.unwrap();
        if scope {
            sqlx::query("INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', $1::uuid)")
                .bind(user(n)).execute(&mut owner).await.unwrap();
        }
    }
    for (n, active, expiry) in [(6, false, 4_102_444_800_000_i64), (7, true, 2)] {
        sqlx::query("INSERT INTO openmettle.local_identity_approvals (provider_id, identity_id, revision, access_generation, active, expires_ms, changed_by, change_reason) VALUES ($1::uuid, $2::uuid, 3, 2, $3, $4, 'fixture-owner', 'synthetic existing approval')")
            .bind(PROVIDER).bind(identity(n)).bind(active).bind(expiry).execute(&mut owner).await.unwrap();
    }
}

/// Every row of every openmettle table as JSON text, compared as sets.
pub(super) async fn everything(db: &TestDb) -> BTreeMap<String, BTreeSet<String>> {
    let mut owner = connect(&db.0, OWNER).await;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = 'openmettle' ORDER BY 1",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    let mut all = BTreeMap::new();
    for table in tables {
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT to_jsonb(t)::text FROM openmettle.{table} t"
        )))
        .fetch_all(&mut owner)
        .await
        .unwrap();
        all.insert(table, rows.into_iter().collect());
    }
    all
}

type Approval = (String, i64, i64, bool, i64, String, String);
async fn approval(db: &TestDb, provider: &str, n: u8) -> Option<Approval> {
    sqlx::query_as(
        "SELECT identity_id::text, revision, access_generation, active, expires_ms, changed_by, change_reason
           FROM openmettle.local_identity_approvals WHERE provider_id = $1::uuid AND identity_id = $2::uuid",
    )
    .bind(provider)
    .bind(identity(n))
    .fetch_optional(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}
fn created(n: u8, expiry: &str) -> Option<Approval> {
    Some((
        identity(n),
        1,
        0,
        true,
        expiry.parse().unwrap(),
        ACTOR.into(),
        REASON.into(),
    ))
}

type Vars = Vec<(&'static str, String)>;
fn input(provider: &str, issuer: &str, subject: &str, expires_ms: &str) -> Vars {
    vec![
        ("provider", provider.into()),
        ("issuer", issuer.into()),
        ("subject", subject.into()),
        ("expires_ms", expires_ms.into()),
        ("actor", ACTOR.into()),
        ("reason", REASON.into()),
    ]
}
fn exact(subject: &str, expires_ms: &str) -> Vars {
    input(PROVIDER, ISSUER, subject, expires_ms)
}
fn with(mut vars: Vars, name: &'static str, value: impl Into<String>) -> Vars {
    vars.retain(|(n, _)| *n != name);
    vars.push((name, value.into()));
    vars
}
fn without(mut vars: Vars, name: &str) -> Vars {
    vars.retain(|(n, _)| *n != name);
    vars
}
fn borrowed(vars: &Vars) -> Vec<(&str, &str)> {
    vars.iter().map(|(n, v)| (*n, v.as_str())).collect()
}
fn approve(db: &TestDb, vars: &Vars) -> Output {
    let out = psql(db, SCRIPT, &borrowed(vars));
    value_free(&out, vars);
    out
}
fn spawn(db: &TestDb, vars: &Vars) -> Child {
    psql_spawn(db, SCRIPT, &borrowed(vars))
}
/// Client output never repeats a supplied value (short values are too common to check).
fn value_free(out: &Output, vars: &Vars) {
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(out));
    for (name, value) in vars {
        if value.len() >= 8 {
            assert!(!text.contains(value.as_str()), "output repeats {name}");
        }
    }
    for value in [SUBJECT.trim(), "O'Neil", ISSUER, "Approval.example"] {
        assert!(!text.contains(value), "output repeats an identity value");
    }
}
fn succeeded(out: &Output) {
    assert!(out.status.success(), "{}", stderr(out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), COMMITTED);
    assert!(out.stderr.is_empty(), "{}", stderr(out));
}
pub(super) fn refused(out: &Output, reason: &str) {
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(stderr(out).contains(reason), "{}", stderr(out));
}

/// Waits (bounded, polling) until the script's psql backend is blocked on a heavyweight lock
/// in a statement that touches `relation`.
async fn blocked(db: &TestDb, child: &mut Child, relation: &str) {
    wait_for_psql(db, child, "Lock", &format!("openmettle.{relation}")).await;
}

pub(super) async fn wait_for_psql(
    db: &TestDb,
    child: &mut Child,
    event_type: &str,
    query_fragment: &str,
) {
    let mut admin = db.admin().await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = $1 AND application_name = 'psql'
                         AND wait_event_type = $2 AND strpos(query, $3) > 0)",
    )
    .bind(&db.0)
    .bind(event_type)
    .bind(query_fragment)
    .fetch_one(&mut admin)
    .await
    .unwrap()
    {
        assert!(Instant::now() < deadline, "script never reached {query_fragment}");
        assert!(child.try_wait().unwrap().is_none(), "script exited before waiting");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
pub(super) async fn db_ms(c: &mut PgConnection) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(c)
        .await
        .unwrap()
}

#[test]
fn one_canonical_first_approval_script_is_linked() {
    assert!(RUNBOOK.contains("](first-identity-approval.psql)"));
    assert!(ADR_0013.contains("](../operator/first-identity-approval.md)"));
    // The executable file is the only approval-creation recipe, and it never updates rows.
    let insert = "INSERT INTO openmettle.local_identity_approvals";
    assert_eq!(SCRIPT.matches(insert).count(), 1);
    for doc in [README, ADR_0012, ADR_0013, RUNBOOK] {
        assert!(!doc.contains(insert));
    }
    for forbidden in [
        "UPDATE ",
        "DELETE ",
        "DO UPDATE",
        "lower(",
        "upper(",
        "trim(",
        "ILIKE",
    ] {
        assert!(!SCRIPT.contains(forbidden), "{forbidden}");
    }
    // The runbook's only SQL block is the read-only inspection query.
    assert_eq!(RUNBOOK.matches("```sql").count(), 1);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn first_approval_creates_only_the_exact_approval_and_never_reapproves() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let before = everything(&db).await;

    succeeded(&approve(&db, &exact(SUBJECT, FUTURE)));
    let after = everything(&db).await;
    for (table, rows) in &before {
        if table != "local_identity_approvals" {
            assert_eq!(&after[table], rows, "{table} changed");
        }
    }
    let added: Vec<_> = after["local_identity_approvals"]
        .difference(&before["local_identity_approvals"])
        .collect();
    assert_eq!(added.len(), 1, "exactly one new row");
    assert!(before["local_identity_approvals"].is_subset(&after["local_identity_approvals"]));
    // The exact identity, not its case variant (2) or the same subject at another issuer (5).
    assert_eq!(approval(&db, PROVIDER, 1).await, created(1, FUTURE));
    assert_eq!(approval(&db, PROVIDER, 2).await, None);
    assert_eq!(approval(&db, OTHER, 5).await, None);

    // Repeating, extending or re-approving refuses and preserves every row, including existing
    // withdrawn and expired approvals.
    let settled = everything(&db).await;
    for vars in [
        exact(SUBJECT, FUTURE),
        exact(SUBJECT, LATER),
        with(exact(SUBJECT, LATER), "actor", "fixture-other-operator"),
        exact("synthetic-withdrawn", LATER),
        exact("synthetic-expired", LATER),
    ] {
        refused(&approve(&db, &vars), EXISTS);
    }
    assert_eq!(everything(&db).await, settled);

    // The read-only inspection query reports the stored outcome without changing anything.
    let query = RUNBOOK
        .split("```sql\n")
        .nth(1)
        .and_then(|rest| rest.split("```").next())
        .unwrap();
    let inspect = |subject: &str| {
        let vars = without(exact(subject, FUTURE), "expires_ms");
        let out = psql(
            &db,
            query,
            &borrowed(&without(without(vars, "actor"), "reason")),
        );
        assert!(out.status.success(), "{}", stderr(&out));
        String::from_utf8(out.stdout).unwrap()
    };
    let shown = inspect(SUBJECT);
    for value in [ACTOR, REASON, FUTURE] {
        assert!(shown.contains(value), "{shown}");
    }
    assert!(inspect(SUBJECT.trim_end()).contains("(0 rows)"));
    assert_eq!(everything(&db).await, settled);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn refusals_commit_nothing_and_leave_eligibility_untouched() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let before = everything(&db).await;
    let base = exact(SUBJECT, FUTURE);
    let mut cases: Vec<(Vars, &str)> = Vec::new();
    for name in [
        "provider",
        "issuer",
        "subject",
        "expires_ms",
        "actor",
        "reason",
    ] {
        cases.push((without(base.clone(), name), INVALID));
        cases.push((with(base.clone(), name, ""), INVALID));
    }
    for (name, value) in [
        ("provider", PROVIDER.to_uppercase()),
        ("provider", format!("{{{PROVIDER}}}")),
        ("provider", PROVIDER.replace('-', "")),
        ("provider", format!(" {PROVIDER}")),
        ("issuer", "i".repeat(2049)),
        ("subject", "s".repeat(256)),
        ("subject", "Synthetic Subjéct".into()),
        ("expires_ms", "0".into()),
        ("expires_ms", "-1".into()),
        ("expires_ms", "+1".into()),
        ("expires_ms", "01".into()),
        ("expires_ms", "1.5".into()),
        ("expires_ms", " 1".into()),
        ("expires_ms", "1e3".into()),
        ("expires_ms", "9223372036854775807".into()),
        ("expires_ms", "1 OR true".into()),
        ("actor", "a".repeat(129)),
        ("reason", "r".repeat(513)),
    ] {
        cases.push((with(base.clone(), name, value), INVALID));
    }
    // Caller-supplied control variables never bypass validation or checks.
    cases.push((
        with(without(base.clone(), "provider"), "valid", "true"),
        INVALID,
    ));
    let mut forged = exact("absent-subject", FUTURE);
    for name in [
        "provider_active",
        "identity_found",
        "inserted",
        "eligible",
        "future",
    ] {
        forged = with(forged, name, "true");
    }
    forged = with(forged, "identity_id", identity(1));
    forged = with(forged, "identity_user", user(1));
    cases.push((forged, NO_IDENTITY));
    for (provider, issuer) in [
        ("00000000-0000-0000-0000-0000000000ff", ISSUER),
        (RETIRED, ISSUER),
        (UNREVISED, ISSUER),
        (PROVIDER, OTHER_ISSUER),
        (PROVIDER, "https://approval.example.test/Realm"),
        (PROVIDER, "https://Approval.example.test/Realm/"),
        (PROVIDER, " https://Approval.example.test/Realm"),
        (OTHER, ISSUER),
    ] {
        cases.push((input(provider, issuer, SUBJECT, FUTURE), NO_PROVIDER));
    }
    for subject in [
        "absent-subject",
        SUBJECT.trim_end(),
        " Synthetic O'Neil  Subject ",
        "Synthetic O'Neil Subject ",
        "SYNTHETIC O'NEIL  SUBJECT ",
        "Synthetic O''Neil  Subject ",
        "x' OR true --",
    ] {
        cases.push((exact(subject, FUTURE), NO_IDENTITY));
    }
    cases.push((
        input(OTHER, OTHER_ISSUER, "synthetic-disabled", FUTURE),
        NO_IDENTITY,
    ));
    cases.push((exact("synthetic-disabled", FUTURE), INELIGIBLE));
    cases.push((exact("synthetic-no-scope", FUTURE), INELIGIBLE));
    for expiry in ["1", PAST] {
        cases.push((exact(SUBJECT, expiry), EXPIRED));
    }
    for (vars, reason) in &cases {
        refused(&approve(&db, vars), reason);
    }
    assert_eq!(everything(&db).await, before);
    // Refused attempts did not consume eligibility: the exact request still succeeds once.
    succeeded(&approve(&db, &base));
    assert_eq!(approval(&db, PROVIDER, 1).await, created(1, FUTURE));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn provider_created_after_lock_lookup_requires_a_new_invocation() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let new_provider = "00000000-0000-0000-0000-0000000000ff";
    let vars = input(new_provider, ISSUER, SUBJECT, FUTURE);
    let mut child = psql_start(&db, &borrowed(&vars));
    let mut stdin = child.stdin.take().unwrap();
    // Feed the exact file in two pieces. Observe the backend waiting for more input
    // after the lock lookup has finished and before it can read current authority.
    let lock_end = "FOR SHARE) AS locked \\gset\n";
    let (first, rest) = SCRIPT.split_at(SCRIPT.find(lock_end).unwrap() + lock_end.len());
    stdin.write_all(first.as_bytes()).unwrap();
    wait_for_psql(&db, &mut child, "Client", " AS provider_rows FROM ").await;

    let mut owner = connect(&db.0, OWNER).await;
    let mut tx = owner.begin().await.unwrap();
    sqlx::query("INSERT INTO openmettle.login_providers (id,issuer,client_id,changed_by,change_reason) VALUES ($1::uuid,$2,'synthetic','fixture-owner','synthetic creation')")
        .bind(new_provider).bind(ISSUER).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO openmettle.login_provider_revisions (provider_id,revision) VALUES ($1::uuid,'v1')")
        .bind(new_provider).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    stdin.write_all(rest.as_bytes()).unwrap();
    drop(stdin);
    refused(&child.wait_with_output().unwrap(), NO_PROVIDER);
    assert_eq!(approval(&db, new_provider, 1).await, None);
    succeeded(&approve(&db, &vars));
    assert_eq!(approval(&db, new_provider, 1).await, created(1, FUTURE));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn high_bit_subject_is_refused_on_sql_ascii() {
    let db = TestDb::create(
        "SELECT pg_advisory_lock_shared($1)",
        "TEMPLATE template0 ENCODING 'SQL_ASCII' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'",
    )
    .await;
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    seed(&db).await;
    let subject = "Synthetic Subjéct";
    sqlx::query("INSERT INTO openmettle.user_identities (id,user_id,issuer,subject) VALUES ($1::uuid,$2::uuid,$3,$4)")
        .bind(identity(8)).bind(user(1)).bind(ISSUER).bind(subject)
        .execute(&mut connect(&db.0, OWNER).await).await.unwrap();
    refused(&approve(&db, &exact(subject, FUTURE)), INVALID);
    assert_eq!(approval(&db, PROVIDER, 8).await, None);
    succeeded(&approve(&db, &exact(SUBJECT, FUTURE)));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn racing_first_approvals_cannot_replace_or_expand_an_approval() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let concurrent = |n: u8| {
        sqlx::query("INSERT INTO openmettle.local_identity_approvals (provider_id, identity_id, active, expires_ms, changed_by, change_reason) VALUES ($1::uuid, $2::uuid, true, $3, 'fixture-holder', 'synthetic concurrent approval')")
            .bind(PROVIDER)
            .bind(identity(n))
            .bind(FUTURE.parse::<i64>().unwrap())
    };
    // A concurrent creator commits while the script waits: nothing is inserted or replaced.
    let mut holder = connect(&db.0, OWNER).await;
    holder.execute("BEGIN").await.unwrap();
    concurrent(1).execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &exact(SUBJECT, LATER));
    blocked(&db, &mut child, "local_identity_approvals").await;
    holder.execute("COMMIT").await.unwrap();
    refused(&child.wait_with_output().unwrap(), EXISTS);
    let held: Option<Approval> = Some((
        identity(1),
        1,
        0,
        true,
        FUTURE.parse().unwrap(),
        "fixture-holder".into(),
        "synthetic concurrent approval".into(),
    ));
    assert_eq!(approval(&db, PROVIDER, 1).await, held);

    // A concurrent creator that rolls back leaves the waiting script to create its own row.
    holder.execute("BEGIN").await.unwrap();
    concurrent(2).execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &exact(LOWER_SUBJECT, LATER));
    blocked(&db, &mut child, "local_identity_approvals").await;
    holder.execute("ROLLBACK").await.unwrap();
    succeeded(&child.wait_with_output().unwrap());
    assert_eq!(approval(&db, PROVIDER, 2).await, created(2, LATER));

    // Two scripts started together: exactly one creates the row, with its own expiry.
    let vars = |expiry| input(OTHER, OTHER_ISSUER, SUBJECT, expiry);
    let first = spawn(&db, &vars(FUTURE));
    let second = spawn(&db, &vars(LATER));
    let outcomes = [
        (FUTURE, first.wait_with_output().unwrap()),
        (LATER, second.wait_with_output().unwrap()),
    ];
    let winners: Vec<_> = outcomes
        .iter()
        .filter(|(_, o)| o.status.success())
        .collect();
    assert_eq!(winners.len(), 1);
    succeeded(&winners[0].1);
    for (_, out) in outcomes.iter().filter(|(_, o)| !o.status.success()) {
        refused(out, EXISTS);
    }
    let row = approval(&db, OTHER, 5).await.unwrap();
    assert_eq!(row.4, winners[0].0.parse::<i64>().unwrap());
    assert_eq!((row.1, row.2, row.3), (1, 0, true));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn provider_user_and_clock_are_rechecked_after_real_lock_waits() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let mut holder = connect(&db.0, OWNER).await;
    let lock_user = |n: u8| {
        sqlx::query("SELECT id FROM openmettle.users WHERE id = $1::uuid FOR UPDATE").bind(user(n))
    };

    // Owner disable (ADR 0013 protocol) committed while the script waits on the user row.
    holder.execute("BEGIN").await.unwrap();
    lock_user(1).execute(&mut holder).await.unwrap();
    sqlx::query("UPDATE openmettle.users SET session_generation = session_generation + 1, disabled_at = GREATEST(created_at, clock_timestamp()) WHERE id = $1::uuid")
        .bind(user(1)).execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &exact(SUBJECT, FUTURE));
    blocked(&db, &mut child, "users").await;
    holder.execute("COMMIT").await.unwrap();
    refused(&child.wait_with_output().unwrap(), INELIGIBLE);
    assert_eq!(approval(&db, PROVIDER, 1).await, None);
    // Owner re-enable preserves the generation.
    sqlx::query("UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid")
        .bind(user(1))
        .execute(&mut holder)
        .await
        .unwrap();

    // Expiry valid when the script started but passed during the wait: the primary clock is
    // sampled after the wait, so nothing commits.
    holder.execute("BEGIN").await.unwrap();
    lock_user(1).execute(&mut holder).await.unwrap();
    // Start the window on the primary after psql connects. Report that timestamp on a
    // fixture-only stderr line so the observer can use the identical cutoff.
    let script = format!(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint + 1200 AS expires_ms \\gset\n\\warn :expires_ms\n{SCRIPT}"
    );
    let vars = without(exact(SUBJECT, FUTURE), "expires_ms");
    let mut child = psql_spawn(&db, &script, &borrowed(&vars));
    blocked(&db, &mut child, "users").await;
    let mut timestamp = String::new();
    BufReader::new(child.stderr.as_mut().unwrap())
        .read_line(&mut timestamp)
        .unwrap();
    let expiry: i64 = timestamp.trim_end().parse().unwrap();
    assert!(
        db_ms(&mut holder).await < expiry,
        "script must wait before expiry"
    );
    while db_ms(&mut holder).await <= expiry {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    holder.execute("ROLLBACK").await.unwrap();
    refused(&child.wait_with_output().unwrap(), EXPIRED);
    assert_eq!(approval(&db, PROVIDER, 1).await, None);

    // A held user lock beyond lock_timeout exits non-zero without committing or echoing values.
    let before = everything(&db).await;
    holder.execute("BEGIN").await.unwrap();
    lock_user(1).execute(&mut holder).await.unwrap();
    let vars = exact(SUBJECT, FUTURE);
    let out = approve(&db, &vars);
    holder.execute("ROLLBACK").await.unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("lock timeout"), "{}", stderr(&out));
    assert_eq!(everything(&db).await, before);

    // A routine provider revision committed during the wait preserves eligibility.
    let lock_provider =
        sqlx::query("SELECT id FROM openmettle.login_providers WHERE id = $1::uuid FOR UPDATE")
            .bind(PROVIDER);
    holder.execute("BEGIN").await.unwrap();
    lock_provider.execute(&mut holder).await.unwrap();
    sqlx::query("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, 'v2')")
        .bind(PROVIDER).execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &exact(LOWER_SUBJECT, FUTURE));
    blocked(&db, &mut child, "login_providers").await;
    holder.execute("COMMIT").await.unwrap();
    succeeded(&child.wait_with_output().unwrap());
    assert_eq!(approval(&db, PROVIDER, 2).await, created(2, FUTURE));

    // Retirement (ADR 0013 protocol) committed during the wait refuses after the wait.
    holder.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT id FROM openmettle.login_providers WHERE id = $1::uuid FOR UPDATE")
        .bind(PROVIDER)
        .execute(&mut holder)
        .await
        .unwrap();
    sqlx::query("UPDATE openmettle.login_providers SET access_generation = access_generation + 1, changed_by = 'fixture-owner', change_reason = 'synthetic retirement', changed_at = clock_timestamp() WHERE id = $1::uuid")
        .bind(PROVIDER).execute(&mut holder).await.unwrap();
    sqlx::query("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, NULL)")
        .bind(PROVIDER).execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &exact(SUBJECT, FUTURE));
    blocked(&db, &mut child, "login_providers").await;
    holder.execute("COMMIT").await.unwrap();
    refused(&child.wait_with_output().unwrap(), NO_PROVIDER);
    assert_eq!(approval(&db, PROVIDER, 1).await, None);
}
