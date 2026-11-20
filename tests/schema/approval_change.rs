//! ADR 0013 approval change: executes the exact operator script with the pinned service psql
//! (isolated CI PostgreSQL 18 and POSTGRES_CONTAINER). These tests prove which approval values
//! each action writes, which requests refuse without changes, and what the script observes after
//! real lock waits. Session effects are tested in `provider_keys::tests::postgres::approval_change`.
use super::first_approval::{db_ms, everything, refused, wait_for_psql};
use super::*;
use std::collections::BTreeMap;

const SCRIPT: &str = include_str!("../../docs/operator/identity-approval-change.psql");
const PROCEDURE: &str = include_str!("../../docs/operator/identity-approval-change.md");
const FIRST: &str = include_str!("../../docs/operator/first-identity-approval.md");
const ADR_0013: &str = include_str!("../../docs/adr/0013-local-identity-sessions.md");
const ADR_0012: &str = include_str!("../../docs/adr/0012-login-provider-authority.md");
const README: &str = include_str!("../../README.md");

// Synthetic values only.
const PROVIDER: &str = "00000000-0000-0000-0000-0000000001d1";
const ISSUER: &str = "https://change.example.test";
const ACTOR: &str = "fixture-change-operator";
const REASON: &str = "synthetic approval change";
/// Deterministic absolute times: far past, 2100-01-01 and one millisecond later.
const PAST: &str = "2";
const FUTURE: &str = "4102444800000";
const LATER: &str = "4102444800001";
const MAX: i64 = i64::MAX;
const MAX_EXPIRY: &str = "9223372036854775807";

const INVALID: &str = "approval change refused: missing or invalid input; nothing changed";
const NOT_FOUND: &str = "approval change refused: no approval has this ID; no changes committed";
const STALE: &str =
    "approval change refused: expected revision or generation is not current; no changes committed";
const OVERFLOW: &str =
    "approval change refused: revision or generation would overflow; no changes committed";
const INAPPLICABLE: &str = "approval change refused: action does not apply to the approval's current state; no changes committed";
const EXPIRED: &str =
    "approval change refused: expiry is not after the primary database clock; no changes committed";

fn user(n: u8) -> String {
    format!("00000000-0000-0000-0000-0000000001a{n}")
}
fn identity(n: u8) -> String {
    format!("00000000-0000-0000-0000-0000000001b{n}")
}
fn approval(n: u8) -> String {
    format!("00000000-0000-0000-0000-0000000001c{n}")
}

/// (approval, active, expires_ms, revision, generation)
const APPROVALS: [(u8, bool, i64, i64, i64); 6] = [
    (1, true, 4_102_444_800_000, 1, 0),   // active, unexpired
    (2, false, 4_102_444_800_000, 3, 2),  // withdrawn, stored expiry still in the future
    (3, true, 2, 2, 0),                   // active but expired
    (4, true, 4_102_444_800_000, MAX, 0), // revision at the bigint maximum
    (5, true, 4_102_444_800_000, 1, MAX), // generation at the bigint maximum
    (6, true, 2, 1, 0),                   // active but expired
];

/// One provider and, per approval, an enabled user, personal scope and identity.
async fn seed(db: &TestDb) {
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query("INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason) VALUES ($1::uuid, $2, 'synthetic', 'fixture-owner', 'synthetic provider')")
        .bind(PROVIDER).bind(ISSUER).execute(&mut owner).await.unwrap();
    sqlx::query("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, 'v1')")
        .bind(PROVIDER).execute(&mut owner).await.unwrap();
    for (n, active, expiry, revision, generation) in APPROVALS {
        sqlx::query("INSERT INTO openmettle.users (id) VALUES ($1::uuid)")
            .bind(user(n))
            .execute(&mut owner)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', $1::uuid)",
        )
        .bind(user(n))
        .execute(&mut owner)
        .await
        .unwrap();
        sqlx::query("INSERT INTO openmettle.user_identities (id, user_id, issuer, subject) VALUES ($1::uuid, $2::uuid, $3, $4)")
            .bind(identity(n)).bind(user(n)).bind(ISSUER).bind(format!("synthetic-change-{n}"))
            .execute(&mut owner).await.unwrap();
        sqlx::query("INSERT INTO openmettle.local_identity_approvals (id, provider_id, identity_id, revision, access_generation, active, expires_ms, changed_by, change_reason) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, 'fixture-owner', 'synthetic existing approval')")
            .bind(approval(n)).bind(PROVIDER).bind(identity(n)).bind(revision).bind(generation)
            .bind(active).bind(expiry).execute(&mut owner).await.unwrap();
    }
}

/// (provider, identity, revision, generation, active, expires_ms, actor, reason, changed_at)
type Row = (String, String, i64, i64, bool, i64, String, String, String);
async fn row(db: &TestDb, n: u8) -> Row {
    sqlx::query_as(
        "SELECT provider_id::text, identity_id::text, revision, access_generation, active,
                expires_ms, changed_by, change_reason, changed_at::text
           FROM openmettle.local_identity_approvals WHERE id = $1::uuid",
    )
    .bind(approval(n))
    .fetch_one(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}
/// Asserts the stored counters, eligibility, expiry and provenance; the provider and identity
/// never change.
fn stored(row: &Row, n: u8, counters: (i64, i64), active: bool, expiry: &str, reason: &str) {
    assert_eq!(
        (&row.0, &row.1, row.2, row.3, row.4, row.5, &*row.6, &*row.7),
        (
            &PROVIDER.to_owned(),
            &identity(n),
            counters.0,
            counters.1,
            active,
            expiry.parse::<i64>().unwrap(),
            ACTOR,
            reason
        )
    );
}

/// Only approval `n` differs between the two snapshots.
fn only_changed(
    before: &BTreeMap<String, BTreeSet<String>>,
    after: &BTreeMap<String, BTreeSet<String>>,
    n: u8,
) {
    let id = approval(n);
    for (table, rows) in before {
        let keep = |set: &BTreeSet<String>| -> BTreeSet<String> {
            set.iter()
                .filter(|r| table != "local_identity_approvals" || !r.contains(&id))
                .cloned()
                .collect()
        };
        assert_eq!(keep(&after[table]), keep(rows), "{table} changed");
    }
}

type Vars = Vec<(&'static str, String)>;
fn request(n: u8, counters: (i64, i64), action: &str, expires_ms: &str) -> Vars {
    vec![
        ("approval", approval(n)),
        ("expected_revision", counters.0.to_string()),
        ("expected_generation", counters.1.to_string()),
        ("action", action.into()),
        ("expires_ms", expires_ms.into()),
        ("actor", ACTOR.into()),
        ("reason", REASON.into()),
    ]
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
fn change(db: &TestDb, vars: &Vars) -> Output {
    let out = psql(db, SCRIPT, &borrowed(vars));
    // Output never repeats operator text (short values are too common to check).
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    for (name, value) in vars {
        if value.len() >= 8 && !value.bytes().all(|b| b.is_ascii_digit()) {
            assert!(!text.contains(value.as_str()), "output repeats {name}");
        }
    }
    out
}
fn spawn(db: &TestDb, vars: &Vars) -> Child {
    psql_spawn(db, SCRIPT, &borrowed(vars))
}
fn committed(out: &Output, revision: i64, generation: i64) {
    assert!(out.status.success(), "{}", stderr(out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("approval change committed: revision {revision} access_generation {generation}\n")
    );
    assert!(out.stderr.is_empty(), "{}", stderr(out));
}
async fn blocked(db: &TestDb, child: &mut Child) {
    wait_for_psql(db, child, "Lock", "openmettle.local_identity_approvals").await;
}

#[test]
fn one_canonical_approval_change_script_is_linked_and_uses_quoted_variables() {
    assert!(PROCEDURE.contains("](identity-approval-change.psql)"));
    assert!(ADR_0013.contains("](../operator/identity-approval-change.md)"));
    assert!(FIRST.contains("](identity-approval-change.md)"));
    assert!(README.contains("](docs/operator/identity-approval-change.md)"));
    // The executable file is the only active approval-change recipe. It writes one table.
    let update = "UPDATE openmettle.local_identity_approvals";
    assert_eq!(SCRIPT.matches(update).count(), 1);
    for doc in [README, ADR_0012, ADR_0013, FIRST, PROCEDURE] {
        assert!(!doc.contains(update));
    }
    for forbidden in [
        "INSERT ",
        "DELETE ",
        "login_providers",
        "openmettle.users",
        "local_sessions",
        "user_identities",
    ] {
        assert!(!SCRIPT.contains(forbidden), "{forbidden}");
    }
    // SQL text uses only quoted :'name' variables. Unquoted references appear only in psql
    // meta-commands and name script-owned booleans or the server-returned new counters.
    let owned = [
        "valid",
        "found",
        "current",
        "bounded",
        "applicable",
        "future",
        "changed",
        "new_revision",
        "new_generation",
    ];
    for line in SCRIPT.lines().map(str::trim_start) {
        if line.starts_with("--") {
            continue;
        }
        let bytes = line.as_bytes();
        for (i, _) in line.match_indices(':') {
            let next = bytes.get(i + 1).copied().unwrap_or(b' ');
            if (i > 0 && bytes[i - 1] == b':') || next == b':' || next == b'\'' || next == b' ' {
                continue;
            }
            assert!(line.starts_with('\\'), "unquoted variable in SQL: {line}");
            if next == b'{' {
                assert!(line.starts_with("\\if :{?"), "{line}");
                continue;
            }
            let name: String = line[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            assert!(owned.contains(&name.as_str()), "{line}");
        }
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn each_action_writes_only_the_documented_values() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    // Apostrophes and psql-like text in the reason are stored verbatim, never executed.
    let odd = "synthetic O'Neil :'approval' ; DROP TABLE x --";
    let step = |n, counters, action, expires: &'static str| {
        with(request(n, counters, action, expires), "reason", odd)
    };
    let mut before = everything(&db).await;
    let mut run = async |vars: Vars, n: u8, new: (i64, i64)| {
        let previous = row(&db, n).await;
        committed(&change(&db, &vars), new.0, new.1);
        let after = everything(&db).await;
        only_changed(&before, &after, n);
        before = after;
        let current = row(&db, n).await;
        assert_ne!(current.8, previous.8, "changed_at advances");
        current
    };

    // An existing approval can store the full positive bigint range. An operator can pass
    // its current expiry to revoke, or another positive value to withdraw. Both preserve it.
    stored(
        &run(step(1, (1, 0), "routine", MAX_EXPIRY), 1, (2, 0)).await,
        1,
        (2, 0),
        true,
        MAX_EXPIRY,
        odd,
    );
    stored(
        &run(step(1, (2, 0), "revoke", MAX_EXPIRY), 1, (3, 1)).await,
        1,
        (3, 1),
        true,
        MAX_EXPIRY,
        odd,
    );
    stored(
        &run(step(1, (3, 1), "withdraw", PAST), 1, (4, 2)).await,
        1,
        (4, 2),
        false,
        MAX_EXPIRY,
        odd,
    );
    stored(
        &run(step(1, (4, 2), "restore", FUTURE), 1, (5, 3)).await,
        1,
        (5, 3),
        true,
        FUTURE,
        odd,
    );
    // A withdrawn approval whose stored expiry is still in the future is restorable.
    stored(
        &run(step(2, (3, 2), "restore", LATER), 2, (4, 3)).await,
        2,
        (4, 3),
        true,
        LATER,
        odd,
    );
    // Active but expired: restore applies directly and advances the generation.
    stored(
        &run(step(3, (2, 0), "restore", FUTURE), 3, (3, 1)).await,
        3,
        (3, 1),
        true,
        FUTURE,
        odd,
    );
    // Active but expired: revoke and withdraw still apply and keep the past expiry.
    stored(
        &run(step(6, (1, 0), "revoke", FUTURE), 6, (2, 1)).await,
        6,
        (2, 1),
        true,
        PAST,
        odd,
    );
    stored(
        &run(step(6, (2, 1), "withdraw", FUTURE), 6, (3, 2)).await,
        6,
        (3, 2),
        false,
        PAST,
        odd,
    );
    stored(
        &run(step(6, (3, 2), "restore", LATER), 6, (4, 3)).await,
        6,
        (4, 3),
        true,
        LATER,
        odd,
    );
    // Routine at the generation maximum leaves the generation untouched.
    let max = run(step(5, (1, MAX), "routine", LATER), 5, (2, MAX)).await;
    stored(&max, 5, (2, MAX), true, LATER, odd);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn refusals_and_stale_retries_commit_nothing() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let before = everything(&db).await;
    let base = request(1, (1, 0), "routine", LATER);
    let names = [
        "approval",
        "expected_revision",
        "expected_generation",
        "action",
        "expires_ms",
        "actor",
        "reason",
    ];
    let mut cases: Vec<(Vars, &str)> = Vec::new();
    for name in names {
        cases.push((without(base.clone(), name), INVALID));
        cases.push((with(base.clone(), name, ""), INVALID));
    }
    for (name, value) in [
        ("approval", approval(1).to_uppercase()),
        ("approval", format!("{{{}}}", approval(1))),
        ("approval", approval(1).replace('-', "")),
        ("approval", format!(" {}", approval(1))),
        ("approval", format!("{}' OR true --", approval(1))),
        ("expected_revision", "0".into()),
        ("expected_revision", "-1".into()),
        ("expected_revision", "+1".into()),
        ("expected_revision", "01".into()),
        ("expected_revision", " 1".into()),
        ("expected_revision", "1.0".into()),
        ("expected_revision", "1 OR true".into()),
        ("expected_revision", "9223372036854775808".into()),
        ("expected_revision", "9999999999999999999".into()),
        ("expected_revision", "10000000000000000000".into()),
        ("expected_generation", "-1".into()),
        ("expected_generation", "00".into()),
        ("expected_generation", "01".into()),
        ("expected_generation", "1e3".into()),
        ("expected_generation", "9223372036854775808".into()),
        ("action", "Routine".into()),
        ("action", "routine ".into()),
        ("action", "delete".into()),
        ("action", "revoke'; --".into()),
        ("expires_ms", "0".into()),
        ("expires_ms", "-1".into()),
        ("expires_ms", "01".into()),
        ("expires_ms", "1.5".into()),
        ("expires_ms", "9223372036854775808".into()),
        ("expires_ms", "10000000000000000000".into()),
        ("actor", "a".repeat(129)),
        ("reason", "r".repeat(513)),
    ] {
        cases.push((with(base.clone(), name, value), INVALID));
    }
    // Caller-supplied control variables never bypass validation or checks.
    cases.push((
        with(without(base.clone(), "approval"), "valid", "true"),
        INVALID,
    ));
    let mut forged = request(1, (9, 9), "routine", LATER);
    for name in [
        "approval_rows",
        "found",
        "current",
        "bounded",
        "applicable",
        "future",
        "changed",
    ] {
        forged = with(
            forged,
            name,
            if name == "approval_rows" { "1" } else { "true" },
        );
    }
    cases.push((forged, STALE));
    cases.push((
        with(
            base.clone(),
            "approval",
            "00000000-0000-0000-0000-0000000001cf",
        ),
        NOT_FOUND,
    ));
    // Stale counters, including correct revision with wrong generation and vice versa.
    for counters in [(2, 0), (1, 1), (3, 2)] {
        cases.push((request(1, counters, "revoke", FUTURE), STALE));
    }
    // Counters at the bigint maximum: valid input, refused before any arithmetic.
    cases.push((request(4, (MAX, 0), "routine", LATER), OVERFLOW));
    for action in ["revoke", "withdraw", "restore"] {
        cases.push((request(5, (1, MAX), action, LATER), OVERFLOW));
    }
    // Ineligible states.
    for action in ["routine", "revoke", "withdraw"] {
        cases.push((request(2, (3, 2), action, LATER), INAPPLICABLE));
    }
    cases.push((request(1, (1, 0), "restore", LATER), INAPPLICABLE));
    cases.push((request(3, (2, 0), "routine", LATER), INAPPLICABLE));
    // Routine and restore require a future expiry; the stored row is not consulted for it.
    for expiry in ["1", PAST] {
        cases.push((request(1, (1, 0), "routine", expiry), EXPIRED));
        cases.push((request(2, (3, 2), "restore", expiry), EXPIRED));
        cases.push((request(3, (2, 0), "restore", expiry), EXPIRED));
    }
    for (vars, reason) in &cases {
        refused(&change(&db, vars), reason);
    }
    assert_eq!(everything(&db).await, before);

    // A repeated command after commit is stale and changes nothing; the current counters apply.
    committed(&change(&db, &base), 2, 0);
    let settled = everything(&db).await;
    refused(&change(&db, &base), STALE);
    assert_eq!(everything(&db).await, settled);
    committed(&change(&db, &request(1, (2, 0), "routine", FUTURE)), 3, 0);
    stored(&row(&db, 1).await, 1, (3, 0), true, FUTURE, REASON);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn competing_change_and_clock_are_rechecked_after_real_lock_waits() {
    let db = TestDb::migrated().await;
    seed(&db).await;
    let mut holder = connect(&db.0, OWNER).await;
    let lock = || {
        sqlx::query(
            "SELECT id FROM openmettle.local_identity_approvals WHERE id = $1::uuid FOR UPDATE",
        )
        .bind(approval(1))
    };
    let competing = || {
        sqlx::query("UPDATE openmettle.local_identity_approvals SET revision = revision + 1, changed_by = 'fixture-holder', change_reason = 'synthetic competing change', changed_at = clock_timestamp() WHERE id = $1::uuid")
            .bind(approval(1))
    };

    // A competing routine change commits while the script waits: its counters are stale.
    holder.execute("BEGIN").await.unwrap();
    lock().execute(&mut holder).await.unwrap();
    competing().execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &request(1, (1, 0), "revoke", FUTURE));
    blocked(&db, &mut child).await;
    holder.execute("COMMIT").await.unwrap();
    refused(&child.wait_with_output().unwrap(), STALE);
    let held = row(&db, 1).await;
    assert_eq!(
        (held.2, held.3, held.4, &*held.6, &*held.7),
        (2, 0, true, "fixture-holder", "synthetic competing change")
    );

    // The competing change rolls back: the waiting script applies to the unchanged row.
    holder.execute("BEGIN").await.unwrap();
    lock().execute(&mut holder).await.unwrap();
    competing().execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &request(1, (2, 0), "revoke", PAST));
    blocked(&db, &mut child).await;
    holder.execute("ROLLBACK").await.unwrap();
    committed(&child.wait_with_output().unwrap(), 3, 1);
    stored(&row(&db, 1).await, 1, (3, 1), true, FUTURE, REASON);

    // The approval expires during the wait. The clock is read after the lock, so routine
    // refuses, and restore then applies to the active-but-expired approval.
    let settled = everything(&db).await;
    let mut expected = row(&db, 1).await;
    holder.execute("BEGIN").await.unwrap();
    lock().execute(&mut holder).await.unwrap();
    let mut child = spawn(&db, &request(1, (3, 1), "routine", LATER));
    blocked(&db, &mut child).await;
    // Put the cutoff strictly inside the observed wait. Container startup and the
    // before-state snapshot have already finished, regardless of runner speed.
    let expiry: i64 = sqlx::query_scalar(
        "UPDATE openmettle.local_identity_approvals
            SET expires_ms = floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint + 100
          WHERE id = $1::uuid RETURNING expires_ms",
    )
    .bind(approval(1))
    .fetch_one(&mut holder)
    .await
    .unwrap();
    expected.5 = expiry;
    while db_ms(&mut holder).await < expiry {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    holder.execute("COMMIT").await.unwrap();
    refused(&child.wait_with_output().unwrap(), INAPPLICABLE);
    only_changed(&settled, &everything(&db).await, 1);
    assert_eq!(row(&db, 1).await, expected);
    committed(&change(&db, &request(1, (3, 1), "restore", LATER)), 4, 2);
    stored(&row(&db, 1).await, 1, (4, 2), true, LATER, REASON);

    // A row held beyond lock_timeout exits non-zero without committing.
    let settled = everything(&db).await;
    holder.execute("BEGIN").await.unwrap();
    lock().execute(&mut holder).await.unwrap();
    let out = change(&db, &request(1, (4, 2), "withdraw", LATER));
    holder.execute("ROLLBACK").await.unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("lock timeout"), "{}", stderr(&out));
    assert_eq!(everything(&db).await, settled);
}
