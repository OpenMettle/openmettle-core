//! ADR 0036 persistence and resolver integration on the actual API and worker roles.
use super::*;
use super::{
    authz_runs::personal_of,
    authz_store::{self, Account, FUTURE, NOW, PROVIDER, ctx},
    run_admission::{api, worker},
};
use openmettle_core::{
    authz::{
        branches::{
            self, Answer, Conversation, Fork, Operation, Part, PartContent, Root, RunTarget,
            UserInput,
        },
        runs::{self as queue, Admission, AdmissionLimits, RunAdmission},
        store::{StoreError, WriteOutcome},
    },
    model_config::{
        Catalog, ConfigSnapshot, PromptEstimate, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection,
    },
    runs::{RunInput, WriteTransaction},
    storage::{self, ReservationInput, Settlement},
};
use serde_json::json;

const CATALOG: &[u8] = include_bytes!("../fixtures/conversation-catalog-v1.json");
const INPUT: &str = "00000000-0000-0000-0000-000000001021";
const ANSWER: &str = "00000000-0000-0000-0000-000000002021";
const EDIT: &str = "00000000-0000-0000-0000-000000003021";
const NEXT: &str = "00000000-0000-0000-0000-000000004021";

struct Fixture {
    actor: Account,
    scope: String,
    root: Root,
}
impl Fixture {
    async fn new(db: &TestDb) -> Self {
        let mut owner = connect(&db.0, OWNER).await;
        authz_store::providers(&mut owner).await;
        let actor = authz_store::account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(db, &actor).await;
        let root = authz_store::applied(
            branches::create_conversation(&mut api(db).await, &ctx(&actor, "new-chat"), &scope)
                .await,
        );
        Self { actor, scope, root }
    }
    fn chat(&self) -> Conversation<'_> {
        Conversation {
            scope: &self.scope,
            id: &self.root.conversation_id,
        }
    }
    async fn prepare(
        &self,
        c: &mut PgConnection,
        branch: &str,
        expected: Option<&str>,
        op: Operation<'_>,
    ) -> Result<RunTarget, StoreError> {
        let mut tx = WriteTransaction::begin(c).await?;
        let result = branches::prepare_turn(
            &mut tx,
            &ctx(&self.actor, "graph"),
            self.chat(),
            branch,
            expected,
            op,
        )
        .await;
        if result.is_ok() {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        result
    }
}
async fn revision(c: &mut PgConnection, f: &Fixture) -> String {
    let artifact = storage::upload_artifact(c, &f.scope, &f.actor.user, "upload")
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(c).await.unwrap();
    let reservation = storage::reserve(
        &mut tx,
        &ReservationInput {
            scope: &f.scope,
            actor: &f.actor.user,
            key: "upload",
            artifact: &artifact,
            max_bytes: 8,
            run: None,
            operation: None,
        },
    )
    .await
    .unwrap();
    crate::mark_storage_payload_published(tx.connection().unwrap(), &reservation.id).await;
    let id = storage::settle(
        &mut tx,
        &Settlement {
            scope: &f.scope,
            reservation: &reservation.id,
            size_bytes: 7,
            content_digest: &[0; 32],
            media_type: "text/plain",
            display_name: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn published_paths_replay_revisions_and_budget_survive_forks() {
    let db = TestDb::migrated().await;
    super::run_admission::seed_token_budget(&db).await;
    let f = Fixture::new(&db).await;
    let chat = f.chat();
    let root = &f.root.branch_id;
    let (mut c, mut w) = (api(&db).await, worker(&db).await);
    let actor = authz_store::principal(&db, &f.actor).await;
    let WriteOutcome::Replayed { target_id } =
        branches::create_conversation(&mut c, &ctx(&f.actor, "new-chat"), &f.scope)
            .await
            .unwrap()
    else {
        panic!("expected conversation replay")
    };
    assert_eq!(target_id, f.root);
    let empty = branches::history(&mut c, &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    assert!(empty.head.is_none() && empty.turns.is_empty());
    sqlx::query(
        "UPDATE openmettle.storage_instance SET instance_budget_bytes=100,personal_limit_bytes=100",
    )
    .execute(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap();
    let revision = revision(&mut c, &f).await;
    let parts = [
        Part::Text("first".into()),
        Part::Attachment(revision.clone()),
        Part::Text("third".into()),
    ];
    let catalog = Catalog::load(CATALOG).unwrap();
    let study: Selection = serde_json::from_value(json!({"preset":"study"})).unwrap();
    let cfg = ConfigSnapshot {
        effective: catalog
            .resolve(&Selection::default(), &study, None, |_, _| true)
            .unwrap(),
        policy_revision: "fixture-v1".into(),
        required_capabilities: Default::default(),
        cost_bound: None,
    };
    use branches::snapshot::{Intent, Snapshots};
    let intent = Intent {
        source_branch_id: root,
        expected_head_message_id: None,
        operation: Operation::Append(UserInput {
            id: INPUT,
            parts: &parts,
        }),
        selection: &study,
        requested_rounds: None,
    };
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let prepared = branches::prepare_turn(
        &mut tx,
        &ctx(&f.actor, "submit"),
        chat,
        root,
        None,
        intent.operation,
    )
    .await
    .unwrap();
    let active = branches::history(tx.connection().unwrap(), &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    let snapshots = Snapshots::encode(&intent, &active, &catalog, &cfg).unwrap();
    let admission = RunAdmission {
        input: RunInput {
            scope: &f.scope,
            actor: &f.actor.user,
            conversation: chat.id,
            branch: &prepared.branch_id,
            message: &prepared.input_message_id,
            key: "submit",
            format: SNAPSHOT_FORMAT,
            version: SNAPSHOT_VERSION,
            input: &snapshots.input,
            config: &snapshots.config,
        },
        actor_approval_id: &f.actor.approval,
        capabilities: &[],
        requested_rounds: None,
        now_ms: NOW,
        cost_qualified: None,
    };
    let limits = AdmissionLimits {
        live_per_actor: 10,
        live_per_scope: 10,
        queued_in_instance: 10,
        queue_timeout: Duration::from_secs(60),
        round_cap: 10,
    };
    let Admission::Admitted { run_id, .. } = queue::admit_run(&mut tx, &admission, &limits)
        .await
        .unwrap()
    else {
        panic!("admission")
    };
    tx.commit().await.unwrap();
    let replay = queue::find_run(&mut c, &f.scope, &f.actor.user, "submit")
        .await
        .unwrap()
        .unwrap();
    assert!(replay.matches(&admission.input));
    assert_eq!(replay.snapshot_format, SNAPSHOT_FORMAT);
    assert_eq!(replay.snapshot_version, SNAPSHOT_VERSION);
    assert_eq!(replay.input_snapshot, snapshots.input);
    assert_eq!(replay.config_snapshot, snapshots.config);
    let (stored, pinned) = Snapshots::decode(&replay).unwrap();
    assert!(stored.matches(&intent));
    assert!(!stored.matches(&Intent {
        requested_rounds: Some(2),
        ..intent
    }));
    assert_eq!(pinned.policy_revision, "fixture-v1");
    assert_eq!(stored.path.len(), 1);
    assert_eq!(stored.path[0].message_id, INPUT);
    assert_eq!(
        stored.path[0].attachments[0].revision_id.as_ref(),
        Some(&revision)
    );
    assert_eq!(
        (replay.branch_id.as_str(), replay.input_message_id.as_str()),
        (root.as_str(), INPUT)
    );
    assert_eq!(
        authz_store::conflict(
            f.prepare(
                &mut c,
                root,
                Some(INPUT),
                Operation::Append(UserInput {
                    id: NEXT,
                    parts: &parts
                })
            )
            .await
        ),
        "branch has live run"
    );

    // Refuse a forged producer, a false byte count and empty reasoning with its true byte count.
    for (parent, blocks, bytes) in [
        (None, "[{}]", 4),
        (Some(INPUT), "[{}]", 1),
        (Some(INPUT), "[]", 2),
    ] {
        let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
        let con = tx.connection().unwrap();
        let id = message(con, &f.scope, chat.id, parent).await.unwrap();
        let result = sqlx::query(
            "INSERT INTO openmettle.message_turns
            (scope_id,conversation_id,message_id,run_id,reasoning_blocks,reasoning_bytes)
            VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::jsonb,$6)",
        )
        .bind(&f.scope)
        .bind(chat.id)
        .bind(id)
        .bind(&run_id)
        .bind(blocks)
        .bind(bytes)
        .execute(con)
        .await;
        assert_eq!(sqlstate(result), "23514");
        tx.rollback().await.unwrap();
    }
    let blocks =
        vec![serde_json::from_value(json!({"kind":"fixture","opaque":"private ✓"})).unwrap()];
    let claim = queue::claim_next(
        &mut w,
        &super::run_admission::OPEN,
        &super::run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
    branches::publish_answer(
        &mut tx,
        &claim.lease(),
        &Answer {
            id: ANSWER,
            parts: &[],
            reasoning: Some(&blocks),
            input_count: Some(88),
            output_count: None,
            stop_reason: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let size:i32=sqlx::query_scalar("SELECT octet_length(reasoning_blocks::text) FROM openmettle.message_turns WHERE message_id=$1::uuid")
        .bind(ANSWER).fetch_one(&mut w).await.unwrap();
    let metadata: (i32, i64, Option<i64>) = sqlx::query_as(
        "SELECT reasoning_bytes,input_count,output_count
        FROM openmettle.message_turns WHERE message_id=$1::uuid",
    )
    .bind(ANSWER)
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(metadata, (size, 88, None));
    let original = branches::history(&mut c, &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    for unprepared in [&empty, &original] {
        assert!(matches!(
            Snapshots::encode(&intent, unprepared, &catalog, &cfg),
            Err(openmettle_core::model_config::Error::Invalid("input turn"))
        ));
    }
    assert!(original.turns[0].parts.is_empty());
    let original_parts = &original.turns[1].parts;
    for (i, part) in original_parts.iter().enumerate() {
        assert_eq!(part.ordinal, i as i32);
        assert!(matches!(&part.value, PartContent::Available(value) if value == &parts[i]));
    }

    let retry = f
        .prepare(
            &mut c,
            root,
            Some(ANSWER),
            Operation::Retry { target: ANSWER },
        )
        .await
        .unwrap();
    assert_eq!(retry.input_message_id, INPUT);
    let retried = branches::history(&mut c, &actor, chat, &retry.branch_id, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried.turns.len(), 1);
    assert_eq!(retried.turns[0].parts[1].id, original_parts[1].id);
    let edit = f
        .prepare(
            &mut c,
            root,
            Some(ANSWER),
            Operation::Edit {
                target: INPUT,
                replacement: UserInput {
                    id: EDIT,
                    parts: &parts[1..],
                },
            },
        )
        .await
        .unwrap();
    let edited = branches::history(&mut c, &actor, chat, &edit.branch_id, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(edited.turns.len(), 1);
    assert_ne!(edited.turns[0].parts[0].id, original_parts[1].id);
    assert!(edited.turns[0].parts[0].value == original_parts[1].value);
    let source = Some(Fork {
        branch: root,
        ancestor: ANSWER,
    });
    let fork = authz_store::applied(
        branches::create_branch(&mut c, &ctx(&f.actor, "fork"), chat, source).await,
    );
    assert_eq!(
        branches::create_branch(&mut c, &ctx(&f.actor, "fork"), chat, source)
            .await
            .unwrap(),
        WriteOutcome::Replayed {
            target_id: fork.clone()
        }
    );
    assert_eq!(
        authz_store::conflict(
            branches::create_branch(
                &mut c,
                &ctx(&f.actor, "fork"),
                chat,
                Some(Fork {
                    branch: root,
                    ancestor: INPUT
                })
            )
            .await
        ),
        openmettle_core::authz::store::KEY_REUSED
    );
    assert!(
        branches::create_branch(
            &mut c,
            &ctx(&f.actor, "other-target"),
            chat,
            Some(Fork {
                branch: root,
                ancestor: EDIT
            })
        )
        .await
        .is_err()
    );
    f.prepare(
        &mut c,
        &fork,
        Some(ANSWER),
        Operation::Append(UserInput {
            id: NEXT,
            parts: &parts[..1],
        }),
    )
    .await
    .unwrap();
    let forked = branches::history(&mut c, &actor, chat, &fork, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        forked
            .turns
            .iter()
            .map(|t| t.metadata.message_id.as_str())
            .collect::<Vec<_>>(),
        [NEXT, ANSWER, INPUT]
    );
    assert_eq!(forked.turns[2].parts[1].id, original_parts[1].id);
    let path: Vec<_> = forked.turns.into_iter().map(|t| t.metadata).collect();
    let target = catalog
        .resolve(
            &study,
            &serde_json::from_value(json!({"model":"b"})).unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let p = PromptEstimate {
        profile: &target.profile,
        revision: "fixture-bound/2",
        instructions: Some(1),
        history: Some(10),
        tools: Some(0),
        attachments: Some(20),
        proposed_input: Some(5),
    };
    let budget = catalog.budget(&target, &path, Some(&p)).unwrap();
    assert_eq!(budget.measured.unwrap().run_id.as_ref(), Some(&run_id));
    assert_eq!(
        budget.estimated.unwrap().upper_bound,
        36 + size as u64 * 2 + 7
    );
    let unknown = catalog.budget(&target, &path, None).unwrap();
    assert!(unknown.measured.is_some() && unknown.estimated.is_none());
    let totals: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT active_bytes,retained_bytes,reserved_bytes,
        (SELECT count(*) FROM openmettle.storage_reservations) FROM openmettle.storage_instance",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(totals, (7, 0, 0, 1));
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    storage::retain_revision(&mut tx, &f.scope, &revision)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        f.prepare(
            &mut c,
            root,
            Some(ANSWER),
            Operation::Retry { target: ANSWER }
        )
        .await,
        Err(StoreError::Denied(
            openmettle_core::authz::DenialReason::NotFound
        ))
    ));
    let history = branches::history(&mut c, &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(history.head.as_deref(), Some(ANSWER));
    assert_eq!(
        authz_store::audit(&db)
            .await
            .iter()
            .map(|r| (r.2.as_str(), r.3.as_str()))
            .collect::<Vec<_>>(),
        [
            ("conversation.create", "conversation"),
            ("branch.create", "branch")
        ]
    );

    // The reader can see the same path but has no share on the attachment's artifact.
    use openmettle_core::authz::{Grantee, ResourceAccess, ResourceKind, projects};
    let reader =
        authz_store::account(&mut connect(&db.0, OWNER).await, PROVIDER, true, FUTURE).await;
    authz_store::applied(
        projects::share_resource(
            &mut c,
            &ctx(&f.actor, "share-chat"),
            ResourceKind::Conversation,
            chat.id,
            &Grantee::User(reader.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    let reader = authz_store::principal(&db, &reader).await;
    let retry_intent = Intent {
        expected_head_message_id: Some(ANSWER),
        operation: Operation::Retry { target: ANSWER },
        ..intent
    };
    let append_intent = Intent {
        source_branch_id: &fork,
        expected_head_message_id: Some(ANSWER),
        operation: Operation::Append(UserInput {
            id: NEXT,
            parts: &parts[..1],
        }),
        ..intent
    };
    for (principal, can_read_artifact) in [(&actor, true), (&reader, false)] {
        let input = branches::history(&mut c, principal, chat, &retry.branch_id, NOW)
            .await
            .unwrap()
            .unwrap();
        let value = &input.turns[0].parts[1].value;
        if can_read_artifact {
            assert!(matches!(value, PartContent::RetainedAttachment(id) if id == &revision));
        } else {
            assert!(matches!(value, PartContent::UnavailableAttachment));
        }
        assert!(matches!(
            Snapshots::encode(&retry_intent, &input, &catalog, &cfg),
            Err(openmettle_core::model_config::Error::Invalid(
                "input attachment"
            ))
        ));

        let history = branches::history(&mut c, principal, chat, &fork, NOW)
            .await
            .unwrap()
            .unwrap();
        let bytes = Snapshots::encode(&append_intent, &history, &catalog, &cfg)
            .unwrap()
            .input;
        assert!(!std::str::from_utf8(&bytes).unwrap().contains(&revision));
        let pinned: branches::snapshot::InputSnapshot = serde_json::from_slice(&bytes).unwrap();
        let omitted = &pinned.path[2].attachments;
        assert_eq!(omitted.len(), 1);
        assert_eq!((omitted[0].ordinal, &omitted[0].revision_id), (1, &None));
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn prepare_turn_validates_actor_and_expected_head_before_locking() {
    let db = TestDb::migrated().await;
    let f = Fixture::new(&db).await;
    let mut c = api(&db).await;
    let valid = ctx(&f.actor, "submit");
    let invalid = openmettle_core::authz::store::AuditContext {
        actor_user_id: "invalid",
        ..valid
    };
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    for (ctx, expected, field) in [
        (&invalid, None, "actor_user_id"),
        (&valid, Some("invalid"), "expected_head_message_id"),
    ] {
        let result = branches::prepare_turn(
            &mut tx,
            ctx,
            f.chat(),
            &f.root.branch_id,
            expected,
            Operation::Append(UserInput {
                id: INPUT,
                parts: &[Part::Text("fixture".into())],
            }),
        )
        .await;
        assert!(matches!(result, Err(StoreError::InvalidInput(name)) if name == field));
    }
    let locked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM pg_locks WHERE pid=pg_backend_pid()
          AND relation IN ('openmettle.users'::regclass, 'openmettle.branch_heads'::regclass))",
    )
    .fetch_one(tx.connection().unwrap())
    .await
    .unwrap();
    assert!(!locked);
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn concurrent_appends_only_publish_one_complete_path() {
    let db = TestDb::migrated().await;
    let f = Fixture::new(&db).await;
    let gate = tokio::sync::Barrier::new(2);
    let attempt = async |id: &str| {
        let mut c = api(&db).await;
        gate.wait().await;
        f.prepare(
            &mut c,
            &f.root.branch_id,
            None,
            Operation::Append(UserInput {
                id,
                parts: &[Part::Text("message".into())],
            }),
        )
        .await
    };
    let (a, b) = tokio::join!(attempt(INPUT), attempt(EDIT));
    let winner = match (a, b) {
        (Ok(w), Err(StoreError::Conflict(branches::HEAD_MISMATCH)))
        | (Err(StoreError::Conflict(branches::HEAD_MISMATCH)), Ok(w)) => w,
        result => panic!("expected one conflict, got {result:?}"),
    };
    let mut c = api(&db).await;
    let counts:(i64,i64,i64,String)=sqlx::query_as("SELECT (SELECT count(*) FROM openmettle.messages),
        (SELECT count(message_id) FROM openmettle.message_turns),(SELECT count(*) FROM openmettle.message_parts),
        head_message_id::text FROM openmettle.branch_heads").fetch_one(&mut c).await.unwrap();
    assert_eq!(counts, (1, 1, 1, winner.input_message_id.clone()));
    assert_eq!(
        authz_store::conflict(
            f.prepare(
                &mut c,
                &f.root.branch_id,
                Some(&winner.input_message_id),
                Operation::Append(UserInput {
                    id: &winner.input_message_id,
                    parts: &[Part::Text("reuse".into())]
                })
            )
            .await
        ),
        "message already exists"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn populated_v20_upgrade_preserves_unmanaged_skeletons_and_legacy_writers() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..20])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let actor = authz_store::account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &actor).await;
    let mut c = api(&db).await;
    let id = conversation(&mut c, &scope, "personal", &actor.user)
        .await
        .unwrap();
    let chat = Conversation {
        scope: &scope,
        id: &id,
    };
    let skeleton = message(&mut c, &scope, &id, None).await.unwrap();
    let legacy:String=sqlx::query_scalar("INSERT INTO openmettle.conversation_branches
        (scope_id,conversation_id,fork_message_id) VALUES ($1::uuid,$2::uuid,$3::uuid) RETURNING id::text")
        .bind(&scope).bind(&id).bind(&skeleton).fetch_one(&mut c).await.unwrap();
    let input = RunInput {
        scope: &scope,
        actor: &actor.user,
        conversation: &id,
        branch: &legacy,
        message: &skeleton,
        key: "old",
        format: "legacy",
        version: 7,
        input: b"old\0\xff",
        config: b"cfg\0",
    };
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    openmettle_core::runs::create_run(&mut tx, &input)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tables = &["messages", "conversation_branches", "runs", "run_events"];
    let before = snapshot_nonempty_at(&mut owner, tables, 20).await;
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(snapshot_nonempty_at(&mut owner, tables, 20).await, before);
    let p = authz_store::principal(&db, &actor).await;
    assert!(
        branches::history(&mut c, &p, chat, &legacy, NOW)
            .await
            .unwrap()
            .is_none()
    );
    let replay = queue::find_run(&mut c, &scope, &actor.user, "old")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            replay.snapshot_format.as_str(),
            replay.snapshot_version,
            replay.input_snapshot.as_slice(),
            replay.config_snapshot.as_slice()
        ),
        ("legacy", 7, input.input, input.config)
    );
    let root = authz_store::applied(
        branches::create_branch(&mut c, &ctx(&actor, "root"), chat, None).await,
    );
    assert!(
        branches::history(&mut c, &p, chat, &root, NOW)
            .await
            .unwrap()
            .unwrap()
            .turns
            .is_empty()
    );
    assert!(
        message(&mut worker(&db).await, &scope, &id, Some(&skeleton))
            .await
            .is_ok()
    );
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    openmettle_core::runs::create_run(
        &mut tx,
        &RunInput {
            key: "after",
            ..input
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(message_id) FROM openmettle.message_turns")
            .fetch_one(&mut c)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn graph_column_grants_and_sealed_content() {
    let db = TestDb::migrated().await;
    let f = Fixture::new(&db).await;
    let mut c = api(&db).await;
    f.prepare(
        &mut c,
        &f.root.branch_id,
        None,
        Operation::Append(UserInput {
            id: INPUT,
            parts: &[Part::Text("visible".into())],
        }),
    )
    .await
    .unwrap();
    let (same_predicate, key): (bool, String) = sqlx::query_as(
        "SELECT pg_get_expr(b.indpred, b.indrelid) = pg_get_expr(a.indpred, a.indrelid),
                pg_get_indexdef(b.indexrelid, 1, true)
           FROM pg_index b CROSS JOIN pg_index a
          WHERE b.indexrelid = 'openmettle.runs_branch_live_idx'::regclass
            AND a.indexrelid = 'openmettle.runs_live_actor_idx'::regclass",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(same_predicate);
    assert_eq!(key, "branch_id");
    let (full_index, conversation, head): (bool, String, String) = sqlx::query_as(
        "SELECT indpred IS NULL AND indnkeyatts=2,
                pg_get_indexdef(indexrelid, 1, true), pg_get_indexdef(indexrelid, 2, true)
           FROM pg_index
          WHERE indexrelid='openmettle.branch_heads_conversation_idx'::regclass
            AND indrelid='openmettle.branch_heads'::regclass",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(full_index);
    assert_eq!(
        (conversation.as_str(), head.as_str()),
        ("conversation_id", "head_message_id")
    );

    // Check every column, including the default-generated part ID and the hidden blocks.
    let grants=sqlx::query("SELECT c.relname,a.attname,r.rolname,
         has_column_privilege(r.oid,c.oid,a.attnum,'SELECT') AS rd,
         has_column_privilege(r.oid,c.oid,a.attnum,'INSERT') AS ins,
         has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE') AS upd
         FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid CROSS JOIN pg_roles r
         WHERE c.relnamespace='openmettle'::regnamespace AND c.relname IN ('branch_heads','message_parts','message_turns')
           AND a.attnum>0 AND NOT a.attisdropped AND r.rolname IN ('openmettle_api','openmettle_worker','openmettle_issuance','openmettle_gateway')")
        .fetch_all(&mut db.admin().await).await.unwrap();
    assert_eq!(grants.len(), (5 + 10 + 8) * 4);
    for row in grants {
        let (rel, col, role): (&str, &str, &str) = (row.get(0), row.get(1), row.get(2));
        let actual = (
            row.get::<bool, _>("rd"),
            row.get::<bool, _>("ins"),
            row.get::<bool, _>("upd"),
        );
        let expected = match (role, rel) {
            (ISSUANCE | pg::GATEWAY, _) => (false, false, false),
            (_, "branch_heads") => (true, role == API, col == "head_message_id"),
            (_, "message_parts") => (true, col != "id", false),
            (API, "message_turns") => (
                col != "reasoning_blocks",
                matches!(
                    col,
                    "scope_id" | "conversation_id" | "message_id" | "author_user_id"
                ),
                false,
            ),
            (WORKER, "message_turns") => (true, col != "author_user_id", false),
            _ => unreachable!(),
        };
        assert_eq!(actual, expected, "{role} {rel}.{col}");
    }
    expect_state(
        &mut c,
        "SELECT reasoning_blocks FROM openmettle.message_turns",
        "42501",
    )
    .await;
    expect_state(&mut c, "SELECT * FROM openmettle.message_turns", "42501").await;
    expect_state(
        &mut c,
        "INSERT INTO openmettle.message_turns (scope_id,conversation_id,message_id,author_user_id)
         VALUES (gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid()) RETURNING *",
        "42501",
    ).await;
    expect_state(
        &mut c,
        "INSERT INTO openmettle.message_turns (run_id) VALUES (gen_random_uuid())",
        "42501",
    )
    .await;
    expect_state(
        &mut c,
        "INSERT INTO openmettle.message_turns (stop_reason) VALUES ('limit')",
        "42501",
    )
    .await;
    let mut w = worker(&db).await;
    expect_state(
        &mut w,
        "INSERT INTO openmettle.message_turns (author_user_id) VALUES (gen_random_uuid())",
        "42501",
    )
    .await;
    expect_state(
        &mut w,
        "INSERT INTO openmettle.branch_heads (branch_id) VALUES (gen_random_uuid())",
        "42501",
    )
    .await;
    for con in [&mut c, &mut w] {
        for sql in [
            "UPDATE openmettle.message_turns SET input_count=0",
            "UPDATE openmettle.message_turns SET stop_reason='limit'",
            "UPDATE openmettle.message_parts SET text_value='changed'",
            "DELETE FROM openmettle.message_parts",
            "DELETE FROM openmettle.message_turns",
            "DELETE FROM openmettle.branch_heads",
            "UPDATE openmettle.branch_heads SET parent_branch_id=NULL",
        ] {
            expect_state(con, sql, "42501").await;
        }
        expect_state(con,"INSERT INTO openmettle.message_parts(scope_id,conversation_id,message_id,ordinal,kind,text_value)
            SELECT scope_id,conversation_id,message_id,1,'text','late' FROM openmettle.message_turns","23514").await;
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn cross_scope_parents_and_revisions_and_incomplete_publications_are_refused() {
    let db = TestDb::migrated().await;
    let f = Fixture::new(&db).await;
    let mut c = api(&db).await;
    let chat = f.chat();
    let mut owner = connect(&db.0, OWNER).await;
    let other = authz_store::account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &other).await;
    let other_root = authz_store::applied(
        branches::create_conversation(&mut c, &ctx(&other, "other-chat"), &scope).await,
    );
    let other_fixture = Fixture {
        actor: other,
        scope,
        root: other_root,
    };
    let foreign = message(
        &mut c,
        &other_fixture.scope,
        &other_fixture.root.conversation_id,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlstate(message(&mut c, &f.scope, chat.id, Some(&foreign)).await),
        "23503"
    );
    let self_parent = sqlx::query(
        "INSERT INTO openmettle.messages(id,scope_id,conversation_id,parent_message_id)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$1::uuid)",
    )
    .bind(INPUT)
    .bind(&f.scope)
    .bind(chat.id)
    .execute(&mut c)
    .await;
    assert_eq!(sqlstate(self_parent), "23514");
    let self_parent=sqlx::query("INSERT INTO openmettle.branch_heads(scope_id,conversation_id,branch_id,parent_branch_id)
        SELECT scope_id,conversation_id,branch_id,branch_id FROM openmettle.branch_heads WHERE branch_id=$1::uuid")
        .bind(&f.root.branch_id).execute(&mut c).await;
    assert_eq!(sqlstate(self_parent), "23514");
    sqlx::query(
        "UPDATE openmettle.storage_instance SET instance_budget_bytes=100,personal_limit_bytes=100",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let foreign_rev = revision(&mut c, &other_fixture).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let con = tx.connection().unwrap();
    let id = message(con, &f.scope, chat.id, None).await.unwrap();
    sqlx::query(
        "INSERT INTO openmettle.message_turns(scope_id,conversation_id,message_id,author_user_id)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid)",
    )
    .bind(&f.scope)
    .bind(chat.id)
    .bind(&id)
    .bind(&f.actor.user)
    .execute(&mut *con)
    .await
    .unwrap();
    let invalid=sqlx::query("INSERT INTO openmettle.message_parts(scope_id,conversation_id,message_id,ordinal,kind,artifact_revision_id)
        VALUES ($1::uuid,$2::uuid,$3::uuid,0,'attachment',$4::uuid)").bind(&f.scope).bind(chat.id).bind(&id).bind(&foreign_rev).execute(con).await;
    assert_eq!(sqlstate(invalid), "23503");
    tx.rollback().await.unwrap();

    // The writer validates eagerly; raw SQL still cannot publish gaps, empty user input or
    // two individually valid parts whose UTF-8 bytes together exceed the message limit.
    for (ordinal, bytes, count) in [(1, 1, 1), (0, 0, 1), (0, 32769, 2)] {
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let con = tx.connection().unwrap();
        let id = message(con, &f.scope, chat.id, None).await.unwrap();
        sqlx::query("INSERT INTO openmettle.message_turns(scope_id,conversation_id,message_id,author_user_id)
            VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid)").bind(&f.scope).bind(chat.id).bind(&id)
            .bind(&f.actor.user).execute(&mut *con).await.unwrap();
        for i in 0..count {
            sqlx::query("INSERT INTO openmettle.message_parts(scope_id,conversation_id,message_id,ordinal,kind,text_value)
                VALUES ($1::uuid,$2::uuid,$3::uuid,$4,'text',repeat('x',$5))")
                .bind(&f.scope).bind(chat.id).bind(&id).bind(ordinal+i).bind(bytes).execute(&mut *con).await.unwrap();
        }
        let invalid = sqlx::query(
            "UPDATE openmettle.branch_heads SET head_message_id=$1::uuid WHERE branch_id=$2::uuid",
        )
        .bind(&id)
        .bind(&f.root.branch_id)
        .execute(con)
        .await;
        assert_eq!(sqlstate(invalid), "23514");
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn archived_project_allows_authorized_create_replay_and_refuses_new_graph_writes() {
    use openmettle_core::authz::projects::{self, ProjectSettingsInput};
    let db = TestDb::migrated().await;
    let f = Fixture::new(&db).await;
    let mut c = api(&db).await;
    let project = authz_store::applied(
        projects::create_project(
            &mut c,
            &ctx(&f.actor, "project"),
            &ProjectSettingsInput {
                name: "Fixture project",
                instructions: "project layer",
                defaults: &json!({"model_config":{"preset":"study"}}),
            },
        )
        .await,
    );
    let settings = projects::load_project_settings(&mut c, &project)
        .await
        .unwrap()
        .unwrap();
    let defaults = Selection::project(&settings).unwrap();
    assert_eq!(defaults.preset.as_deref(), Some("study"));
    let root = authz_store::applied(
        branches::create_conversation(&mut c, &ctx(&f.actor, "project-chat"), &settings.scope_id)
            .await,
    );
    let chat = Conversation {
        scope: &settings.scope_id,
        id: &root.conversation_id,
    };
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    branches::prepare_turn(
        &mut tx,
        &ctx(&f.actor, "project-turn"),
        chat,
        &root.branch_id,
        None,
        Operation::Append(UserInput {
            id: INPUT,
            parts: &[Part::Text("fixture".into())],
        }),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let source = Some(Fork {
        branch: &root.branch_id,
        ancestor: INPUT,
    });
    let child = authz_store::applied(
        branches::create_branch(&mut c, &ctx(&f.actor, "project-fork"), chat, source).await,
    );
    projects::archive_project(&mut c, &ctx(&f.actor, "archive"), &project)
        .await
        .unwrap();
    let WriteOutcome::Replayed { target_id } =
        branches::create_conversation(&mut c, &ctx(&f.actor, "project-chat"), chat.scope)
            .await
            .unwrap()
    else {
        panic!("expected archived conversation replay")
    };
    assert_eq!(target_id, root);
    assert_eq!(
        branches::create_branch(&mut c, &ctx(&f.actor, "project-fork"), chat, source)
            .await
            .unwrap(),
        WriteOutcome::Replayed { target_id: child }
    );
    assert_eq!(
        authz_store::conflict(
            branches::create_branch(&mut c, &ctx(&f.actor, "another-fork"), chat, source).await
        ),
        "project is archived"
    );
    assert_eq!(
        authz_store::conflict(
            branches::create_conversation(&mut c, &ctx(&f.actor, "another-chat"), chat.scope).await
        ),
        "project is archived"
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM openmettle.authorization_audit WHERE request_key IN ('another-chat','another-fork')")
        .fetch_one(&mut c).await.unwrap(),0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn populated_v32_upgrade_adds_stop_reason_and_enforces_constraint() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..32])
        .await
        .unwrap();
    super::run_admission::seed_token_budget(&db).await;
    let f = Fixture::new(&db).await;
    let chat = f.chat();
    let root = &f.root.branch_id;
    let mut c = api(&db).await;
    let mut w = worker(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    let actor = authz_store::principal(&db, &f.actor).await;

    // Populate a user turn and an assistant turn at schema 32 before migrating to 33.
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let prepared = branches::prepare_turn(
        &mut tx,
        &ctx(&f.actor, "pre-33-submit"),
        chat,
        root,
        None,
        Operation::Append(UserInput {
            id: INPUT,
            parts: &[Part::Text("before upgrade".into())],
        }),
    )
    .await
    .unwrap();
    let limits = AdmissionLimits {
        live_per_actor: 10,
        live_per_scope: 10,
        queued_in_instance: 10,
        queue_timeout: Duration::from_secs(60),
        round_cap: 10,
    };
    let Admission::Admitted { .. } = queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &f.scope,
                actor: &f.actor.user,
                conversation: chat.id,
                branch: &prepared.branch_id,
                message: &prepared.input_message_id,
                key: "pre-33-submit",
                format: "legacy",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &f.actor.approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("admission")
    };
    tx.commit().await.unwrap();
    let claim = queue::claim_next(
        &mut w,
        &super::run_admission::OPEN,
        &super::run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    // Pre-migration-33 binaries / schema 32 fail closed on stop_reason = Some("limit"),
    // while normal turns (stop_reason = None) and history reads continue working cleanly.
    let mut pre_limit_tx = WriteTransaction::begin(&mut w).await.unwrap();
    let pre_limit_err = branches::publish_answer(
        &mut pre_limit_tx,
        &claim.lease(),
        &Answer {
            id: ANSWER,
            parts: &[Part::Text("cannot persist limit on v32".into())],
            reasoning: None,
            input_count: Some(10),
            output_count: Some(5),
            stop_reason: Some("limit"),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        pre_limit_err,
        openmettle_core::authz::leases::LeaseError::Store(StoreError::InvalidInput(
            "assistant turn"
        ))
    ));
    pre_limit_tx.rollback().await.unwrap();

    let mut wtx = WriteTransaction::begin(&mut w).await.unwrap();
    branches::publish_answer(
        &mut wtx,
        &claim.lease(),
        &Answer {
            id: ANSWER,
            parts: &[Part::Text("pre-upgrade answer".into())],
            reasoning: None,
            input_count: Some(10),
            output_count: Some(5),
            stop_reason: None,
        },
    )
    .await
    .unwrap();
    wtx.commit().await.unwrap();
    openmettle_core::authz::leases::settle(
        &mut w,
        &claim.lease(),
        &super::run_admission::LEASES,
        openmettle_core::authz::leases::Settle::Succeeded,
    )
    .await
    .unwrap();
    let pre_history = branches::history(&mut c, &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pre_history.turns.len(), 2);
    assert_eq!(pre_history.turns[0].stop_reason, None);
    assert_eq!(pre_history.turns[1].stop_reason, None);

    let before = snapshot_nonempty_at(&mut owner, &["message_turns"], 32).await;
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(
        snapshot_nonempty_at(&mut owner, &["message_turns"], 32).await,
        before
    );

    // Pre-existing rows read back with stop_reason = None.
    let history = branches::history(&mut c, &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(history.turns.len(), 2);
    assert_eq!(history.turns[0].stop_reason, None);
    assert_eq!(history.turns[1].stop_reason, None);

    // Admit a second run and verify the new CHECK constraint and library validation.
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let second = branches::prepare_turn(
        &mut tx,
        &ctx(&f.actor, "post-33-submit"),
        chat,
        root,
        Some(ANSWER),
        Operation::Append(UserInput {
            id: NEXT,
            parts: &[Part::Text("after upgrade".into())],
        }),
    )
    .await
    .unwrap();
    let Admission::Admitted { run_id: run2, .. } = queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &f.scope,
                actor: &f.actor.user,
                conversation: chat.id,
                branch: &second.branch_id,
                message: &second.input_message_id,
                key: "post-33-submit",
                format: "legacy",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &f.actor.approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("admission")
    };
    tx.commit().await.unwrap();
    let claim2 = queue::claim_next(
        &mut w,
        &super::run_admission::OPEN,
        &super::run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();

    // Unknown stop_reason values fail closed at both the library and SQL CHECK layers.
    for bad in ["other", "length", ""] {
        let mut bad_tx = WriteTransaction::begin(&mut w).await.unwrap();
        let err = branches::publish_answer(
            &mut bad_tx,
            &claim2.lease(),
            &Answer {
                id: EDIT,
                parts: &[Part::Text("bad".into())],
                reasoning: None,
                input_count: None,
                output_count: None,
                stop_reason: Some(bad),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            openmettle_core::authz::leases::LeaseError::Store(StoreError::InvalidInput(
                "assistant turn"
            ))
        ));
        bad_tx.rollback().await.unwrap();

        let mut sql_tx = WriteTransaction::begin(&mut w).await.unwrap();
        let con = sql_tx.connection().unwrap();
        let msg = message(con, &f.scope, chat.id, Some(NEXT)).await.unwrap();
        let res = sqlx::query(
            "INSERT INTO openmettle.message_turns
             (scope_id,conversation_id,message_id,run_id,stop_reason)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5)",
        )
        .bind(&f.scope)
        .bind(chat.id)
        .bind(msg)
        .bind(&run2)
        .bind(bad)
        .execute(con)
        .await;
        assert_eq!(sqlstate(res), "23514", "stop_reason={bad:?}");
        sql_tx.rollback().await.unwrap();
    }

    // Even openmettle_owner cannot set stop_reason on a user turn.
    let mut owner_tx = WriteTransaction::begin(&mut owner).await.unwrap();
    let ocon = owner_tx.connection().unwrap();
    let user_msg = message(ocon, &f.scope, chat.id, Some(NEXT)).await.unwrap();
    let user_res = sqlx::query(
        "INSERT INTO openmettle.message_turns
         (scope_id,conversation_id,message_id,author_user_id,stop_reason)
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'limit')",
    )
    .bind(&f.scope)
    .bind(chat.id)
    .bind(user_msg)
    .bind(&f.actor.user)
    .execute(ocon)
    .await;
    assert_eq!(sqlstate(user_res), "23514");
    owner_tx.rollback().await.unwrap();

    // Valid assistant turn with stop_reason = Some("limit") publishes and reads back cleanly.
    let mut ok_tx = WriteTransaction::begin(&mut w).await.unwrap();
    branches::publish_answer(
        &mut ok_tx,
        &claim2.lease(),
        &Answer {
            id: EDIT,
            parts: &[Part::Text("cut off at limit".into())],
            reasoning: None,
            input_count: Some(21),
            output_count: Some(12),
            stop_reason: Some("limit"),
        },
    )
    .await
    .unwrap();
    ok_tx.commit().await.unwrap();

    let updated = branches::history(&mut c, &actor, chat, root, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.turns[0].metadata.message_id, EDIT);
    assert_eq!(updated.turns[0].stop_reason.as_deref(), Some("limit"));
    assert_eq!(updated.turns[1].stop_reason, None);
    assert_eq!(updated.turns[2].stop_reason, None);
}

#[path = "branches_http.rs"]
mod branches_http;
