//! ADR 0042 PR2: fenced capacity controller store and device-slot reconciliation on
//! PostgreSQL 18. All identities, devices and byte counts are synthetic.
use super::*;
use openmettle_core::{
    authz::{
        leases::LeaseSettings,
        runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
    },
    capacity::{
        self, Controller, Decision, DeviceBytes, DeviceObservation, Error, Evidence, GrantRequest,
        GrantState, Observation,
    },
    quotas::{self, RunBudgetReservation},
    runs::{RunInput, WriteTransaction},
};

const GROUP: &str = "00000000-0000-4000-8000-00000000c001";
const GROUP_B: &str = "00000000-0000-4000-8000-00000000c002";
const GPU0: &str = "00000000-0000-4000-8000-00000000c0d0";
const GPU1: &str = "00000000-0000-4000-8000-00000000c0d1";
const GIB: i64 = 1 << 30;
/// 24 GiB device: chat uses its 16 GiB floor, 1 GiB headroom, so 7 GiB is grantable.
const TOTAL: i64 = 24 * GIB;
const FLOOR: i64 = 16 * GIB;
const HEADROOM: i64 = GIB;
const SPARE: i64 = TOTAL - FLOOR - HEADROOM;
const LEASE: Duration = Duration::from_secs(60);

/// One leased run and its run-level `device_reservations` hold, when metering created one.
struct Leased {
    run: String,
    claim: String,
    hold: Option<String>,
}

struct Fixture {
    db: TestDb,
    owner: PgConnection,
    scope: String,
    runs: Vec<Leased>,
}

impl Fixture {
    /// A metered installation: every claimed run holds one device slot.
    async fn new(devices: &[&str], runs: usize) -> Self {
        Self::with(devices, runs, true).await
    }

    /// A group with `devices` configured and `runs` claimed runs. Without metering (an upgraded
    /// installation before activation), admission creates no quota holds.
    async fn with(devices: &[&str], runs: usize, metered: bool) -> Self {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        if !metered {
            migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        }
        migrate::apply(&settings, MIGRATIONS).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        authz_store::providers(&mut owner).await;
        let alice =
            authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE)
                .await;
        let scope = authz_runs::personal_of(&db, &alice).await;
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'usage_tokens', 1000000),
                        ('personal', 'device_reservations', 8)",
            )
            .await
            .unwrap();
        for group in [GROUP, GROUP_B] {
            sqlx::query(
                "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms)
                 VALUES ($1::uuid, 60000)",
            )
            .bind(group)
            .execute(&mut owner)
            .await
            .unwrap();
        }
        for device in devices {
            sqlx::query(
                "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
                 VALUES ($1::uuid, $2::uuid, $3)",
            )
            .bind(device)
            .bind(GROUP)
            .bind(FLOOR)
            .execute(&mut owner)
            .await
            .unwrap();
        }
        let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
        let mut api = connect(&db.0, API).await;
        let (branch, message) = super::quotas::branch_and_message(&mut api, &scope, &chat).await;
        let limits = AdmissionLimits {
            live_per_actor: 16,
            live_per_scope: 16,
            queued_in_instance: 32,
            queue_timeout: Duration::from_secs(300),
            round_cap: 4,
        };
        for i in 0..runs {
            let key = format!("capacity-run-{i}");
            let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
            let Admission::Admitted { run_id, .. } = authz_queue::admit_run(
                &mut tx,
                &RunAdmission {
                    input: RunInput {
                        scope: &scope,
                        actor: &alice.user,
                        conversation: &chat,
                        branch: &branch,
                        message: &message,
                        key: &key,
                        format: "openmettle.conversation",
                        version: 1,
                        input: b"{}",
                        config: b"{}",
                    },
                    actor_approval_id: &alice.approval,
                    capabilities: &[],
                    requested_rounds: Some(1),
                    now_ms: authz_store::NOW,
                    cost_qualified: None,
                },
                &limits,
            )
            .await
            .unwrap() else {
                panic!("expected admission");
            };
            assert!(
                quotas::reserve_admitted_run_budget(
                    &mut tx,
                    &RunBudgetReservation {
                        scope_id: &scope,
                        scope_kind: "personal",
                        actor_user_id: &alice.user,
                        actor_approval_id: &alice.approval,
                        run_id: &run_id,
                        token_units: 100,
                        per_round_cost_micros: None,
                        round_limit: 1,
                        requires_device_slot: true,
                    },
                )
                .await
                .unwrap()
                .is_none()
            );
            tx.commit().await.unwrap();
        }
        let mut worker = connect(&db.0, WORKER).await;
        let mut leased = Vec::new();
        for _ in 0..runs {
            let claim = authz_queue::claim_next(
                &mut worker,
                &ClaimLimits {
                    executing_per_actor: 16,
                    executing_per_scope: 16,
                },
                &LeaseSettings {
                    lease: Duration::from_secs(60),
                    execution_timeout: Duration::from_secs(600),
                },
            )
            .await
            .unwrap()
            .unwrap();
            let hold: Option<String> = sqlx::query_scalar(
                "SELECT id::text FROM openmettle.quota_reservations
                  WHERE run_id = $1::uuid AND gateway_request_id IS NULL
                    AND resource_kind = 'device_reservations'",
            )
            .bind(&claim.run_id)
            .fetch_optional(&mut owner)
            .await
            .unwrap();
            assert_eq!(hold.is_some(), metered);
            leased.push(Leased {
                run: claim.run_id,
                claim: claim.claim_token,
                hold,
            });
        }
        leased.sort_by(|a, b| a.run.cmp(&b.run));
        Self {
            db,
            owner,
            scope,
            runs: leased,
        }
    }

    async fn worker(&self) -> PgConnection {
        connect(&self.db.0, WORKER).await
    }

    fn request<'a>(
        &'a self,
        run: usize,
        key: &'a str,
        footprint: &'a [DeviceBytes],
    ) -> GrantRequest<'a> {
        GrantRequest {
            scope_id: &self.scope,
            run_id: &self.runs[run].run,
            claim_token: &self.runs[run].claim,
            request_key: key,
            profile: "synthetic-image",
            footprint,
        }
    }

    /// (state, grant) of a run's device slot, and the scope's device `reserved_held`.
    async fn slot(&mut self, run: usize) -> (String, Option<String>, i64) {
        sqlx::query_as(
            "SELECT h.state, h.device_grant_id::text,
                    (SELECT reserved_held::bigint FROM openmettle.quota_budgets
                      WHERE scope_id = h.scope_id AND resource_kind = 'device_reservations')
               FROM openmettle.quota_reservations h WHERE h.id = $1::uuid",
        )
        .bind(self.runs[run].hold.as_deref().unwrap())
        .fetch_one(&mut self.owner)
        .await
        .unwrap()
    }

    async fn owner_exec(&mut self, sql: &str, binds: &[&str]) {
        let mut query = sqlx::query(AssertSqlSafe(sql.to_owned()));
        for bind in binds {
            query = query.bind(*bind);
        }
        query.execute(&mut self.owner).await.unwrap();
    }

    async fn expire_controller_lease(&mut self) {
        self.owner_exec(
            "UPDATE openmettle.capacity_groups
                SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
            &[GROUP],
        )
        .await;
    }

    async fn expire_run_lease(&mut self, run: usize) {
        let id = self.runs[run].run.clone();
        self.owner_exec(
            "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() - interval '1 second'
              WHERE id = $1::uuid",
            &[&id],
        )
        .await;
    }

    /// Give run `run` a claim lasting `lease`, then decide a 1 GiB grant for it while another
    /// session holds `lock` (bound to run `hold`'s device slot, if given) for two seconds.
    async fn grant_behind_lock(
        &mut self,
        controller: &Controller,
        run: usize,
        lock: &str,
        lease: &str,
        hold: Option<usize>,
    ) -> Result<Decision, Error> {
        let id = self.runs[run].run.clone();
        self.owner_exec(
            "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() + $2::interval
              WHERE id = $1::uuid",
            &[&id, lease],
        )
        .await;
        let mut blocker = connect(&self.db.0, OWNER).await;
        let mut held = blocker.begin().await.unwrap();
        let mut query = sqlx::query(AssertSqlSafe(lock.to_owned()));
        if let Some(hold) = hold {
            query = query.bind(self.runs[hold].hold.clone().unwrap());
        }
        query.execute(&mut *held).await.unwrap();
        let need = [bytes(GPU0, GIB)];
        let key = format!("behind-lock-{run}");
        let request = self.request(run, &key, &need);
        let mut w = self.worker().await;
        let db = &self.db;
        let (decision, ()) =
            tokio::join!(capacity::grant(&mut w, controller, &request), async move {
                authz_store::wait_for_lock_waiters(db, 1).await;
                tokio::time::sleep(Duration::from_millis(2000)).await;
                held.commit().await.unwrap();
            });
        decision
    }

    /// Change the group's configured freshness TTL, as an operator would.
    async fn ttl(&mut self, ms: &str) {
        self.owner_exec(
            "UPDATE openmettle.capacity_groups SET observation_ttl_ms = $2::integer
              WHERE id = $1::uuid",
            &[GROUP, ms],
        )
        .await;
    }

    async fn grants(&mut self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM openmettle.capacity_grants")
            .fetch_one(&mut self.owner)
            .await
            .unwrap()
    }

    async fn drift(&mut self) -> (i64, i64, i64, i64) {
        sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                    pending_gateway_reconciliations FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut connect(&self.db.0, WORKER).await)
        .await
        .unwrap()
    }
}

fn bytes(device: &str, bytes: i64) -> DeviceBytes {
    DeviceBytes {
        device_id: device.into(),
        bytes,
    }
}

/// A device sample whose chat use covers the floor, with `committed` outstanding grant bytes.
fn sample(device: &str, committed: i64, grantable: i64) -> DeviceObservation {
    DeviceObservation {
        device_id: device.into(),
        total_bytes: TOTAL,
        committed_bytes: committed,
        actual_used_bytes: FLOOR,
        reclaimable_bytes: 0,
        safety_headroom_bytes: HEADROOM,
        active_chat_floor_bytes: FLOOR,
        grantable_bytes: grantable,
    }
}

async fn db_now_us(c: &mut PgConnection) -> i64 {
    sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint")
        .fetch_one(c)
        .await
        .unwrap()
}

async fn publish(
    c: &mut PgConnection,
    controller: &Controller,
    revision: i64,
    watermark: i64,
    devices: &[DeviceObservation],
) -> Result<bool, Error> {
    let observed_at_us = db_now_us(c).await;
    capacity::publish(
        c,
        controller,
        &Observation {
            revision,
            observed_at_us,
            commit_watermark: watermark,
            devices,
        },
    )
    .await
}

fn granted(decision: Decision) -> String {
    match decision {
        Decision::Grant {
            grant_id,
            state: GrantState::Granted,
        } => grant_id,
        other => panic!("expected a new grant, got {other:?}"),
    }
}

async fn admits(c: &mut PgConnection) -> bool {
    capacity::snapshot(c, GROUP)
        .await
        .unwrap()
        .unwrap()
        .admits_bursts
}

/// Hold `lock` (with `bind`, if any) in another session, run `write`, and release the lock
/// 1.5 s after `write` starts waiting on it.
async fn behind_lock<T>(
    db: &TestDb,
    lock: &str,
    bind: Option<&str>,
    write: impl std::future::Future<Output = T>,
) -> T {
    let mut blocker = connect(&db.0, OWNER).await;
    let mut held = blocker.begin().await.unwrap();
    let mut query = sqlx::query(AssertSqlSafe(lock.to_owned()));
    if let Some(bind) = bind {
        query = query.bind(bind.to_owned());
    }
    query.execute(&mut *held).await.unwrap();
    let (out, ()) = tokio::join!(write, async move {
        authz_store::wait_for_lock_waiters(db, 1).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        held.commit().await.unwrap();
    });
    out
}

/// The group row's epoch, deadline, revision and ready epoch.
async fn group_state(c: &mut PgConnection) -> (i64, String, i64, Option<i64>) {
    sqlx::query_as(
        "SELECT controller_epoch, lease_expires_at::text, observation_revision, ready_epoch
           FROM openmettle.capacity_groups WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .fetch_one(c)
    .await
    .unwrap()
}

/// Acquire, publish a full-spare snapshot at `revision` and resume: the group admits bursts.
async fn open_group(c: &mut PgConnection, revision: i64, devices: &[&str]) -> Controller {
    let controller = Controller::acquire(c, GROUP, LEASE).await.unwrap();
    let samples: Vec<_> = devices.iter().map(|d| sample(d, 0, SPARE)).collect();
    assert!(
        publish(c, &controller, revision, 0, &samples)
            .await
            .unwrap()
    );
    assert!(capacity::resume(c, &controller).await.unwrap());
    controller
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn racing_callers_citing_one_revision_cannot_double_spend_the_last_bytes() {
    let mut f = Fixture::new(&[GPU0], 3).await;
    let mut ctl = f.worker().await;
    let controller = open_group(&mut ctl, 1, &[GPU0]).await;
    let snapshot = capacity::snapshot(&mut ctl, GROUP).await.unwrap().unwrap();
    assert!(snapshot.admits_bursts);
    assert_eq!(snapshot.observation_revision, 1);
    assert_eq!(snapshot.totals().grantable_bytes, i128::from(SPARE));

    // Both callers cite revision 1, which leaves room for only one 4 GiB footprint. Hold the
    // group row until both decisions wait on it so they contend for the same bytes.
    let need = [bytes(GPU0, 4 * GIB)];
    let (r0, r1) = (f.request(0, "race-0", &need), f.request(1, "race-1", &need));
    let (mut w0, mut w1) = (f.worker().await, f.worker().await);
    let mut blocker = connect(&f.db.0, OWNER).await;
    let mut held = blocker.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.capacity_groups WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(GROUP)
        .execute(&mut *held)
        .await
        .unwrap();
    let db = &f.db;
    let (a, b, ()) = tokio::join!(
        capacity::grant(&mut w0, &controller, &r0),
        capacity::grant(&mut w1, &controller, &r1),
        async move {
            authz_store::wait_for_lock_waiters(db, 2).await;
            held.commit().await.unwrap();
        }
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    let winners: Vec<usize> = (0..2)
        .filter(|&i| matches!(outcomes[i], Decision::Grant { .. }))
        .collect();
    assert_eq!(winners.len(), 1, "{outcomes:?}");
    let (won, lost) = (winners[0], 1 - winners[0]);
    assert_eq!(outcomes[lost], Decision::Insufficient);
    let grant = granted(outcomes[won].clone());

    // Only the winner's slot is committed; the loser keeps an unbound held slot.
    let (state, bound, held_slots) = f.slot(won).await;
    assert_eq!(
        (state.as_str(), bound.as_deref()),
        ("handoff_committed", Some(grant.as_str()))
    );
    assert_eq!(held_slots, 3);
    let (state, bound, _) = f.slot(lost).await;
    assert_eq!((state.as_str(), bound), ("held", None));

    // The remaining 3 GiB fit; one byte more would spend the chat floor or headroom.
    let over = [bytes(GPU0, 3 * GIB + 1)];
    assert_eq!(
        capacity::grant(&mut ctl, &controller, &f.request(2, "over", &over))
            .await
            .unwrap(),
        Decision::Insufficient
    );
    let rest = [bytes(GPU0, 3 * GIB)];
    granted(
        capacity::grant(&mut ctl, &controller, &f.request(2, "rest", &rest))
            .await
            .unwrap(),
    );
    let charged: i64 = sqlx::query_scalar(
        "SELECT sum(bytes)::bigint FROM openmettle.capacity_grant_devices WHERE device_id = $1::uuid",
    )
    .bind(GPU0)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(charged, SPARE);
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn takeover_fences_delayed_old_epoch_writes_and_reopens_only_after_fresh_recovery() {
    let mut f = Fixture::new(&[GPU0], 2).await;
    let mut a = f.worker().await;
    let old = open_group(&mut a, 1, &[GPU0]).await;
    assert_eq!(old.epoch(), 1);
    let first = granted(
        capacity::grant(
            &mut a,
            &old,
            &f.request(0, "first", &[bytes(GPU0, 4 * GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        capacity::reconcile(&mut a, &old, &first, Evidence::Releasing)
            .await
            .unwrap(),
        GrantState::Releasing
    );
    let measured_before_takeover = db_now_us(&mut a).await;

    // Worker-readable rows never confer authority: neither the stored hash nor a guess passes.
    let (hash, epoch): (Vec<u8>, i64) = sqlx::query_as(
        "SELECT controller_token_hash, controller_epoch FROM openmettle.capacity_groups
          WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .fetch_one(&mut a)
    .await
    .unwrap();
    for secret in [hash, vec![0; 32]] {
        assert_eq!(
            sqlstate(
                sqlx::query(
                    "SELECT openmettle.capacity_reconcile($1::uuid, $2, $3, $4::uuid,
                         'released', ARRAY[$5::uuid])",
                )
                .bind(GROUP)
                .bind(&secret)
                .bind(epoch)
                .bind(&first)
                .bind(GPU0)
                .execute(&mut a)
                .await
            ),
            "OMC01"
        );
        assert_eq!(
            sqlstate(
                sqlx::query("SELECT openmettle.capacity_renew_controller($1::uuid, $2, $3, 60000)")
                    .bind(GROUP)
                    .bind(&secret)
                    .bind(epoch)
                    .execute(&mut a)
                    .await
            ),
            "OMC01"
        );
    }

    // A live lease cannot be taken over; renewal extends it; an expired one advances the epoch.
    let mut b = f.worker().await;
    assert_eq!(
        Controller::acquire(&mut b, GROUP, LEASE).await.unwrap_err(),
        Error::Fenced
    );
    old.renew(&mut a, LEASE).await.unwrap();
    f.expire_controller_lease().await;
    assert!(!admits(&mut b).await);
    assert_eq!(old.renew(&mut a, LEASE).await, Err(Error::Fenced));
    let new = Controller::acquire(&mut b, GROUP, LEASE).await.unwrap();
    assert_eq!(new.epoch(), 2);

    // Every delayed write from epoch 1 is refused and changes nothing.
    assert_eq!(
        publish(&mut a, &old, 2, 1, &[sample(GPU0, 4 * GIB, 0)]).await,
        Err(Error::Fenced)
    );
    assert_eq!(
        capacity::grant(&mut a, &old, &f.request(1, "late", &[bytes(GPU0, GIB)])).await,
        Err(Error::Fenced)
    );
    assert_eq!(
        capacity::reconcile(&mut a, &old, &first, Evidence::Released(&[GPU0.into()])).await,
        Err(Error::Fenced)
    );
    assert_eq!(capacity::resume(&mut a, &old).await, Err(Error::Fenced));
    let snapshot = capacity::snapshot(&mut b, GROUP).await.unwrap().unwrap();
    assert_eq!(
        (snapshot.controller_epoch, snapshot.observation_revision),
        (2, 1)
    );
    assert!(!snapshot.admits_bursts);
    let state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&first)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(state, "releasing");
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(first.clone()), 2)
    );

    // The successor stays closed until it publishes a sample measured in its own epoch and
    // attests the earlier grant against its fenced inventory.
    assert_eq!(
        capacity::grant(&mut b, &new, &f.request(1, "early", &[bytes(GPU0, GIB)]))
            .await
            .unwrap(),
        Decision::Unavailable
    );
    assert!(!capacity::resume(&mut b, &new).await.unwrap());
    assert_eq!(
        capacity::publish(
            &mut b,
            &new,
            &Observation {
                revision: 2,
                observed_at_us: measured_before_takeover,
                commit_watermark: 1,
                devices: &[sample(GPU0, 4 * GIB, SPARE - 4 * GIB)],
            },
        )
        .await,
        Err(Error::Invalid)
    );
    // The revision sequence survives the epoch change: an older revision is ignored.
    assert!(
        !publish(&mut b, &new, 1, 1, &[sample(GPU0, 4 * GIB, 0)])
            .await
            .unwrap()
    );
    assert!(
        publish(
            &mut b,
            &new,
            2,
            1,
            &[sample(GPU0, 4 * GIB, SPARE - 4 * GIB)]
        )
        .await
        .unwrap()
    );
    assert!(!capacity::resume(&mut b, &new).await.unwrap());
    assert_eq!(
        capacity::reconcile(&mut b, &new, &first, Evidence::Allocated)
            .await
            .unwrap(),
        GrantState::Releasing
    );
    assert!(capacity::resume(&mut b, &new).await.unwrap());

    // The releasing grant is still charged and the chat floor stays protected.
    assert_eq!(
        capacity::grant(
            &mut b,
            &new,
            &f.request(1, "after", &[bytes(GPU0, 3 * GIB + 1)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    let second = granted(
        capacity::grant(
            &mut b,
            &new,
            &f.request(1, "after-fit", &[bytes(GPU0, 3 * GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        capacity::reconcile(&mut b, &new, &first, Evidence::Released(&[GPU0.into()]))
            .await
            .unwrap(),
        GrantState::Released
    );
    assert_eq!(f.slot(0).await, ("released".into(), Some(first), 1));

    // The epoch alone fences a holder that re-acquires with the same secret after a lapse.
    f.expire_controller_lease().await;
    let reused = [7u8; 32];
    let acquire = |c: &'static str| {
        sqlx::query_scalar::<_, i64>(c)
            .bind(GROUP)
            .bind(reused.as_slice())
    };
    let sql = "SELECT openmettle.capacity_acquire_controller($1::uuid, $2, 60000)";
    let lapsed = acquire(sql).fetch_one(&mut b).await.unwrap();
    f.expire_controller_lease().await;
    assert_eq!(acquire(sql).fetch_one(&mut b).await.unwrap(), lapsed + 1);
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.capacity_resume($1::uuid, $2, $3)")
                .bind(GROUP)
                .bind(reused.as_slice())
                .bind(lapsed)
                .execute(&mut b)
                .await
        ),
        "OMC01"
    );
    assert_eq!(
        f.slot(1).await,
        ("handoff_committed".into(), Some(second), 1)
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn stale_or_inconsistent_observations_cannot_justify_a_grant() {
    let mut f = Fixture::new(&[GPU0, GPU1], 2).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0, GPU1]).await;
    let full = [sample(GPU0, 0, SPARE), sample(GPU1, 0, SPARE)];

    // Refused samples: a missing rank, a duplicate rank, an unconfigured device, a floor below
    // the configured minimum, grantable bytes that spend the floor, an uncited commitment
    // watermark and a measurement from the future.
    let mut low_floor = sample(GPU1, 0, SPARE);
    low_floor.active_chat_floor_bytes = FLOOR - 1;
    low_floor.actual_used_bytes = FLOOR - 1;
    let unknown = "00000000-0000-4000-8000-00000000c0ff";
    for devices in [
        vec![sample(GPU0, 0, SPARE)],
        vec![sample(GPU0, 0, SPARE), sample(GPU0, 0, SPARE)],
        vec![sample(GPU0, 0, SPARE), sample(unknown, 0, SPARE)],
        vec![sample(GPU0, 0, SPARE), low_floor],
        vec![sample(GPU0, 0, SPARE), sample(GPU1, 0, SPARE + 1)],
    ] {
        assert_eq!(
            publish(&mut c, &controller, 2, 0, &devices).await,
            Err(Error::Invalid)
        );
    }
    assert_eq!(
        publish(&mut c, &controller, 2, 1, &full).await,
        Err(Error::Invalid)
    );
    let future = db_now_us(&mut c).await + 60_000_000;
    assert_eq!(
        capacity::publish(
            &mut c,
            &controller,
            &Observation {
                revision: 2,
                observed_at_us: future,
                commit_watermark: 0,
                devices: &full,
            },
        )
        .await,
        Err(Error::Invalid)
    );

    // A fresh sample admits a rank-constrained grant on both devices.
    let both = [bytes(GPU0, GIB), bytes(GPU1, GIB)];
    let first = granted(
        capacity::grant(&mut c, &controller, &f.request(0, "fresh", &both))
            .await
            .unwrap(),
    );

    // A sample claiming to include that grant must count it on every device.
    assert_eq!(
        publish(
            &mut c,
            &controller,
            2,
            1,
            &[sample(GPU0, GIB, SPARE - GIB), sample(GPU1, 0, SPARE - GIB)]
        )
        .await,
        Err(Error::Invalid)
    );
    let sampled_at = db_now_us(&mut c).await;
    let counted = [
        sample(GPU0, GIB, SPARE - GIB),
        sample(GPU1, GIB, SPARE - GIB),
    ];
    let at = |revision, observed_at_us| Observation {
        revision,
        observed_at_us,
        commit_watermark: 1,
        devices: &counted,
    };
    assert!(
        capacity::publish(&mut c, &controller, &at(2, sampled_at))
            .await
            .unwrap()
    );

    // Past the TTL the group closes, and republishing the old sample never extends freshness.
    f.ttl("1000").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let late = [bytes(GPU0, GIB)];
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(1, "stale", &late))
            .await
            .unwrap(),
        Decision::Unavailable
    );
    assert!(
        capacity::publish(&mut c, &controller, &at(3, sampled_at))
            .await
            .unwrap()
    );
    // A replayed revision is ignored even when it carries a newer measurement.
    assert!(!publish(&mut c, &controller, 3, 1, &counted).await.unwrap());
    let snapshot = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    assert_eq!(snapshot.observation_revision, 3);
    assert!(!snapshot.admits_bursts);
    assert!(!capacity::resume(&mut c, &controller).await.unwrap());
    assert_eq!(snapshot.totals().committed_bytes, i128::from(2 * GIB));
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(1, "stale", &late))
            .await
            .unwrap(),
        Decision::Unavailable
    );
    assert_eq!(
        capacity::publish(&mut c, &controller, &at(4, sampled_at - 1)).await,
        Err(Error::Invalid)
    );

    // A fresh sample reopens the group; the earlier grant stays charged on both ranks.
    f.ttl("60000").await;
    assert!(publish(&mut c, &controller, 4, 1, &counted).await.unwrap());
    assert_eq!(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(1, "fit", &[bytes(GPU1, SPARE - GIB + 1)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(1, "fit", &[bytes(GPU1, SPARE - GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(f.slot(0).await.1, Some(first));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_saturated_device_publishes_zero_spare_that_replaces_the_earlier_sample() {
    let f = Fixture::new(&[GPU0], 1).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    // Chat grows to fill the device: measured use exceeds what headroom allows.
    let full = DeviceObservation {
        actual_used_bytes: TOTAL,
        reclaimable_bytes: GIB,
        grantable_bytes: 0,
        ..sample(GPU0, 0, 0)
    };
    assert!(
        publish(&mut c, &controller, 2, 0, std::slice::from_ref(&full))
            .await
            .unwrap()
    );
    let snapshot = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    assert_eq!(
        (
            snapshot.observation_revision,
            snapshot.devices[0].grantable_bytes
        ),
        (2, 0)
    );
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(0, "one", &[bytes(GPU0, 1)]))
            .await
            .unwrap(),
        Decision::Insufficient
    );
    // Spare capacity clamps at zero: no byte is grantable while the device is saturated.
    let over = DeviceObservation {
        grantable_bytes: 1,
        ..full
    };
    assert_eq!(
        publish(&mut c, &controller, 3, 0, &[over]).await,
        Err(Error::Invalid)
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_recovers_the_recorded_decision_and_conflicting_reuse_is_refused() {
    let mut f = Fixture::new(&[GPU0], 2).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    let need = [bytes(GPU0, 2 * GIB)];
    let grant = granted(
        capacity::grant(&mut c, &controller, &f.request(0, "replay", &need))
            .await
            .unwrap(),
    );
    // A lost reply recovers the same grant without a second commitment.
    for _ in 0..2 {
        assert_eq!(
            capacity::grant(&mut c, &controller, &f.request(0, "replay", &need))
                .await
                .unwrap(),
            Decision::Grant {
                grant_id: grant.clone(),
                state: GrantState::Granted
            }
        );
    }
    let seq: i64 =
        sqlx::query_scalar("SELECT commit_seq FROM openmettle.capacity_groups WHERE id = $1::uuid")
            .bind(GROUP)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(seq, 1);
    // The identity cannot change the footprint, and the run cannot hold a second live grant.
    assert_eq!(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "replay", &[bytes(GPU0, GIB)])
        )
        .await,
        Err(Error::Conflict)
    );
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(0, "second", &need)).await,
        Err(Error::Conflict)
    );

    // Release confirmation settles both ledgers once; replays stay idempotent.
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(grant.clone()), 2)
    );
    for _ in 0..2 {
        assert_eq!(
            capacity::reconcile(
                &mut c,
                &controller,
                &grant,
                Evidence::Released(&[GPU0.into()])
            )
            .await
            .unwrap(),
            GrantState::Released
        );
    }
    assert_eq!(f.slot(0).await, ("released".into(), Some(grant.clone()), 1));
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT openmettle.quota_release_device_slot($1::uuid, $2::uuid)"
        )
        .bind(f.runs[0].hold.as_deref().unwrap())
        .bind(&grant)
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    let releases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.quota_reconciliations
          WHERE reservation_id = $1::uuid AND kind = 'release' AND delta_reserved = -1",
    )
    .bind(f.runs[0].hold.as_deref().unwrap())
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(releases, 1);
    // A replay after release reports the recorded outcome and never re-dispatches.
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(0, "replay", &need))
            .await
            .unwrap(),
        Decision::Grant {
            grant_id: grant,
            state: GrantState::Released
        }
    );
    // A metered run's slot backs one grant in PR2: once used, a new request is refused.
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(0, "after-release", &need)).await,
        Err(Error::SlotRequired)
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // Only the worker's fenced functions write the store.
    let mut api = connect(&f.db.0, API).await;
    expect_state(
        &mut api,
        "SELECT openmettle.capacity_acquire_controller(gen_random_uuid(), '\\x00'::bytea, 1000)",
        "42501",
    )
    .await;
    expect_state(&mut api, "SELECT FROM openmettle.capacity_grants", "42501").await;
    expect_state(
        &mut c,
        "UPDATE openmettle.capacity_grants SET state = 'released'",
        "42501",
    )
    .await;
    expect_state(
        &mut c,
        "UPDATE openmettle.capacity_groups SET controller_epoch = controller_epoch + 1",
        "42501",
    )
    .await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_metered_grant_needs_the_runs_held_slot_and_a_run_holds_one_live_grant() {
    let mut f = Fixture::with(&[GPU0], 2, false).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    // Before metering, a run may still hold only one live grant, whatever its request keys.
    granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "first", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "second", &[bytes(GPU0, GIB)])
        )
        .await,
        Err(Error::Conflict)
    );
    // A run admitted before metering activation holds no device slot, so it cannot obtain
    // physical capacity once metering is enforced.
    f.owner_exec(
        "UPDATE openmettle.quota_enforcement
            SET metering_enforced = true, metering_enforced_at = clock_timestamp() WHERE id",
        &[],
    )
    .await;
    assert_eq!(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(1, "metered", &[bytes(GPU0, GIB)])
        )
        .await,
        Err(Error::SlotRequired)
    );
    assert_eq!(f.grants().await, 1);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_claim_expiring_while_an_unmetered_decision_waits_for_a_lock_is_refused() {
    // Without metering there is no slot handoff; the group lock and the final enforcement-row
    // lock are the waits.
    let mut f = Fixture::with(&[GPU0], 2, false).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    for (run, lock) in [
        (
            0,
            "SELECT FROM openmettle.capacity_groups FOR NO KEY UPDATE",
        ),
        (1, "SELECT FROM openmettle.quota_enforcement FOR UPDATE"),
    ] {
        let decision = f
            .grant_behind_lock(&controller, run, lock, "1500 ms", None)
            .await;
        assert_eq!(decision, Err(Error::LeaseLost), "{lock}");
    }
    assert_eq!(f.grants().await, 0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn every_time_bound_is_rechecked_after_the_slot_handoff_waits() {
    // The quota handoff's reservation update is the metered path's last blocking statement.
    let mut f = Fixture::new(&[GPU0], 3).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    let hold_lock = "SELECT FROM openmettle.quota_reservations WHERE id = $1::uuid
                     FOR NO KEY UPDATE";
    // The run's claim expires during the wait.
    let decision = f
        .grant_behind_lock(&controller, 0, hold_lock, "1500 ms", Some(0))
        .await;
    assert_eq!(decision, Err(Error::LeaseLost));
    // The sample goes stale during the wait.
    f.ttl("1000").await;
    assert!(
        publish(&mut c, &controller, 2, 0, &[sample(GPU0, 0, SPARE)])
            .await
            .unwrap()
    );
    let decision = f
        .grant_behind_lock(&controller, 1, hold_lock, "60 s", Some(1))
        .await;
    assert_eq!(decision, Err(Error::Expired));
    // The controller's lease lapses during the wait.
    f.ttl("60000").await;
    assert!(
        publish(&mut c, &controller, 3, 0, &[sample(GPU0, 0, SPARE)])
            .await
            .unwrap()
    );
    controller
        .renew(&mut c, Duration::from_millis(1000))
        .await
        .unwrap();
    let decision = f
        .grant_behind_lock(&controller, 2, hold_lock, "60 s", Some(2))
        .await;
    assert_eq!(decision, Err(Error::Fenced));
    // Every decision rolled back: no grant, and every slot is still held.
    assert_eq!(f.grants().await, 0);
    for run in 0..3 {
        assert_eq!(f.slot(run).await, ("held".into(), None, 3));
    }
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn repeatable_read_cannot_decide_from_a_snapshot_before_a_closing_transition() {
    let f = Fixture::new(&[GPU0], 2).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    let first = granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "first", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
    let mut rr = f.worker().await;
    let mut tx = rr.begin().await.unwrap();
    tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    tx.execute("SELECT 1").await.unwrap();
    // The allocation becomes unknown after the REPEATABLE READ snapshot was taken.
    assert_eq!(
        capacity::reconcile(&mut c, &controller, &first, Evidence::UnknownAllocation)
            .await
            .unwrap(),
        GrantState::UnknownAllocation
    );
    let need = [bytes(GPU0, GIB)];
    assert_eq!(
        capacity::grant(&mut tx, &controller, &f.request(1, "stale-snapshot", &need)).await,
        Err(Error::Invalid)
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        capacity::grant(&mut c, &controller, &f.request(1, "current", &need))
            .await
            .unwrap(),
        Decision::Unavailable
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn raising_chat_floors_waits_for_decisions_without_deadlock_and_closes_the_group() {
    let f = Fixture::new(&[GPU0, GPU1], 1).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0, GPU1]).await;
    // The operator raises both floors in one open transaction, in the opposite device order to
    // the decision's footprint. The decision waits on the group, never on a device row, then
    // finds the published floors no longer cover the configuration.
    let mut operator = connect(&f.db.0, OWNER).await;
    let mut raise = operator.begin().await.unwrap();
    let floor = |device| {
        sqlx::query(
            "UPDATE openmettle.capacity_devices SET chat_floor_bytes = $2 WHERE id = $1::uuid",
        )
        .bind(device)
        .bind(FLOOR + GIB)
    };
    floor(GPU1).execute(&mut *raise).await.unwrap();
    let need = [bytes(GPU0, GIB), bytes(GPU1, GIB)];
    let request = f.request(0, "floor", &need);
    let db = &f.db;
    let (decision, ()) = tokio::join!(capacity::grant(&mut c, &controller, &request), async move {
        authz_store::wait_for_lock_waiters(db, 1).await;
        floor(GPU0).execute(&mut *raise).await.unwrap();
        raise.commit().await.unwrap();
    });
    assert_eq!(decision.unwrap(), Decision::Unavailable);
    assert!(!admits(&mut c).await);
    // A sample covering the raised floors reopens the group with one GiB less spare.
    let raised = |device| DeviceObservation {
        actual_used_bytes: FLOOR + GIB,
        active_chat_floor_bytes: FLOOR + GIB,
        ..sample(device, 0, SPARE - GIB)
    };
    assert!(
        publish(&mut c, &controller, 2, 0, &[raised(GPU0), raised(GPU1)])
            .await
            .unwrap()
    );
    assert_eq!(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "floor", &[bytes(GPU0, SPARE - GIB + 1)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "floor", &[bytes(GPU0, SPARE - GIB)]),
        )
        .await
        .unwrap(),
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn partial_release_keeps_both_ledgers_charged_until_every_device_confirms() {
    let mut f = Fixture::new(&[GPU0, GPU1], 2).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0, GPU1]).await;
    let grant = granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "two-rank", &[bytes(GPU0, 2 * GIB), bytes(GPU1, 2 * GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        capacity::reconcile(&mut c, &controller, &grant, Evidence::Releasing)
            .await
            .unwrap(),
        GrantState::Releasing
    );
    // Evidence for a device outside the footprint is refused.
    assert_eq!(
        capacity::reconcile(
            &mut c,
            &controller,
            &grant,
            Evidence::Released(&["00000000-0000-4000-8000-00000000c0ff".into()])
        )
        .await,
        Err(Error::Invalid)
    );
    // One rank confirms: the allocation is unknown, both ledgers keep their charges and the
    // group closes to bursts, which resume and snapshots report the same way.
    assert_eq!(
        capacity::reconcile(
            &mut c,
            &controller,
            &grant,
            Evidence::Released(&[GPU0.into()])
        )
        .await
        .unwrap(),
        GrantState::UnknownAllocation
    );
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(grant.clone()), 2)
    );
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.quota_release_device_slot($1::uuid, $2::uuid)")
                .bind(f.runs[0].hold.as_deref().unwrap())
                .bind(&grant)
                .execute(&mut c)
                .await
        ),
        "OMQ06"
    );
    assert_eq!(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(1, "blocked", &[bytes(GPU0, GIB)])
        )
        .await
        .unwrap(),
        Decision::Unavailable
    );
    assert!(!admits(&mut c).await);
    assert!(!capacity::resume(&mut c, &controller).await.unwrap());
    // The released rank's bytes are not returned by a sample that omits the whole grant.
    assert_eq!(
        publish(
            &mut c,
            &controller,
            2,
            1,
            &[
                sample(GPU0, 0, SPARE),
                sample(GPU1, 2 * GIB, SPARE - 2 * GIB)
            ]
        )
        .await,
        Err(Error::Invalid)
    );
    // Neither a later release trigger nor an inventory attestation hides the unknown allocation.
    assert_eq!(
        capacity::reconcile(&mut c, &controller, &grant, Evidence::Releasing)
            .await
            .unwrap(),
        GrantState::UnknownAllocation
    );
    assert_eq!(
        capacity::reconcile(&mut c, &controller, &grant, Evidence::Allocated).await,
        Err(Error::Invalid)
    );

    // The remaining rank confirms non-allocation: both ledgers settle exactly once.
    assert_eq!(
        capacity::reconcile(
            &mut c,
            &controller,
            &grant,
            Evidence::NotAllocated(&[GPU0.into(), GPU1.into()])
        )
        .await
        .unwrap(),
        GrantState::Released
    );
    let evidence: Vec<(String, String)> = sqlx::query_as(
        "SELECT device_id::text, release_evidence FROM openmettle.capacity_grant_devices
          WHERE grant_id = $1::uuid ORDER BY device_id",
    )
    .bind(&grant)
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        evidence,
        vec![
            (GPU0.into(), "released".into()),
            (GPU1.into(), "not_allocated".into())
        ]
    );
    assert_eq!(f.slot(0).await, ("released".into(), Some(grant), 1));
    assert_eq!(f.drift().await, (0, 0, 0, 0));
    assert!(capacity::resume(&mut c, &controller).await.unwrap());
    granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(1, "reopened", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn crash_recovery_preserves_charges_until_a_current_controller_reconciles() {
    let mut f = Fixture::new(&[GPU0], 3).await;
    let mut a = f.worker().await;
    let first = open_group(&mut a, 1, &[GPU0]).await;
    let need = [bytes(GPU0, 2 * GIB)];

    // A grant transaction that never commits leaves neither ledger changed.
    {
        let mut crashed = f.worker().await;
        let mut tx = WriteTransaction::begin(&mut crashed).await.unwrap();
        granted(
            capacity::grant(
                tx.connection().unwrap(),
                &first,
                &f.request(0, "crash", &need),
            )
            .await
            .unwrap(),
        );
        drop(tx);
    }
    assert_eq!(f.grants().await, 0);
    assert_eq!(f.slot(0).await, ("held".into(), None, 3));
    let dispatched = granted(
        capacity::grant(&mut a, &first, &f.request(0, "crash", &need))
            .await
            .unwrap(),
    );
    let lost_reply = granted(
        capacity::grant(&mut a, &first, &f.request(1, "lost-reply", &need))
            .await
            .unwrap(),
    );
    // Run 1's reply is lost and recorded. Run 0's worker dies, and its expired claim authorizes
    // no new allocation.
    assert_eq!(
        capacity::reconcile(&mut a, &first, &lost_reply, Evidence::UnknownAllocation)
            .await
            .unwrap(),
        GrantState::UnknownAllocation
    );
    f.expire_run_lease(0).await;
    // A replay of the identical request still recovers the recorded decision.
    assert_eq!(
        capacity::grant(&mut a, &first, &f.request(0, "crash", &need))
            .await
            .unwrap(),
        Decision::Grant {
            grant_id: dispatched.clone(),
            state: GrantState::Granted
        }
    );
    assert_eq!(
        capacity::grant(&mut a, &first, &f.request(0, "after-crash", &need)).await,
        Err(Error::LeaseLost)
    );

    // The controller dies before recording anything about run 0's grant. Its successor stays
    // closed until it attests that grant in its own epoch and release evidence resolves the
    // unknown one; the charges and the chat floor survive throughout.
    f.expire_controller_lease().await;
    let mut b = f.worker().await;
    let next = Controller::acquire(&mut b, GROUP, LEASE).await.unwrap();
    let committed = [sample(GPU0, 4 * GIB, SPARE - 4 * GIB)];
    assert!(publish(&mut b, &next, 2, 2, &committed).await.unwrap());
    assert!(!capacity::resume(&mut b, &next).await.unwrap());
    assert_eq!(
        capacity::grant(
            &mut b,
            &next,
            &f.request(2, "during-recovery", &[bytes(GPU0, GIB)])
        )
        .await
        .unwrap(),
        Decision::Unavailable
    );
    assert_eq!(
        capacity::reconcile(&mut b, &next, &lost_reply, Evidence::Allocated).await,
        Err(Error::Invalid)
    );
    assert_eq!(
        capacity::reconcile(
            &mut b,
            &next,
            &lost_reply,
            Evidence::NotAllocated(&[GPU0.into()])
        )
        .await
        .unwrap(),
        GrantState::Released
    );
    assert_eq!(f.slot(1).await, ("released".into(), Some(lost_reply), 2));
    assert!(!capacity::resume(&mut b, &next).await.unwrap());
    assert_eq!(
        capacity::reconcile(&mut b, &next, &dispatched, Evidence::Allocated)
            .await
            .unwrap(),
        GrantState::Granted
    );
    assert!(capacity::resume(&mut b, &next).await.unwrap());

    // Behind its fence the successor then confirms the dead worker's allocation is gone and
    // settles that run's slot without its lease.
    for evidence in [Evidence::Releasing, Evidence::Released(&[GPU0.into()])] {
        capacity::reconcile(&mut b, &next, &dispatched, evidence)
            .await
            .unwrap();
    }
    assert_eq!(f.slot(0).await, ("released".into(), Some(dispatched), 1));
    // The released bytes return only through a fresh sample; the floor stays out of reach.
    let rest = [bytes(GPU0, SPARE)];
    assert_eq!(
        capacity::grant(&mut b, &next, &f.request(2, "resumed", &rest))
            .await
            .unwrap(),
        Decision::Insufficient
    );
    assert!(
        publish(&mut b, &next, 3, 2, &[sample(GPU0, 0, SPARE)])
            .await
            .unwrap()
    );
    assert_eq!(
        capacity::grant(
            &mut b,
            &next,
            &f.request(2, "resumed", &[bytes(GPU0, SPARE + 1)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    granted(
        capacity::grant(&mut b, &next, &f.request(2, "resumed", &rest))
            .await
            .unwrap(),
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn device_membership_is_immutable_and_an_empty_group_never_admits() {
    let mut f = Fixture::new(&[GPU0], 0).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    f.owner_exec(
        "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
         VALUES ($1::uuid, $2::uuid, 0)",
        &[GPU1, GROUP_B],
    )
    .await;
    // A sampled device and a never-sampled one both keep their group, at any isolation level.
    let mut operator = connect(&f.db.0, OWNER).await;
    let move_to = |device, group| {
        sqlx::query(
            "UPDATE openmettle.capacity_devices SET group_id = $2::uuid WHERE id = $1::uuid",
        )
        .bind(device)
        .bind(group)
    };
    for (device, group) in [(GPU0, GROUP_B), (GPU1, GROUP)] {
        assert_eq!(
            sqlstate(move_to(device, group).execute(&mut operator).await),
            "23514"
        );
        let mut tx = operator.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            sqlstate(move_to(device, group).execute(&mut *tx).await),
            "23514"
        );
        tx.rollback().await.unwrap();
    }
    assert!(admits(&mut c).await);
    // A recovered, freshly sampled group without any configured device admits nothing.
    f.owner_exec(
        "DELETE FROM openmettle.capacity_observations WHERE group_id = $1::uuid",
        &[GROUP],
    )
    .await;
    f.owner_exec(
        "DELETE FROM openmettle.capacity_devices WHERE group_id = $1::uuid",
        &[GROUP],
    )
    .await;
    assert!(!admits(&mut c).await);
    assert!(!capacity::resume(&mut c, &controller).await.unwrap());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn readiness_is_evaluated_on_the_callers_snapshot() {
    let f = Fixture::new(&[GPU0], 1).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    let grant = granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "first", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
    // One statement takes its snapshot, pauses while the allocation becomes unknown, then
    // evaluates readiness, as snapshot() does beside its rows: the answer belongs to the
    // statement's snapshot, not to a later one.
    let mut reader = f.worker().await;
    let statement = sqlx::query_scalar::<_, bool>(
        "SELECT openmettle.capacity_admits($1::uuid, false)
           FROM (SELECT pg_sleep(1) OFFSET 0) AS pause",
    )
    .bind(GROUP);
    let (read, closed) = tokio::join!(statement.fetch_one(&mut reader), async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        capacity::reconcile(&mut c, &controller, &grant, Evidence::UnknownAllocation).await
    });
    assert_eq!(closed.unwrap(), GrantState::UnknownAllocation);
    assert!(read.unwrap());
    assert!(!admits(&mut c).await);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_expiry_after_the_last_wait_aborts_the_callers_transaction() {
    let mut f = Fixture::new(&[GPU0], 2).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    f.ttl("1000").await;
    assert!(
        publish(&mut c, &controller, 2, 0, &[sample(GPU0, 0, SPARE)])
            .await
            .unwrap()
    );
    // Hold run 1's slot so its decision waits past the sample's freshness.
    let mut blocker = connect(&f.db.0, OWNER).await;
    let mut held = blocker.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.quota_reservations WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(f.runs[1].hold.as_deref().unwrap())
        .execute(&mut *held)
        .await
        .unwrap();
    let mut w = f.worker().await;
    let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
    // An earlier write in the caller's transaction: run 0's grant.
    granted(
        capacity::grant(
            tx.connection().unwrap(),
            &controller,
            &f.request(0, "earlier", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
    let need = [bytes(GPU0, GIB)];
    let request = f.request(1, "expires", &need);
    let db = &f.db;
    let conn = tx.connection().unwrap();
    let (decision, ()) = tokio::join!(capacity::grant(conn, &controller, &request), async move {
        authz_store::wait_for_lock_waiters(db, 1).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        held.commit().await.unwrap();
    });
    assert_eq!(decision, Err(Error::Expired));
    // The transaction is aborted: its next statement fails, and the earlier grant is gone.
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT 1")
                .execute(tx.connection().unwrap())
                .await
        ),
        "25P02"
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.grants().await, 0);
    assert_eq!(f.slot(0).await, ("held".into(), None, 2));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn release_rolls_back_when_the_controller_lease_lapses_during_settlement() {
    let mut f = Fixture::new(&[GPU0], 1).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    let grant = granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "settle", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
    capacity::reconcile(&mut c, &controller, &grant, Evidence::Releasing)
        .await
        .unwrap();
    // Hold the run's slot row so settlement waits past the controller's lease.
    let mut blocker = connect(&f.db.0, OWNER).await;
    let mut held = blocker.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.quota_reservations WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(f.runs[0].hold.as_deref().unwrap())
        .execute(&mut *held)
        .await
        .unwrap();
    controller
        .renew(&mut c, Duration::from_millis(1000))
        .await
        .unwrap();
    let devices = [GPU0.to_string()];
    let mut w = f.worker().await;
    let db = &f.db;
    let (outcome, ()) = tokio::join!(
        capacity::reconcile(&mut w, &controller, &grant, Evidence::Released(&devices)),
        async move {
            authz_store::wait_for_lock_waiters(db, 1).await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            held.commit().await.unwrap();
        }
    );
    assert_eq!(outcome, Err(Error::Fenced));
    // The release rolled back: both ledgers keep their charges.
    let state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&grant)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(state, "releasing");
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(grant), 1)
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn publication_rolls_back_when_the_controller_lease_lapses_during_its_wait() {
    let f = Fixture::new(&[GPU0], 0).await;
    let mut c = f.worker().await;
    // An operator holds the device row, so the device's first sample waits in its foreign-key
    // check past the controller's lease.
    let mut operator = connect(&f.db.0, OWNER).await;
    let mut held = operator.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.capacity_devices WHERE id = $1::uuid FOR UPDATE")
        .bind(GPU0)
        .execute(&mut *held)
        .await
        .unwrap();
    let controller = Controller::acquire(&mut c, GROUP, Duration::from_millis(1000))
        .await
        .unwrap();
    let observed_at_us = db_now_us(&mut c).await;
    let devices = [sample(GPU0, 0, SPARE)];
    let observation = Observation {
        revision: 1,
        observed_at_us,
        commit_watermark: 0,
        devices: &devices,
    };
    let db = &f.db;
    let (published, ()) = tokio::join!(
        capacity::publish(&mut c, &controller, &observation),
        async move {
            authz_store::wait_for_lock_waiters(db, 1).await;
            tokio::time::sleep(Duration::from_millis(1500)).await;
            held.commit().await.unwrap();
        }
    );
    assert_eq!(published, Err(Error::Fenced));
    let snapshot = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    assert_eq!(
        (snapshot.observation_revision, snapshot.devices.len()),
        (0, 0)
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_device_with_grant_history_cannot_be_replaced_into_another_group() {
    let mut f = Fixture::new(&[GPU0], 1).await;
    let mut c = f.worker().await;
    let controller = open_group(&mut c, 1, &[GPU0]).await;
    let grant = granted(
        capacity::grant(
            &mut c,
            &controller,
            &f.request(0, "history", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
    // Drop the sample so only the grant history references the device.
    f.owner_exec(
        "DELETE FROM openmettle.capacity_observations WHERE group_id = $1::uuid",
        &[GROUP],
    )
    .await;
    let mut operator = connect(&f.db.0, OWNER).await;
    let replace = || {
        sqlx::query(
            "WITH gone AS (
                 DELETE FROM openmettle.capacity_devices WHERE id = $1::uuid
                 RETURNING id, chat_floor_bytes)
             INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
             SELECT id, $2::uuid, chat_floor_bytes FROM gone",
        )
        .bind(GPU0)
        .bind(GROUP_B)
    };
    // Refused with an outstanding grant, and again with only released history.
    assert_eq!(sqlstate(replace().execute(&mut operator).await), "23503");
    capacity::reconcile(
        &mut c,
        &controller,
        &grant,
        Evidence::Released(&[GPU0.into()]),
    )
    .await
    .unwrap();
    assert_eq!(sqlstate(replace().execute(&mut operator).await), "23503");
    let group: String = sqlx::query_scalar(
        "SELECT group_id::text FROM openmettle.capacity_devices WHERE id = $1::uuid",
    )
    .bind(GPU0)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(group, GROUP);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn device_configuration_locks_only_its_own_visible_group() {
    const GPU2: &str = "00000000-0000-4000-8000-00000000c0d2";
    const GPU3: &str = "00000000-0000-4000-8000-00000000c0d3";
    const GROUP_C: &str = "00000000-0000-4000-8000-00000000c003";
    let f = Fixture::new(&[GPU0], 0).await;
    let add = |device, group| {
        sqlx::query(
            "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
             VALUES ($1::uuid, $2::uuid, 0)",
        )
        .bind(device)
        .bind(group)
    };
    let lock_group = |group| {
        sqlx::query("SELECT FROM openmettle.capacity_groups WHERE id = $1::uuid FOR NO KEY UPDATE")
            .bind(group)
    };
    let within = Duration::from_secs(2);
    // While a decision holds one group, a device write into another group proceeds and a write
    // into the held group waits for it.
    let mut decider = connect(&f.db.0, OWNER).await;
    let mut held = decider.begin().await.unwrap();
    lock_group(GROUP).execute(&mut *held).await.unwrap();
    let mut other = connect(&f.db.0, OWNER).await;
    tokio::time::timeout(within, add(GPU1, GROUP_B).execute(&mut other))
        .await
        .expect("a write into another group does not wait")
        .unwrap();
    let mut same = connect(&f.db.0, OWNER).await;
    let db = &f.db;
    let (done, ()) = tokio::join!(add(GPU2, GROUP).execute(&mut same), async move {
        authz_store::wait_for_lock_waiters(db, 1).await;
        held.commit().await.unwrap();
    });
    done.unwrap();
    // A device for a group whose creating transaction is still open is refused, even while that
    // transaction holds another group, rather than added without its group's lock.
    let mut creator = connect(&f.db.0, OWNER).await;
    let mut creating = creator.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms) VALUES ($1::uuid, 60000)",
    )
    .bind(GROUP_C)
    .execute(&mut *creating)
    .await
    .unwrap();
    lock_group(GROUP).execute(&mut *creating).await.unwrap();
    let refused = tokio::time::timeout(within, add(GPU3, GROUP_C).execute(&mut other))
        .await
        .expect("a write into an invisible group does not wait");
    assert_eq!(sqlstate(refused), "23503");
    creating.commit().await.unwrap();
    add(GPU3, GROUP_C).execute(&mut other).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn group_writes_waiting_past_expiry_behind_a_share_lock_are_refused() {
    let f = Fixture::new(&[GPU0], 0).await;
    let mut c = f.worker().await;
    let share = "LOCK TABLE openmettle.capacity_groups IN SHARE MODE";
    let short = Duration::from_millis(1000);
    let devices = [sample(GPU0, 0, SPARE)];
    // Renewal's deadline write waits past the lease and must not revive the epoch.
    let first = open_group(&mut c, 1, &[GPU0]).await;
    first.renew(&mut c, short).await.unwrap();
    let before = group_state(&mut c).await;
    let renewed = behind_lock(&f.db, share, None, first.renew(&mut c, LEASE)).await;
    assert_eq!(renewed, Err(Error::Fenced));
    assert_eq!(group_state(&mut c).await, before);
    // Publication's group write waits past the lease.
    let second = Controller::acquire(&mut c, GROUP, short).await.unwrap();
    let before = group_state(&mut c).await;
    let observation = Observation {
        revision: 2,
        observed_at_us: db_now_us(&mut c).await,
        commit_watermark: 0,
        devices: &devices,
    };
    let published = behind_lock(
        &f.db,
        share,
        None,
        capacity::publish(&mut c, &second, &observation),
    )
    .await;
    assert_eq!(published, Err(Error::Fenced));
    assert_eq!(group_state(&mut c).await, before);
    // Resume's ready write waits past the lease.
    let third = Controller::acquire(&mut c, GROUP, short).await.unwrap();
    assert!(publish(&mut c, &third, 2, 0, &devices).await.unwrap());
    let before = group_state(&mut c).await;
    let resumed = behind_lock(&f.db, share, None, capacity::resume(&mut c, &third)).await;
    assert_eq!(resumed, Err(Error::Fenced));
    assert_eq!(group_state(&mut c).await, before);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn unmetered_release_evidence_rolls_back_when_the_lease_lapses_during_its_wait() {
    let mut f = Fixture::with(&[GPU0, GPU1], 2, false).await;
    let mut c = f.worker().await;
    let first = open_group(&mut c, 1, &[GPU0, GPU1]).await;
    let whole = granted(
        capacity::grant(&mut c, &first, &f.request(0, "whole", &[bytes(GPU0, GIB)]))
            .await
            .unwrap(),
    );
    let split = granted(
        capacity::grant(
            &mut c,
            &first,
            &f.request(1, "split", &[bytes(GPU0, GIB), bytes(GPU1, GIB)]),
        )
        .await
        .unwrap(),
    );
    let row_lock = "SELECT FROM openmettle.capacity_grants WHERE id = $1::uuid FOR UPDATE";
    let gpu0 = [GPU0.to_string()];
    // Complete evidence for a grant without a device slot.
    first
        .renew(&mut c, Duration::from_millis(1000))
        .await
        .unwrap();
    let released = behind_lock(
        &f.db,
        row_lock,
        Some(&whole),
        capacity::reconcile(&mut c, &first, &whole, Evidence::Released(&gpu0)),
    )
    .await;
    assert_eq!(released, Err(Error::Fenced));
    // Partial evidence, from the next controller.
    let second = Controller::acquire(&mut c, GROUP, Duration::from_millis(1000))
        .await
        .unwrap();
    let partial = behind_lock(
        &f.db,
        row_lock,
        Some(&split),
        capacity::reconcile(&mut c, &second, &split, Evidence::Released(&gpu0)),
    )
    .await;
    assert_eq!(partial, Err(Error::Fenced));
    // Neither grant changed.
    let unchanged: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.capacity_grants WHERE state = 'granted'),
                (SELECT count(*) FROM openmettle.capacity_grant_devices
                  WHERE release_evidence IS NOT NULL)",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(unchanged, (2, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_recreated_group_never_reuses_a_controller_epoch() {
    // GROUP_B has no devices, so the operator may delete and recreate it.
    let mut f = Fixture::new(&[GPU0], 0).await;
    let mut c = f.worker().await;
    let first = Controller::acquire(&mut c, GROUP_B, LEASE).await.unwrap();
    f.owner_exec(
        "UPDATE openmettle.capacity_groups
            SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        &[GROUP_B],
    )
    .await;
    let second = Controller::acquire(&mut c, GROUP_B, LEASE).await.unwrap();
    assert!(second.epoch() > first.epoch());
    f.owner_exec(
        "DELETE FROM openmettle.capacity_groups WHERE id = $1::uuid",
        &[GROUP_B],
    )
    .await;
    f.owner_exec(
        "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms) VALUES ($1::uuid, 60000)",
        &[GROUP_B],
    )
    .await;
    let third = Controller::acquire(&mut c, GROUP_B, LEASE).await.unwrap();
    assert!(
        third.epoch() > second.epoch(),
        "epoch {} after {}",
        third.epoch(),
        second.epoch()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_26_device_slots_stay_charged_across_the_upgrade_without_capacity_evidence() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..26]).await.unwrap();
    let mut api = connect(&db.0, API).await;
    let mut owner = connect(&db.0, OWNER).await;
    let actor = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &actor).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
             VALUES('personal','device_reservations',1)",
        )
        .await
        .unwrap();
    let hold: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,'device_reservations',1,'legacy',
             NULL,NULL,NULL,clock_timestamp()+interval '15 minutes')::text",
    )
    .bind(&scope)
    .bind(&actor)
    .fetch_one(&mut api)
    .await
    .unwrap();
    let legacy_grant = "00000000-0000-4000-8000-00000000c0e1";
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_commit_handoff($1::uuid,$2::uuid)")
            .bind(&hold)
            .bind(legacy_grant)
            .fetch_one(&mut api)
            .await
            .unwrap()
    );

    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());
    for table in ["capacity_groups", "capacity_grants"] {
        let rows: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT count(*) FROM openmettle.{table}"
        )))
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(rows, 0, "{table}");
    }
    // A pre-27 binding has no capacity record, so its slot can never be credited.
    let mut worker = connect(&db.0, WORKER).await;
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.quota_release_device_slot($1::uuid,$2::uuid)")
                .bind(&hold)
                .bind(legacy_grant)
                .execute(&mut worker)
                .await
        ),
        "OMQ06"
    );
    let charge: (String, i64) = sqlx::query_as(
        "SELECT h.state, b.reserved_held::bigint FROM openmettle.quota_reservations h
           JOIN openmettle.quota_budgets b ON b.scope_id = h.scope_id
            AND b.resource_kind = 'device_reservations' WHERE h.id = $1::uuid",
    )
    .bind(&hold)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(charge, ("handoff_committed".into(), 1));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_40_restricts_api_capacity_visibility_without_exposing_secrets_or_tenant_grants()
{
    let mut f = Fixture::new(&[GPU0], 1).await;
    let mut worker = f.worker().await;
    let controller = open_group(&mut worker, 1, &[GPU0]).await;
    let need = [bytes(GPU0, 2 * GIB)];
    let _grant = granted(
        capacity::grant(&mut worker, &controller, &f.request(0, "priv-grant", &need))
            .await
            .unwrap(),
    );

    sqlx::query(
        "INSERT INTO openmettle.capacity_profiles
            (profile, group_id, per_device_bytes, required_devices, estimated_wait_seconds)
         VALUES ('chat.base', $1::uuid, $2, 1, 15)",
    )
    .bind(GROUP)
    .bind(2 * GIB)
    .execute(&mut f.owner)
    .await
    .unwrap();

    // openmettle_api can NEVER read controller_token_hash, raw capacity_groups, or tenant
    // capacity_grants / capacity_grant_devices rows, and cannot mutate capacity_profiles.
    let mut api = connect(&f.db.0, API).await;
    for denied_sql in [
        "SELECT controller_token_hash FROM openmettle.capacity_groups",
        "SELECT id FROM openmettle.capacity_groups",
        "SELECT scope_id, run_id FROM openmettle.capacity_grants",
        "SELECT FROM openmettle.capacity_grants",
        "SELECT FROM openmettle.capacity_grant_devices",
        "SELECT FROM openmettle.capacity_devices",
        "SELECT FROM openmettle.capacity_observations",
        "INSERT INTO openmettle.capacity_profiles (profile, group_id, per_device_bytes, required_devices) VALUES ('bad', '00000000-0000-4000-8000-00000000c001'::uuid, 1, 1)",
        "UPDATE openmettle.capacity_profiles SET per_device_bytes = 1",
        "DELETE FROM openmettle.capacity_profiles",
    ] {
        expect_state(&mut api, denied_sql, "42501").await;
    }

    // Only openmettle_api may execute capacity_group_observations(); worker, issuance and gateway
    // are refused.
    for role in [WORKER, ISSUANCE] {
        let mut conn = connect(&f.db.0, role).await;
        expect_state(
            &mut conn,
            "SELECT * FROM openmettle.capacity_group_observations()",
            "42501",
        )
        .await;
    }
    let gateway_exec: bool = sqlx::query_scalar(
        "SELECT has_function_privilege('openmettle_gateway', 'openmettle.capacity_group_observations()', 'EXECUTE')",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(!gateway_exec);

    // openmettle_api reads capacity_profiles and capacity_group_observations() cleanly inside a
    // REPEATABLE READ, READ ONLY snapshot, seeing the unwatermarked 2 GiB grant subtracted from
    // effective_grantable_bytes without accessing tenant grant rows.
    let mut tx = api.begin().await.unwrap();
    tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .await
        .unwrap();
    let profile_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.capacity_profiles")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(profile_count, 1);
    let row = sqlx::query(
        "SELECT group_id::text AS group_id, admits_bursts, observation_stale,
                grantable_bytes, effective_grantable_bytes
           FROM openmettle.capacity_group_observations()
          WHERE group_id = $1::uuid",
    )
    .bind(GROUP)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("group_id"), GROUP);
    assert!(row.get::<bool, _>("admits_bursts"));
    assert!(!row.get::<bool, _>("observation_stale"));
    assert_eq!(row.get::<i64, _>("grantable_bytes"), SPARE);
    assert_eq!(
        row.get::<i64, _>("effective_grantable_bytes"),
        SPARE - 2 * GIB
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn adapter_fenced_takeover_reconciliation_reclaim_and_partial_release_round_trip() {
    use openmettle_core::capacity::adapter::{
        self, ADAPTER_CONTRACT_VERSION, AdapterError, BackendDeviceConfig, CapacityAdapter,
        CapacityWait, CoordinatorError, DispatchGrantCommand, DispatchOutcome,
        EstablishEpochRequest, FencedBackend, GroupCoordinator, ReleaseGrantCommand,
    };
    use sqlx::postgres::PgPoolOptions;

    let mut f = Fixture::new(&[GPU0, GPU1], 3).await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(role_options(&f.db.0, WORKER))
        .await
        .unwrap();
    let mut c = f.worker().await;
    let backend = Arc::new(
        FencedBackend::new(
            GROUP,
            vec![
                BackendDeviceConfig {
                    device_id: GPU0.into(),
                    total_bytes: TOTAL,
                    safety_headroom_bytes: HEADROOM,
                    active_chat_floor_bytes: FLOOR,
                    backed_chat_floor_bytes: FLOOR,
                    reclaimable_bytes: 2 * GIB,
                    unattributed_used_bytes: 0,
                },
                BackendDeviceConfig {
                    device_id: GPU1.into(),
                    total_bytes: TOTAL,
                    safety_headroom_bytes: HEADROOM,
                    active_chat_floor_bytes: FLOOR,
                    backed_chat_floor_bytes: FLOOR,
                    reclaimable_bytes: 2 * GIB,
                    unattributed_used_bytes: 0,
                },
            ],
        )
        .unwrap(),
    );

    // Epoch 1: acquire, establish fence on backend, publish conservative observation, resume.
    let c1 = Controller::acquire(&mut c, GROUP, LEASE).await.unwrap();
    let coord1 = GroupCoordinator::new(pool.clone(), c1, backend.clone());
    let r1 = coord1.takeover_and_reconcile().await.unwrap();
    assert_eq!(r1.established_epoch, coord1.controller().epoch());
    let obs1 = backend.observe().unwrap();
    // 24 - 1 headroom - 16 floor - 2 reclaimable = 5 GiB grantable before reclaim.
    assert_eq!(obs1[0].grantable_bytes, 5 * GIB);
    assert!(
        publish(&mut c, coord1.controller(), 1, 0, &obs1)
            .await
            .unwrap()
    );
    assert!(coord1.resume().await.unwrap());

    // Run 0 needs 6 GiB per GPU: insufficient before tail-KV reclaim.
    let six_each = [bytes(GPU0, 6 * GIB), bytes(GPU1, 6 * GIB)];
    let wait0 = CapacityWait::start();
    assert_eq!(
        coord1
            .dispatch_grant(&f.request(0, "run0-pre", &six_each), &wait0)
            .await
            .unwrap(),
        DispatchOutcome::Insufficient
    );

    // Fenced tail-KV reclaim hands back 2 GiB per device while preserving the 16 GiB chat floor.
    let reclaimed = coord1
        .reclaim_kv(
            "reclaim-run0",
            &[bytes(GPU0, 2 * GIB), bytes(GPU1, 2 * GIB)],
        )
        .await
        .unwrap();
    assert_eq!(reclaimed.reclaimed.len(), 2);
    assert!(
        reclaimed
            .reclaimed
            .iter()
            .all(|r| r.reclaimed_bytes == 2 * GIB)
    );
    let obs2 = backend.observe().unwrap();
    assert_eq!(obs2[0].active_chat_floor_bytes, FLOOR);
    assert_eq!(obs2[0].grantable_bytes, SPARE);
    assert!(
        publish(&mut c, coord1.controller(), 2, 0, &obs2)
            .await
            .unwrap()
    );

    // Commit-before-dispatch run 0 (3 GiB on both GPUs); replaying the already-confirmed grant
    // returns Existing without calling the backend again.
    let three_each = [bytes(GPU0, 3 * GIB), bytes(GPU1, 3 * GIB)];
    let DispatchOutcome::Dispatched {
        grant_id: g0,
        replayed: false,
    } = coord1
        .dispatch_grant(&f.request(0, "run0", &three_each), &wait0)
        .await
        .unwrap()
    else {
        panic!("expected initial dispatch");
    };
    assert_eq!(
        coord1
            .dispatch_grant(&f.request(0, "run0", &three_each), &wait0)
            .await
            .unwrap(),
        DispatchOutcome::Existing {
            grant_id: g0.clone(),
            state: GrantState::Granted,
        }
    );

    // Run 1 suffers an ambiguous/lost dispatch reply -> durable grant enters unknown_allocation
    // and closes the group to new bursts until reconciled.
    backend.inject_next_dispatch_error(AdapterError::Unavailable);
    let one_gpu0 = [bytes(GPU0, GIB)];
    let wait1 = CapacityWait::start();
    assert_eq!(
        coord1
            .dispatch_grant(&f.request(1, "run1-lost", &one_gpu0), &wait1)
            .await,
        Err(CoordinatorError::Adapter(AdapterError::Unavailable))
    );
    let wait2 = CapacityWait::start();
    assert_eq!(
        coord1
            .dispatch_grant(&f.request(2, "run2-closed", &one_gpu0), &wait2)
            .await
            .unwrap(),
        DispatchOutcome::Unavailable
    );

    // Controller 1 lease expires; controller 2 takes over and establishes epoch 2 on backend.
    let epoch1 = coord1.controller().epoch();
    f.expire_controller_lease().await;
    let c2 = Controller::acquire(&mut c, GROUP, LEASE).await.unwrap();
    let coord2 = GroupCoordinator::new(pool.clone(), c2, backend.clone());
    assert!(coord2.controller().epoch() > epoch1);
    let report = coord2.takeover_and_reconcile().await.unwrap();
    assert_eq!(report.established_epoch, coord2.controller().epoch());
    // g0 was live on backend -> attested; run1's unknown_allocation was never allocated -> confirmed
    // NotAllocated behind epoch 2 fence and released along with its quota slot!
    assert_eq!(
        (
            report.attested,
            report.released,
            report.rogue_released,
            report.unknown
        ),
        (1, 1, 0, 0)
    );
    assert_eq!(f.slot(1).await.0, "released");

    // Cross-epoch idempotent replay of reclaim_kv returns epoch 2 and cached handback.
    let reclaimed_e2 = coord2
        .reclaim_kv(
            "reclaim-run0",
            &[bytes(GPU0, 2 * GIB), bytes(GPU1, 2 * GIB)],
        )
        .await
        .unwrap();
    assert_eq!(reclaimed_e2.controller_epoch, coord2.controller().epoch());
    assert_eq!(reclaimed_e2.reclaimed, reclaimed.reclaimed);

    // Delayed epoch-1 commands are strictly refused by the backend after epoch-2 takeover.
    assert_eq!(
        backend
            .dispatch_grant(DispatchGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: epoch1,
                grant_id: "00000000-0000-4000-8000-00000000c999".into(),
                profile: "synthetic-image".into(),
                footprint: one_gpu0.to_vec(),
            })
            .await,
        Err(AdapterError::StaleEpoch {
            established_epoch: coord2.controller().epoch()
        })
    );
    assert_eq!(
        backend
            .release_grant(ReleaseGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: epoch1,
                grant_id: g0.clone(),
                devices: vec![GPU0.into(), GPU1.into()],
            })
            .await,
        Err(AdapterError::StaleEpoch {
            established_epoch: coord2.controller().epoch()
        })
    );
    assert_eq!(
        backend
            .establish_epoch(EstablishEpochRequest::new(coord1.controller()))
            .await,
        Err(AdapterError::StaleEpoch {
            established_epoch: coord2.controller().epoch()
        })
    );

    // Partial release failure on GPU1 keeps g0 in unknown_allocation and keeps its quota slot
    // charged; even though GPU0 freed physical bytes, its durable commitment remains charged and
    // the group cannot resume until GPU1 confirms release.
    backend.inject_unknown_release(&g0, GPU1);
    assert_eq!(
        coord2
            .release_grant(&g0, &[GPU0.into(), GPU1.into()])
            .await
            .unwrap(),
        GrantState::UnknownAllocation
    );
    assert_eq!(f.slot(0).await.0, "handoff_committed");
    let snap = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    let durable_partial = adapter::durable_committed_through(&pool, GROUP, snap.commit_seq)
        .await
        .unwrap();
    let obs3 = backend.observe_with_commitments(&durable_partial).unwrap();
    assert_eq!(obs3[0].committed_bytes, 3 * GIB);
    assert_eq!(obs3[0].grantable_bytes, SPARE - 3 * GIB);
    assert!(
        publish(&mut c, coord2.controller(), 3, snap.commit_seq, &obs3)
            .await
            .unwrap()
    );
    assert!(!coord2.resume().await.unwrap());

    // Once GPU1 clears and takeover/release confirms GPU1, g0 settles and the group reopens.
    backend.clear_unknown_release(&g0, GPU1);
    let resolved = coord2.takeover_and_reconcile().await.unwrap();
    assert_eq!(
        (
            resolved.attested,
            resolved.released,
            resolved.rogue_released,
            resolved.unknown
        ),
        (0, 1, 0, 0)
    );
    assert_eq!(f.slot(0).await.0, "released");
    let durable_settled = adapter::durable_committed_through(&pool, GROUP, snap.commit_seq)
        .await
        .unwrap();
    assert!(durable_settled.is_empty());
    let obs4 = backend.observe_with_commitments(&durable_settled).unwrap();
    assert_eq!(obs4[0].grantable_bytes, SPARE);
    assert_eq!(obs4[1].grantable_bytes, SPARE);
    assert!(
        publish(&mut c, coord2.controller(), 4, snap.commit_seq, &obs4)
            .await
            .unwrap()
    );
    assert!(coord2.resume().await.unwrap());
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn two_phase_in_flight_dispatch_blocks_bursts_rechecks_run_lease_and_deduplicates_settled_replay()
 {
    use openmettle_core::{
        capacity::adapter::{
            AdapterError, BackendDeviceConfig, CapacityAdapter, CapacityWait, CoordinatorError,
            DispatchOutcome, FencedBackend, GroupCoordinator,
        },
        telemetry::{
            Process,
            metrics::{self},
        },
    };
    use opentelemetry_proto::tonic::{
        common::v1::any_value::Value as AnyVal,
        metrics::v1::{metric, number_data_point::Value as NumVal},
    };
    use sqlx::postgres::PgPoolOptions;

    fn metric_count(metric_name: &str, attr_key: &str, attr_val: &str) -> u64 {
        let Some(req) = metrics::global().encode_otlp(Process::Worker, None) else {
            return 0;
        };
        let mut total = 0u64;
        for rm in &req.resource_metrics {
            for sm in &rm.scope_metrics {
                for m in &sm.metrics {
                    if m.name != metric_name {
                        continue;
                    }
                    match m.data.as_ref() {
                        Some(metric::Data::Sum(sum)) => {
                            for dp in &sum.data_points {
                                let matches = dp.attributes.iter().any(|kv| {
                                    kv.key == attr_key
                                        && matches!(
                                            kv.value.as_ref().and_then(|v| v.value.as_ref()),
                                            Some(AnyVal::StringValue(s)) if s == attr_val
                                        )
                                });
                                if matches && let Some(NumVal::AsInt(v)) = dp.value {
                                    total += v as u64;
                                }
                            }
                        }
                        Some(metric::Data::Histogram(hist)) => {
                            for dp in &hist.data_points {
                                let matches = dp.attributes.iter().any(|kv| {
                                    kv.key == attr_key
                                        && matches!(
                                            kv.value.as_ref().and_then(|v| v.value.as_ref()),
                                            Some(AnyVal::StringValue(s)) if s == attr_val
                                        )
                                });
                                if matches {
                                    total += dp.count;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        total
    }

    let mut f = Fixture::new(&[GPU0], 3).await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(role_options(&f.db.0, WORKER))
        .await
        .unwrap();
    let mut c = f.worker().await;
    let backend = Arc::new(
        FencedBackend::new(
            GROUP,
            vec![BackendDeviceConfig {
                device_id: GPU0.into(),
                total_bytes: TOTAL,
                safety_headroom_bytes: HEADROOM,
                active_chat_floor_bytes: FLOOR,
                backed_chat_floor_bytes: FLOOR,
                reclaimable_bytes: 0,
                unattributed_used_bytes: 0,
            }],
        )
        .unwrap(),
    );

    let c1 = Controller::acquire(&mut c, GROUP, LEASE).await.unwrap();
    let coord = GroupCoordinator::new(pool.clone(), c1, backend.clone());
    // Do NOT establish_epoch yet so dispatch_grant hits AdapterError::Unfenced after Tx 1 commits
    // `dispatch_state = 'in_flight'`.
    let obs = backend.observe().unwrap();
    assert!(
        publish(&mut c, coord.controller(), 1, 0, &obs)
            .await
            .unwrap()
    );
    assert!(coord.resume().await.unwrap());

    let one_gib = [bytes(GPU0, GIB)];
    let wait0 = CapacityWait::start();
    assert_eq!(
        coord
            .dispatch_grant(&f.request(0, "inflight-run0", &one_gib), &wait0)
            .await,
        Err(CoordinatorError::Adapter(AdapterError::Unfenced))
    );

    // The prepared grant is durable with `dispatch_state = 'in_flight'` and IMMEDIATELY blocks
    // concurrent bursts (P1 #4).
    let (state, dispatch_state): (String, String) = sqlx::query_as(
        "SELECT state, dispatch_state FROM openmettle.capacity_grants
          WHERE request_key = 'inflight-run0'",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        (state.as_str(), dispatch_state.as_str()),
        ("granted", "in_flight")
    );
    assert!(!admits(&mut c).await);
    assert_eq!(
        coord
            .dispatch_grant(
                &f.request(1, "concurrent-run1", &one_gib),
                &CapacityWait::start()
            )
            .await
            .unwrap(),
        DispatchOutcome::Unavailable
    );

    // Establish epoch on backend, then expire run 0's lease: retrying the unconfirmed `in_flight`
    // grant MUST fail with LeaseLost and NEVER allocate on the backend (P1 #1).
    let est = backend
        .establish_epoch(
            openmettle_core::capacity::adapter::EstablishEpochRequest::new(coord.controller()),
        )
        .await
        .unwrap();
    assert!(est.allocations.is_empty());
    f.expire_run_lease(0).await;
    assert_eq!(
        coord
            .dispatch_grant(&f.request(0, "inflight-run0", &one_gib), &wait0)
            .await,
        Err(CoordinatorError::Store(Error::LeaseLost))
    );
    let after_expired_retry = backend
        .establish_epoch(
            openmettle_core::capacity::adapter::EstablishEpochRequest::new(coord.controller()),
        )
        .await
        .unwrap();
    assert!(
        after_expired_retry.allocations.is_empty(),
        "expired run lease must never dispatch onto backend"
    );

    // Restore run 0's lease and retry the unconfirmed `in_flight` grant: it now dispatches once
    // and confirms (`dispatch_state = 'confirmed'`), reopening bursts.
    let run0_id = f.runs[0].run.clone();
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() + interval '60 seconds'
          WHERE id = $1::uuid",
        &[&run0_id],
    )
    .await;
    let DispatchOutcome::Dispatched {
        grant_id: g0,
        replayed: true,
    } = coord
        .dispatch_grant(&f.request(0, "inflight-run0", &one_gib), &wait0)
        .await
        .unwrap()
    else {
        panic!("expected confirmed retry of in_flight grant");
    };
    let confirmed: String = sqlx::query_scalar(
        "SELECT dispatch_state FROM openmettle.capacity_grants WHERE id = $1::uuid",
    )
    .bind(&g0)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(confirmed, "confirmed");
    assert!(admits(&mut c).await);

    // Replaying an already-confirmed grant MUST return Existing WITHOUT calling the backend and
    // WITHOUT incrementing grant or wait metrics (P1 #1).
    let grants_before = metric_count("openmettle.capacity.grants", "outcome", "granted");
    let waits_before = metric_count("openmettle.capacity.wait.duration", "outcome", "granted");
    assert!(grants_before > 0, "initial grant must have recorded metric");
    assert!(waits_before > 0, "initial wait must have recorded metric");
    // Inject a one-shot dispatch error that would fire if the backend were touched on replay.
    backend.inject_next_dispatch_error(AdapterError::Unavailable);
    assert_eq!(
        coord
            .dispatch_grant(&f.request(0, "inflight-run0", &one_gib), &wait0)
            .await
            .unwrap(),
        DispatchOutcome::Existing {
            grant_id: g0.clone(),
            state: GrantState::Granted,
        }
    );
    assert_eq!(
        metric_count("openmettle.capacity.grants", "outcome", "granted"),
        grants_before
    );
    assert_eq!(
        metric_count("openmettle.capacity.wait.duration", "outcome", "granted"),
        waits_before
    );

    // Aging the observation past TTL and attempting a new dispatch increments
    // `openmettle.capacity.observations.stale{surface="controller"}` (P2 #12).
    let stale_before = metric_count(
        "openmettle.capacity.observations.stale",
        "surface",
        "controller",
    );
    f.owner_exec(
        "UPDATE openmettle.capacity_groups
            SET observed_at = clock_timestamp() - interval '120 seconds'
          WHERE id = $1::uuid",
        &[GROUP],
    )
    .await;
    assert_eq!(
        coord
            .dispatch_grant(
                &f.request(1, "stale-run1", &one_gib),
                &CapacityWait::start()
            )
            .await
            .unwrap(),
        DispatchOutcome::Unavailable
    );
    assert!(
        metric_count(
            "openmettle.capacity.observations.stale",
            "surface",
            "controller",
        ) > stale_before
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn takeover_reconciles_rogue_backend_allocations_extra_ranks_and_rejects_malformed_reclaim() {
    use openmettle_core::capacity::adapter::{
        self, ADAPTER_CONTRACT_VERSION, AdapterError, BackendDeviceConfig, CapacityAdapter,
        CapacityWait, DeviceReclaimResult, DispatchGrantCommand, DispatchGrantResponse,
        DispatchOutcome, EstablishEpochRequest, EstablishEpochResponse, FencedBackend,
        GroupCoordinator, ReclaimKvCommand, ReclaimKvResponse, ReleaseGrantCommand,
        ReleaseGrantResponse,
    };
    use sqlx::postgres::PgPoolOptions;

    const ROGUE_GRANT: &str = "00000000-0000-4000-8000-00000000c888";

    let mut f = Fixture::new(&[GPU0, GPU1], 2).await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(role_options(&f.db.0, WORKER))
        .await
        .unwrap();
    let mut c = f.worker().await;
    let backend = Arc::new(
        FencedBackend::new(
            GROUP,
            vec![
                BackendDeviceConfig {
                    device_id: GPU0.into(),
                    total_bytes: TOTAL,
                    safety_headroom_bytes: HEADROOM,
                    active_chat_floor_bytes: FLOOR,
                    backed_chat_floor_bytes: FLOOR,
                    reclaimable_bytes: 0,
                    unattributed_used_bytes: 0,
                },
                BackendDeviceConfig {
                    device_id: GPU1.into(),
                    total_bytes: TOTAL,
                    safety_headroom_bytes: HEADROOM,
                    active_chat_floor_bytes: FLOOR,
                    backed_chat_floor_bytes: FLOOR,
                    reclaimable_bytes: 0,
                    unattributed_used_bytes: 0,
                },
            ],
        )
        .unwrap(),
    );

    // Epoch 1: grant run 0 on GPU0 only (3 GiB).
    let c1 = Controller::acquire(&mut c, GROUP, LEASE).await.unwrap();
    let coord1 = GroupCoordinator::new(pool.clone(), c1, backend.clone());
    coord1.takeover_and_reconcile().await.unwrap();
    assert!(
        publish(
            &mut c,
            coord1.controller(),
            1,
            0,
            &backend.observe().unwrap()
        )
        .await
        .unwrap()
    );
    assert!(coord1.resume().await.unwrap());
    let DispatchOutcome::Dispatched { grant_id: g0, .. } = coord1
        .dispatch_grant(
            &f.request(0, "extra-rank-run0", &[bytes(GPU0, 3 * GIB)]),
            &CapacityWait::start(),
        )
        .await
        .unwrap()
    else {
        panic!("expected g0 dispatch");
    };

    // Inject BOTH:
    // 1. A backend-only rogue allocation (ROGUE_GRANT, 2 GiB on GPU0) not present in PostgreSQL.
    // 2. An unexpected extra rank (GPU1, 2 GiB) on g0 so backend footprint mismatches DB.
    backend
        .inject_rogue_allocation(ROGUE_GRANT, "rogue", &[bytes(GPU0, 2 * GIB)])
        .unwrap();
    backend
        .inject_extra_rank_allocation(&g0, GPU1, 2 * GIB)
        .unwrap();

    // Also commit an unbacked durable grant (run 1, 3 GiB on GPU0) via low-level capacity::grant
    // so we can verify per-grant backing attribution (P1 #5): rogue 2 GiB on GPU0 must NEVER back
    // run 1's unbacked durable 3 GiB!
    let _g1 = granted(
        capacity::grant(
            &mut c,
            coord1.controller(),
            &f.request(1, "unbacked-run1", &[bytes(GPU0, 3 * GIB)]),
        )
        .await
        .unwrap(),
    );
    let snap = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    let durable = adapter::durable_committed_through(&pool, GROUP, snap.commit_seq)
        .await
        .unwrap();
    let obs_attr = backend.observe_with_commitments(&durable).unwrap();
    // GPU0: total 24, headroom 1, floor 16, resident g0=3, resident rogue=2 -> actual_used = 21.
    // Durable: g0=3 (backed=3), g1=3 (backed=0) -> committed=6, unbacked=3.
    // Charged = 21 + 3 + 0 + 1 = 25 -> grantable MUST clamp to 0!
    assert_eq!(obs_attr[0].committed_bytes, 6 * GIB);
    assert_eq!(obs_attr[0].actual_used_bytes, 21 * GIB);
    assert_eq!(obs_attr[0].grantable_bytes, 0);

    // Block release of BOTH ROGUE_GRANT on GPU0 and g0's extra rank on GPU1.
    backend.inject_unknown_release(ROGUE_GRANT, GPU0);
    backend.inject_unknown_release(&g0, GPU1);

    // Epoch 2 takeover:
    // - ROGUE_GRANT fails release -> report.unknown += 1, unresolved_backend_unknown = true.
    // - g0 has extra rank GPU1 returning Unknown -> MUST NOT settle g0 in PostgreSQL even though
    //   GPU0 confirmed Released!
    // - g1 was absent on backend -> confirmed NotAllocated and released cleanly!
    f.expire_controller_lease().await;
    let c2 = Controller::acquire(&mut c, GROUP, LEASE).await.unwrap();
    let coord2 = GroupCoordinator::new(pool.clone(), c2, backend.clone());
    let report = coord2.takeover_and_reconcile().await.unwrap();
    assert_eq!(
        (
            report.attested,
            report.released,
            report.rogue_released,
            report.unknown
        ),
        (0, 1, 0, 2)
    );
    assert!(coord2.has_unresolved_backend_unknown());
    assert_eq!(f.slot(0).await.0, "handoff_committed");
    assert_eq!(f.slot(1).await.0, "released");
    let g0_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&g0)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(g0_state, "unknown_allocation");

    // Clear g0's extra rank first while keeping ROGUE_GRANT stuck: g0 settles cleanly, leaving
    // ONLY the backend-only rogue unknown — resume() MUST still return Ok(false)!
    backend.clear_unknown_release(&g0, GPU1);
    let report2 = coord2.takeover_and_reconcile().await.unwrap();
    assert_eq!(
        (
            report2.attested,
            report2.released,
            report2.rogue_released,
            report2.unknown
        ),
        (0, 1, 0, 1)
    );
    assert_eq!(f.slot(0).await.0, "released");
    assert!(coord2.has_unresolved_backend_unknown());
    let obs_rogue_only = backend
        .observe_with_commitments(
            &adapter::durable_committed_through(&pool, GROUP, snap.commit_seq)
                .await
                .unwrap(),
        )
        .unwrap();
    assert!(
        publish(
            &mut c,
            coord2.controller(),
            2,
            snap.commit_seq,
            &obs_rogue_only
        )
        .await
        .unwrap()
    );
    assert!(
        !coord2.resume().await.unwrap(),
        "resume must stay closed while a backend-only rogue allocation is unresolved"
    );

    // Clear ROGUE_GRANT: takeover confirms rogue release and resume() now succeeds!
    backend.clear_unknown_release(ROGUE_GRANT, GPU0);
    let report3 = coord2.takeover_and_reconcile().await.unwrap();
    assert_eq!(
        (
            report3.attested,
            report3.released,
            report3.rogue_released,
            report3.unknown
        ),
        (0, 0, 1, 0)
    );
    assert!(!coord2.has_unresolved_backend_unknown());
    assert!(coord2.resume().await.unwrap());
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // Malformed reclaim_kv responses (extra/duplicate/wrong device or > target bytes) are
    // strictly rejected by GroupCoordinator::reclaim_kv (P2 #9).
    struct MalformedReclaimAdapter {
        mode: u8,
    }
    impl CapacityAdapter for MalformedReclaimAdapter {
        async fn establish_epoch(
            &self,
            _r: EstablishEpochRequest,
        ) -> Result<EstablishEpochResponse, AdapterError> {
            Err(AdapterError::Unavailable)
        }
        async fn dispatch_grant(
            &self,
            _c: DispatchGrantCommand,
        ) -> Result<DispatchGrantResponse, AdapterError> {
            Err(AdapterError::Unavailable)
        }
        async fn reclaim_kv(
            &self,
            command: ReclaimKvCommand,
        ) -> Result<ReclaimKvResponse, AdapterError> {
            let reclaimed = match self.mode {
                // Exceeds requested target bytes.
                0 => vec![DeviceReclaimResult {
                    device_id: GPU0.into(),
                    reclaimed_bytes: 2 * GIB + 1,
                }],
                // Wrong/unrequested device ID.
                1 => vec![DeviceReclaimResult {
                    device_id: GPU1.into(),
                    reclaimed_bytes: GIB,
                }],
                // Missing device / empty result.
                2 => vec![],
                // Duplicate device ID when two devices requested.
                _ => vec![
                    DeviceReclaimResult {
                        device_id: GPU0.into(),
                        reclaimed_bytes: GIB,
                    },
                    DeviceReclaimResult {
                        device_id: GPU0.into(),
                        reclaimed_bytes: GIB,
                    },
                ],
            };
            Ok(ReclaimKvResponse {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: command.group_id,
                controller_epoch: command.controller_epoch,
                request_key: command.request_key,
                reclaimed,
            })
        }
        async fn release_grant(
            &self,
            _c: ReleaseGrantCommand,
        ) -> Result<ReleaseGrantResponse, AdapterError> {
            Err(AdapterError::Unavailable)
        }
    }

    for (mode, targets) in [
        (0u8, vec![bytes(GPU0, 2 * GIB)]),
        (1u8, vec![bytes(GPU0, 2 * GIB)]),
        (2u8, vec![bytes(GPU0, 2 * GIB)]),
        (3u8, vec![bytes(GPU0, 2 * GIB), bytes(GPU1, 2 * GIB)]),
    ] {
        f.expire_controller_lease().await;
        let ctl = Controller::acquire(&mut c, GROUP, LEASE).await.unwrap();
        let bad = GroupCoordinator::new(pool.clone(), ctl, MalformedReclaimAdapter { mode });
        assert_eq!(
            bad.reclaim_kv("bad-reclaim", &targets).await,
            Err(AdapterError::Invalid),
            "malformed reclaim mode {mode} must be rejected"
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn capacity_cardinality_triggers_enforce_openapi_bounds() {
    let mut f = Fixture::new(&[], 0).await;

    // 1. capacity_profiles allows 256 rows and refuses the 257th with SQLSTATE 23514.
    for i in 0..256 {
        sqlx::query(
            "INSERT INTO openmettle.capacity_profiles
                 (profile, group_id, per_device_bytes, required_devices)
             VALUES ($1, $2::uuid, $3, 1)",
        )
        .bind(format!("profile-{i:03}"))
        .bind(GROUP)
        .bind(GIB)
        .execute(&mut f.owner)
        .await
        .unwrap();
    }
    assert_eq!(
        sqlstate(
            sqlx::query(
                "INSERT INTO openmettle.capacity_profiles
                     (profile, group_id, per_device_bytes, required_devices)
                 VALUES ('profile-256', $1::uuid, $2, 1)",
            )
            .bind(GROUP)
            .bind(GIB)
            .execute(&mut f.owner)
            .await
        ),
        "23514"
    );

    // 2. capacity_groups allows 64 rows (Fixture already inserted GROUP and GROUP_B = 2)
    //    and refuses the 65th with SQLSTATE 23514.
    for i in 2..64u64 {
        let id = format!("00000000-0000-4000-8000-{i:012x}");
        sqlx::query(
            "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms)
             VALUES ($1::uuid, 60000)",
        )
        .bind(&id)
        .execute(&mut f.owner)
        .await
        .unwrap();
    }
    assert_eq!(
        sqlstate(
            sqlx::query(
                "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms)
                 VALUES ('00000000-0000-4000-8000-000000000099'::uuid, 60000)",
            )
            .execute(&mut f.owner)
            .await
        ),
        "23514"
    );

    // 3. capacity_devices allows 64 devices per group and refuses the 65th with SQLSTATE 23514.
    for i in 0..64u64 {
        let dev_id = format!("00000000-0000-4000-8000-0000d000{:04x}", i);
        sqlx::query(
            "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
             VALUES ($1::uuid, $2::uuid, $3)",
        )
        .bind(&dev_id)
        .bind(GROUP)
        .bind(FLOOR)
        .execute(&mut f.owner)
        .await
        .unwrap();
    }
    assert_eq!(
        sqlstate(
            sqlx::query(
                "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
                 VALUES ('00000000-0000-4000-8000-0000d000ffff'::uuid, $1::uuid, $2)",
            )
            .bind(GROUP)
            .bind(FLOOR)
            .execute(&mut f.owner)
            .await
        ),
        "23514"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn v1_capacity_and_admin_inspection_enforce_authorization_projection_and_overload() {
    use super::authz_http::{Api, As, browser, native, refused, success, validate_openapi_schema};
    use serde_json::{Value, json};

    let mut f = Fixture::new(&[GPU0, GPU1], 2).await;
    let mut worker = f.worker().await;
    let controller = open_group(&mut worker, 1, &[GPU0, GPU1]).await;
    // Publish initial snapshot on GROUP (2 GPUs, 24 GiB each, 16 GiB chat floor, 1 GiB headroom,
    // 7 GiB grantable on each GPU). GROUP_B remains unobserved so it is unavailable.
    let s0 = DeviceObservation {
        device_id: GPU0.into(),
        total_bytes: TOTAL,
        committed_bytes: 0,
        actual_used_bytes: FLOOR + 2 * GIB,
        reclaimable_bytes: 2 * GIB,
        safety_headroom_bytes: HEADROOM,
        active_chat_floor_bytes: FLOOR,
        grantable_bytes: 5 * GIB,
    };
    let s1 = DeviceObservation {
        device_id: GPU1.into(),
        total_bytes: TOTAL,
        committed_bytes: 0,
        actual_used_bytes: FLOOR,
        reclaimable_bytes: 0,
        safety_headroom_bytes: HEADROOM,
        active_chat_floor_bytes: FLOOR,
        grantable_bytes: SPARE,
    };
    assert!(
        publish(&mut worker, &controller, 2, 0, &[s0, s1])
            .await
            .unwrap()
    );
    // Commit an unwatermarked 3 GiB burst grant on GPU0 so GPU0 effective_grantable = 2 GiB while
    // GPU1 effective_grantable = 7 GiB.
    let grant_id = granted(
        capacity::grant(
            &mut worker,
            &controller,
            &f.request(0, "http-vis-grant", &[bytes(GPU0, 3 * GIB)]),
        )
        .await
        .unwrap(),
    );

    // Seed synthetic accounts: regular user (alice), family-restricted user (kid), operator with
    // opt-in `capacity.inspect` (op), and account_admin (adm).
    let alice = authz_store::account(
        &mut f.owner,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let kid = authz_store::account(
        &mut f.owner,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let op = authz_store::account(
        &mut f.owner,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let adm = authz_store::account(
        &mut f.owner,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    authz_store::make_admin(&mut f.owner, &adm).await;
    sqlx::query(
        "INSERT INTO openmettle.user_capability_grants (user_id, capability, granted, updated_by_user_id)
         VALUES ($1::uuid, 'capacity.inspect', true, $2::uuid)",
    )
    .bind(&op.user)
    .bind(&adm.user)
    .execute(&mut f.owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.user_capability_denies (user_id, capability, denied, updated_by_user_id)
         VALUES ($1::uuid, 'media.blocked', true, $2::uuid)",
    )
    .bind(&alice.user)
    .bind(&adm.user)
    .execute(&mut f.owner)
    .await
    .unwrap();
    // Family policy for `kid` disables model `a` at all hours (P1 #7).
    let fam_policy_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_user_id, active, zone)
         VALUES ('user', $1::uuid, true, 'UTC')
         RETURNING id::text",
    )
    .bind(&kid.user)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
         VALUES ($1::uuid, 'disabled', 'a', true)",
    )
    .bind(&fam_policy_id)
    .execute(&mut f.owner)
    .await
    .unwrap();

    // Seed configured profiles covering availability projection, capability/catalog/family
    // filtering, explicit `model_id` fail-closed removal, and non-emission of static waits:
    // - `a` (model_id = 'a', unrestricted in catalog): ready for alice, omitted for kid (family policy!)
    // - `b` (model_id = 'b', requires opt-in `model.restricted`): omitted for alice and kid
    // - `model.removed` (model_id = 'removed-model', absent from catalog): omitted (fail closed!)
    // - `media.busy`: 4 GiB on 2 GPUs, wait=NULL -> busy
    // - `media.queued`: 4 GiB on 2 GPUs, wait=30 -> busy (P2 #11: never emits fabricated static wait)
    // - `media.oversized`: 8 GiB on 1 GPU, wait=60 -> unavailable
    // - `media.unobserved`: mapped to GROUP_B (unobserved) -> unavailable
    // - `media.denied`: requires `media.blocked` (user-denied for alice) -> omitted for alice
    // - `media.optin`: requires opt-in `media.secret` -> omitted for alice
    for (profile, group, per_dev, req_dev, req_cap, gate, model_id, wait) in [
        (
            "a",
            GROUP,
            2 * GIB,
            1,
            None,
            "on_by_default",
            Some("a"),
            None,
        ),
        (
            "b",
            GROUP,
            2 * GIB,
            1,
            None,
            "on_by_default",
            Some("b"),
            None,
        ),
        (
            "model.removed",
            GROUP,
            2 * GIB,
            1,
            None,
            "on_by_default",
            Some("removed-model"),
            None,
        ),
        (
            "media.busy",
            GROUP,
            4 * GIB,
            2,
            None,
            "on_by_default",
            None,
            None,
        ),
        (
            "media.queued",
            GROUP,
            4 * GIB,
            2,
            None,
            "on_by_default",
            None,
            Some(30),
        ),
        (
            "media.oversized",
            GROUP,
            8 * GIB,
            1,
            None,
            "on_by_default",
            None,
            Some(60),
        ),
        (
            "media.unobserved",
            GROUP_B,
            2 * GIB,
            1,
            None,
            "on_by_default",
            None,
            Some(15),
        ),
        (
            "media.denied",
            GROUP,
            GIB,
            1,
            Some("media.blocked"),
            "on_by_default",
            None,
            None,
        ),
        (
            "media.optin",
            GROUP,
            GIB,
            1,
            Some("media.secret"),
            "opt_in",
            None,
            None,
        ),
    ] {
        sqlx::query(
            "INSERT INTO openmettle.capacity_profiles
                (profile, group_id, per_device_bytes, required_devices,
                 required_capability, capability_gate, model_id, estimated_wait_seconds)
             VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8)",
        )
        .bind(profile)
        .bind(group)
        .bind(per_dev)
        .bind(req_dev)
        .bind(req_cap)
        .bind(gate)
        .bind(model_id)
        .bind(wait)
        .execute(&mut f.owner)
        .await
        .unwrap();
    }

    // Mount real openmettle-api with a model catalog where model `b` requires opt-in capability.
    let dir = auth_config_support::Dir::new();
    std::fs::create_dir(dir.path("artifacts")).unwrap();
    let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    catalog["models"]["b"]["required_capabilities"] = json!({"model.restricted": "opt_in"});
    doc["catalog_file"] = json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
    let api = Api::configured(&f.db, dir, doc, 4);

    let (alice_cookie, alice_bearer) = (
        browser(&f.db, &alice, 1).await,
        native(&f.db, &alice, 2).await,
    );
    let kid_cookie = browser(&f.db, &kid, 6).await;
    let op_cookie = browser(&f.db, &op, 3).await;
    let (adm_cookie, adm_bearer) = (browser(&f.db, &adm, 4).await, native(&f.db, &adm, 5).await);
    let (alice_b, alice_n) = (As::Browser(&alice_cookie), As::Native(&alice_bearer));
    let kid_b = As::Browser(&kid_cookie);
    let op_b = As::Browser(&op_cookie);
    let (adm_b, adm_n) = (As::Browser(&adm_cookie), As::Native(&adm_bearer));

    // Create a private project owned by alice so we can prove `capacity.inspect` grants no content access.
    let private_project = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("cap-priv-proj"),
            Some(&json!({"name": "Private Space"})),
        ),
        201,
    );
    let project_id = private_project["project_id"].as_str().unwrap();

    // 1. Coarse user GET /v1/capacity works on browser and native channels, omits denied/opt-in/
    //    catalog-restricted/removed-model profiles, reports `busy` (not fabricated static waits),
    //    and leaks zero internal IDs or byte counters.
    use consumer::CapacityAvailability as A;
    for who in [alice_b, alice_n] {
        let body = success(api.call(who, "GET", "/v1/capacity", None, None), 200);
        assert!(
            validate_openapi_schema("#/components/schemas/CapacitySummary", &body),
            "{body}"
        );
        let decoded = consumer::decode_capacity_summary(&body).unwrap();
        let summary: Vec<(&str, &consumer::CapacityAvailability, Option<u32>)> = decoded
            .iter()
            .map(|p| {
                (
                    p.profile.as_str(),
                    &p.availability,
                    p.estimated_wait_seconds,
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("a", &A::Ready, None),
                ("media.busy", &A::Busy, None),
                ("media.oversized", &A::Unavailable, None),
                ("media.queued", &A::Busy, None),
                ("media.unobserved", &A::Unavailable, None),
            ]
        );
        let wire = body.to_string();
        for forbidden in [
            GROUP,
            GROUP_B,
            GPU0,
            GPU1,
            grant_id.as_str(),
            f.scope.as_str(),
            f.runs[0].run.as_str(),
            "media.denied",
            "media.optin",
            "model.removed",
            "\"b\"",
        ] {
            assert!(!wire.contains(forbidden), "leaked {forbidden} in {wire}");
        }
    }

    // 1b. Family policy blocking model `a` hides profile `a` for `kid` (P1 #7).
    let kid_body = success(api.call(kid_b, "GET", "/v1/capacity", None, None), 200);
    let kid_profiles = consumer::decode_capacity_summary(&kid_body).unwrap();
    assert!(
        !kid_profiles.iter().any(|p| p.profile == "a"),
        "family-policy-disabled model `a` must be omitted: {kid_profiles:?}"
    );
    assert!(
        kid_profiles.iter().any(|p| p.profile == "media.busy"),
        "non-model profile stays visible for kid"
    );

    // 1c. API mounted WITHOUT a model catalog fails closed on `model_id`-backed profiles (P1 #7).
    {
        let no_cat_dir = auth_config_support::Dir::new();
        let no_cat_doc = auth_config_support::document_v2_native(&no_cat_dir, &ca::Ca::new().pem());
        let no_cat_api = Api::configured(&f.db, no_cat_dir, no_cat_doc, 4);
        let no_cat_body = success(
            no_cat_api.call(alice_b, "GET", "/v1/capacity", None, None),
            200,
        );
        let no_cat_profiles = consumer::decode_capacity_summary(&no_cat_body).unwrap();
        assert!(
            !no_cat_profiles
                .iter()
                .any(|p| p.profile == "a" || p.profile == "b" || p.profile == "model.removed"),
            "model_id-backed profiles must fail closed when no catalog is configured: {no_cat_profiles:?}"
        );
        assert!(no_cat_profiles.iter().any(|p| p.profile == "media.busy"));
    }

    // 2. Query parameters and wrong methods are rejected cleanly.
    refused(
        api.call(alice_b, "GET", "/v1/capacity?extra=1", None, None),
        400,
        "validation",
    );
    refused(
        api.call(
            adm_b,
            "GET",
            "/v1/admin/capacity/groups?extra=1",
            None,
            None,
        ),
        400,
        "validation",
    );
    refused(
        api.call(alice_b, "POST", "/v1/capacity", Some("k"), Some(&json!({}))),
        404,
        "not_found",
    );

    // 3. Privileged GET /v1/admin/capacity/groups: regular user gets 403 policy; active
    //    account_admin and opt-in `capacity.inspect` operator both succeed, without leaking
    //    controller_token_hash or tenant grant identifiers.
    refused(
        api.call(alice_b, "GET", "/v1/admin/capacity/groups", None, None),
        403,
        "policy",
    );
    for who in [adm_b, adm_n, op_b] {
        let body = success(
            api.call(who, "GET", "/v1/admin/capacity/groups", None, None),
            200,
        );
        assert!(
            validate_openapi_schema("#/components/schemas/AdminCapacityGroupList", &body),
            "{body}"
        );
        let groups = consumer::decode_admin_capacity_groups(&body).unwrap();
        assert_eq!(groups.len(), 2);
        let g = groups.iter().find(|g| g.group_id == GROUP).unwrap();
        assert!(g.admits_bursts);
        assert_eq!(g.observation_revision, 2);
        assert!(g.observed_at.is_some());
        assert_eq!(g.devices.len(), 2);
        let d0 = g.devices.iter().find(|d| d.device_id == GPU0).unwrap();
        let d1 = g.devices.iter().find(|d| d.device_id == GPU1).unwrap();
        assert_eq!(d0.grantable_bytes, 5 * GIB);
        assert_eq!(d0.effective_grantable_bytes, 2 * GIB);
        assert_eq!(d1.grantable_bytes, SPARE);
        assert_eq!(d1.effective_grantable_bytes, SPARE);
        assert_eq!(
            g.totals.effective_grantable_bytes,
            (2 * GIB + SPARE) as u128
        );
        let gb = groups.iter().find(|g| g.group_id == GROUP_B).unwrap();
        assert!(!gb.admits_bursts);
        assert!(gb.observed_at.is_none());
        assert!(gb.devices.is_empty());
        let wire = body.to_string();
        for forbidden in [
            grant_id.as_str(),
            f.scope.as_str(),
            f.runs[0].run.as_str(),
            "controller_token_hash",
        ] {
            assert!(!wire.contains(forbidden), "leaked {forbidden} in {wire}");
        }
    }

    // 4. Operator with `capacity.inspect` gains ZERO content access to private projects.
    refused(
        api.call(
            op_b,
            "GET",
            &format!("/v1/projects/{project_id}"),
            None,
            None,
        ),
        404,
        "not_found",
    );

    // 5. Explicit user deny and platform deny on `capacity.inspect` BOTH beat active
    //    `account_admin` and opt-in operator grants (P1 #6).
    sqlx::query(
        "INSERT INTO openmettle.user_capability_denies (user_id, capability, denied, updated_by_user_id)
         VALUES ($1::uuid, 'capacity.inspect', true, $2::uuid),
                ($2::uuid, 'capacity.inspect', true, $2::uuid)",
    )
    .bind(&op.user)
    .bind(&adm.user)
    .execute(&mut f.owner)
    .await
    .unwrap();
    refused(
        api.call(op_b, "GET", "/v1/admin/capacity/groups", None, None),
        403,
        "policy",
    );
    refused(
        api.call(adm_b, "GET", "/v1/admin/capacity/groups", None, None),
        403,
        "policy",
    );
    // Clear adm's user deny, then test platform deny against adm.
    sqlx::query(
        "UPDATE openmettle.user_capability_denies SET denied = false
          WHERE user_id = $1::uuid AND capability = 'capacity.inspect'",
    )
    .bind(&adm.user)
    .execute(&mut f.owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.platform_capability_denies (capability, denied, updated_by_user_id)
         VALUES ('capacity.inspect', true, $1::uuid)",
    )
    .bind(&adm.user)
    .execute(&mut f.owner)
    .await
    .unwrap();
    refused(
        api.call(adm_b, "GET", "/v1/admin/capacity/groups", None, None),
        403,
        "policy",
    );
    // Clear platform deny so adm can inspect remaining state transitions.
    sqlx::query(
        "UPDATE openmettle.platform_capability_denies SET denied = false
          WHERE capability = 'capacity.inspect'",
    )
    .execute(&mut f.owner)
    .await
    .unwrap();

    // 6. An `in_flight` prepared grant flips `admits_bursts` to false immediately on
    //    GET /v1/admin/capacity/groups (P1 #4).
    sqlx::query(
        "UPDATE openmettle.capacity_grants SET dispatch_state = 'in_flight'
          WHERE id = $1::uuid",
    )
    .bind(&grant_id)
    .execute(&mut f.owner)
    .await
    .unwrap();
    let inflight_admin = success(
        api.call(adm_b, "GET", "/v1/admin/capacity/groups", None, None),
        200,
    );
    assert!(
        !consumer::decode_admin_capacity_groups(&inflight_admin)
            .unwrap()
            .iter()
            .find(|g| g.group_id == GROUP)
            .unwrap()
            .admits_bursts
    );
    sqlx::query(
        "UPDATE openmettle.capacity_grants SET dispatch_state = 'confirmed'
          WHERE id = $1::uuid",
    )
    .bind(&grant_id)
    .execute(&mut f.owner)
    .await
    .unwrap();

    // 7. Aging the observation past its TTL flips `admits_bursts` to false and all GROUP profiles
    //    to `unavailable`.
    f.owner_exec(
        "UPDATE openmettle.capacity_groups
            SET observed_at = clock_timestamp() - interval '120 seconds'
          WHERE id = $1::uuid",
        &[GROUP],
    )
    .await;
    let stale_admin = success(
        api.call(adm_b, "GET", "/v1/admin/capacity/groups", None, None),
        200,
    );
    let stale_groups = consumer::decode_admin_capacity_groups(&stale_admin).unwrap();
    assert!(
        !stale_groups
            .iter()
            .find(|g| g.group_id == GROUP)
            .unwrap()
            .admits_bursts
    );
    let stale_user = success(api.call(alice_b, "GET", "/v1/capacity", None, None), 200);
    let stale_profiles = consumer::decode_capacity_summary(&stale_user).unwrap();
    assert!(
        stale_profiles.iter().all(|p| p.availability
            == consumer::CapacityAvailability::Unavailable
            && p.estimated_wait_seconds.is_none()),
        "{stale_profiles:?}"
    );
}
