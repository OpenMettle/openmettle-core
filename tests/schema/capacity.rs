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
