//! ADR 0042 PR2: fenced capacity controller store and device-slot reconciliation on
//! PostgreSQL 18. All identities, devices and byte counts are synthetic.
use super::*;
use openmettle_core::{
    authz::{
        leases::LeaseSettings,
        runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
    },
    capacity::{
        self, Decision, DeviceBytes, DeviceObservation, Error, Fence, GrantRequest, GrantState,
        Observation, Release,
    },
    quotas::{self, RunBudgetReservation},
    runs::{RunInput, WriteTransaction},
};

const GROUP: &str = "00000000-0000-4000-8000-00000000c001";
const GPU0: &str = "00000000-0000-4000-8000-00000000c0d0";
const GPU1: &str = "00000000-0000-4000-8000-00000000c0d1";
const CTRL_A: &str = "00000000-0000-4000-8000-00000000c0a1";
const CTRL_B: &str = "00000000-0000-4000-8000-00000000c0b2";
const GIB: i64 = 1 << 30;
/// 24 GiB device: chat uses its 16 GiB floor, 1 GiB headroom, so 7 GiB is grantable.
const TOTAL: i64 = 24 * GIB;
const FLOOR: i64 = 16 * GIB;
const HEADROOM: i64 = GIB;
const SPARE: i64 = TOTAL - FLOOR - HEADROOM;

/// One leased run with its run-level `device_reservations` hold.
struct Leased {
    run: String,
    claim: String,
    hold: String,
}

struct Fixture {
    db: TestDb,
    owner: PgConnection,
    scope: String,
    runs: Vec<Leased>,
}

impl Fixture {
    /// A group with `devices` configured and `runs` claimed runs that each hold one device slot.
    async fn new(devices: &[&str], runs: usize) -> Self {
        let db = TestDb::migrated().await;
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
        sqlx::query(
            "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms) VALUES ($1::uuid, 60000)",
        )
        .bind(GROUP)
        .execute(&mut owner)
        .await
        .unwrap();
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
            let hold: String = sqlx::query_scalar(
                "SELECT id::text FROM openmettle.quota_reservations
                  WHERE run_id = $1::uuid AND gateway_request_id IS NULL
                    AND resource_kind = 'device_reservations'",
            )
            .bind(&claim.run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
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
        .bind(&self.runs[run].hold)
        .fetch_one(&mut self.owner)
        .await
        .unwrap()
    }

    async fn expire_controller_lease(&mut self) {
        sqlx::query(
            "UPDATE openmettle.capacity_groups
                SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        )
        .bind(GROUP)
        .execute(&mut self.owner)
        .await
        .unwrap();
    }

    /// Change the group's configured freshness TTL, as an operator would.
    async fn ttl(&mut self, ms: i32) {
        sqlx::query(
            "UPDATE openmettle.capacity_groups SET observation_ttl_ms = $2 WHERE id = $1::uuid",
        )
        .bind(GROUP)
        .bind(ms)
        .execute(&mut self.owner)
        .await
        .unwrap();
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
    fence: &Fence<'_>,
    revision: i64,
    watermark: i64,
    devices: &[DeviceObservation],
) -> Result<bool, Error> {
    let observed_at_us = db_now_us(c).await;
    capacity::publish(
        c,
        fence,
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

/// Acquire, publish a full-spare snapshot at `revision` and resume: the group admits bursts.
async fn open_group(
    c: &mut PgConnection,
    controller: &'static str,
    revision: i64,
    devices: &[&str],
) -> i64 {
    let epoch = capacity::acquire(c, GROUP, controller, Duration::from_secs(60))
        .await
        .unwrap();
    let fence = Fence {
        group_id: GROUP,
        controller_id: controller,
        epoch,
    };
    let samples: Vec<_> = devices.iter().map(|d| sample(d, 0, SPARE)).collect();
    assert!(publish(c, &fence, revision, 0, &samples).await.unwrap());
    assert!(capacity::resume(c, &fence).await.unwrap());
    epoch
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn racing_callers_citing_one_revision_cannot_double_spend_the_last_bytes() {
    let mut f = Fixture::new(&[GPU0], 3).await;
    let mut ctl = f.worker().await;
    let epoch = open_group(&mut ctl, CTRL_A, 1, &[GPU0]).await;
    let fence = Fence {
        group_id: GROUP,
        controller_id: CTRL_A,
        epoch,
    };
    let snapshot = capacity::snapshot(&mut ctl, GROUP).await.unwrap().unwrap();
    assert!(snapshot.admits_bursts());
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
        capacity::grant(&mut w0, &fence, &r0),
        capacity::grant(&mut w1, &fence, &r1),
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
        capacity::grant(&mut ctl, &fence, &f.request(2, "over", &over))
            .await
            .unwrap(),
        Decision::Insufficient
    );
    let rest = [bytes(GPU0, 3 * GIB)];
    granted(
        capacity::grant(&mut ctl, &fence, &f.request(2, "rest", &rest))
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
    let old = Fence {
        group_id: GROUP,
        controller_id: CTRL_A,
        epoch: open_group(&mut a, CTRL_A, 1, &[GPU0]).await,
    };
    assert_eq!(old.epoch, 1);
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
        capacity::record_release(&mut a, &old, &first, Release::Releasing)
            .await
            .unwrap(),
        GrantState::Releasing
    );
    let measured_before_takeover = db_now_us(&mut a).await;

    // A live lease cannot be taken over; an expired one advances the epoch.
    let mut b = f.worker().await;
    assert_eq!(
        capacity::acquire(&mut b, GROUP, CTRL_B, Duration::from_secs(60)).await,
        Err(Error::Fenced)
    );
    f.expire_controller_lease().await;
    let new = Fence {
        group_id: GROUP,
        controller_id: CTRL_B,
        epoch: capacity::acquire(&mut b, GROUP, CTRL_B, Duration::from_secs(60))
            .await
            .unwrap(),
    };
    assert_eq!(new.epoch, 2);

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
        capacity::record_release(&mut a, &old, &first, Release::Released(&[GPU0.into()])).await,
        Err(Error::Fenced)
    );
    assert_eq!(capacity::resume(&mut a, &old).await, Err(Error::Fenced));
    assert_eq!(
        capacity::acquire(&mut a, GROUP, CTRL_A, Duration::from_secs(60)).await,
        Err(Error::Fenced)
    );
    let snapshot = capacity::snapshot(&mut b, GROUP).await.unwrap().unwrap();
    assert_eq!(
        (snapshot.controller_epoch, snapshot.observation_revision),
        (2, 1)
    );
    assert!(!snapshot.admits_bursts());
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

    // The successor stays closed until it publishes a sample measured in its own epoch.
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
        capacity::record_release(&mut b, &new, &first, Release::Released(&[GPU0.into()]))
            .await
            .unwrap(),
        GrantState::Released
    );
    assert_eq!(f.slot(0).await, ("released".into(), Some(first), 1));

    // The same controller re-acquiring after its lease lapsed gets a new epoch, and the epoch
    // alone fences its own delayed epoch-2 writes.
    f.expire_controller_lease().await;
    let again = Fence {
        epoch: capacity::acquire(&mut b, GROUP, CTRL_B, Duration::from_secs(60))
            .await
            .unwrap(),
        ..new
    };
    assert_eq!(again.epoch, 3);
    assert_eq!(
        publish(
            &mut b,
            &new,
            3,
            2,
            &[sample(GPU0, 3 * GIB, SPARE - 3 * GIB)]
        )
        .await,
        Err(Error::Fenced)
    );
    assert_eq!(
        capacity::record_release(&mut b, &new, &second, Release::Releasing).await,
        Err(Error::Fenced)
    );
    assert_eq!(
        capacity::grant(&mut b, &again, &f.request(0, "closed", &[bytes(GPU0, GIB)]))
            .await
            .unwrap(),
        Decision::Unavailable
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
    let fence = Fence {
        group_id: GROUP,
        controller_id: CTRL_A,
        epoch: open_group(&mut c, CTRL_A, 1, &[GPU0, GPU1]).await,
    };
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
            publish(&mut c, &fence, 2, 0, &devices).await,
            Err(Error::Invalid)
        );
    }
    assert_eq!(
        publish(&mut c, &fence, 2, 1, &full).await,
        Err(Error::Invalid)
    );
    let future = db_now_us(&mut c).await + 60_000_000;
    assert_eq!(
        capacity::publish(
            &mut c,
            &fence,
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
        capacity::grant(&mut c, &fence, &f.request(0, "fresh", &both))
            .await
            .unwrap(),
    );

    // A sample claiming to include that grant must count it on every device.
    assert_eq!(
        publish(
            &mut c,
            &fence,
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
    assert!(
        capacity::publish(
            &mut c,
            &fence,
            &Observation {
                revision: 2,
                observed_at_us: sampled_at,
                commit_watermark: 1,
                devices: &counted,
            },
        )
        .await
        .unwrap()
    );

    // Past the TTL the group closes, and republishing the old sample never extends freshness.
    f.ttl(1000).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let late = [bytes(GPU0, GIB)];
    assert_eq!(
        capacity::grant(&mut c, &fence, &f.request(1, "stale", &late))
            .await
            .unwrap(),
        Decision::Unavailable
    );
    assert!(
        capacity::publish(
            &mut c,
            &fence,
            &Observation {
                revision: 3,
                observed_at_us: sampled_at,
                commit_watermark: 1,
                devices: &counted,
            },
        )
        .await
        .unwrap()
    );
    // A replayed revision is ignored even when it carries a newer measurement.
    assert!(!publish(&mut c, &fence, 3, 1, &counted).await.unwrap());
    let snapshot = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    assert_eq!(snapshot.observation_revision, 3);
    assert!(snapshot.ready && !snapshot.fresh && !snapshot.admits_bursts());
    assert_eq!(snapshot.totals().committed_bytes, i128::from(2 * GIB));
    assert_eq!(
        capacity::grant(&mut c, &fence, &f.request(1, "stale", &late))
            .await
            .unwrap(),
        Decision::Unavailable
    );
    assert_eq!(
        capacity::publish(
            &mut c,
            &fence,
            &Observation {
                revision: 4,
                observed_at_us: sampled_at - 1,
                commit_watermark: 1,
                devices: &counted,
            },
        )
        .await,
        Err(Error::Invalid)
    );

    // A fresh sample reopens the group; the earlier grant stays charged on both ranks.
    f.ttl(60_000).await;
    assert!(publish(&mut c, &fence, 4, 1, &counted).await.unwrap());
    assert_eq!(
        capacity::grant(
            &mut c,
            &fence,
            &f.request(1, "fit", &[bytes(GPU1, SPARE - GIB + 1)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    granted(
        capacity::grant(
            &mut c,
            &fence,
            &f.request(1, "fit", &[bytes(GPU1, SPARE - GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(f.slot(0).await.1, Some(first));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_recovers_the_recorded_decision_and_conflicting_reuse_is_refused() {
    let mut f = Fixture::new(&[GPU0], 2).await;
    let mut c = f.worker().await;
    let fence = Fence {
        group_id: GROUP,
        controller_id: CTRL_A,
        epoch: open_group(&mut c, CTRL_A, 1, &[GPU0]).await,
    };
    let need = [bytes(GPU0, 2 * GIB)];
    let grant = granted(
        capacity::grant(&mut c, &fence, &f.request(0, "replay", &need))
            .await
            .unwrap(),
    );
    // A lost reply recovers the same grant without a second commitment.
    for _ in 0..2 {
        assert_eq!(
            capacity::grant(&mut c, &fence, &f.request(0, "replay", &need))
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
    // The identity cannot change the footprint, and the run's slot cannot bind a second grant.
    assert_eq!(
        capacity::grant(&mut c, &fence, &f.request(0, "replay", &[bytes(GPU0, GIB)])).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        capacity::grant(&mut c, &fence, &f.request(0, "second", &need)).await,
        Err(Error::Conflict)
    );

    // Release confirmation settles both ledgers once; replays stay idempotent.
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(grant.clone()), 2)
    );
    for _ in 0..2 {
        assert_eq!(
            capacity::record_release(&mut c, &fence, &grant, Release::Released(&[GPU0.into()]))
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
        .bind(&f.runs[0].hold)
        .bind(&grant)
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    let releases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.quota_reconciliations
          WHERE reservation_id = $1::uuid AND kind = 'release' AND delta_reserved = -1",
    )
    .bind(&f.runs[0].hold)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(releases, 1);
    // A replay after release reports the recorded outcome and never re-dispatches.
    assert_eq!(
        capacity::grant(&mut c, &fence, &f.request(0, "replay", &need))
            .await
            .unwrap(),
        Decision::Grant {
            grant_id: grant,
            state: GrantState::Released
        }
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // Only the worker's fenced functions write the store.
    let mut api = connect(&f.db.0, API).await;
    expect_state(
        &mut api,
        "SELECT openmettle.capacity_acquire_controller(gen_random_uuid(), gen_random_uuid(), 1000)",
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
async fn partial_release_keeps_both_ledgers_charged_until_every_device_confirms() {
    let mut f = Fixture::new(&[GPU0, GPU1], 2).await;
    let mut c = f.worker().await;
    let fence = Fence {
        group_id: GROUP,
        controller_id: CTRL_A,
        epoch: open_group(&mut c, CTRL_A, 1, &[GPU0, GPU1]).await,
    };
    let grant = granted(
        capacity::grant(
            &mut c,
            &fence,
            &f.request(0, "two-rank", &[bytes(GPU0, 2 * GIB), bytes(GPU1, 2 * GIB)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        capacity::record_release(&mut c, &fence, &grant, Release::Releasing)
            .await
            .unwrap(),
        GrantState::Releasing
    );
    // Evidence for a device outside the footprint is refused.
    assert_eq!(
        capacity::record_release(
            &mut c,
            &fence,
            &grant,
            Release::Released(&["00000000-0000-4000-8000-00000000c0ff".into()])
        )
        .await,
        Err(Error::Invalid)
    );
    // One rank confirms: the allocation is unknown, both ledgers keep their charges and the
    // group closes to bursts.
    assert_eq!(
        capacity::record_release(&mut c, &fence, &grant, Release::Released(&[GPU0.into()]))
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
                .bind(&f.runs[0].hold)
                .bind(&grant)
                .execute(&mut c)
                .await
        ),
        "OMQ06"
    );
    assert_eq!(
        capacity::grant(
            &mut c,
            &fence,
            &f.request(1, "blocked", &[bytes(GPU0, GIB)])
        )
        .await
        .unwrap(),
        Decision::Unavailable
    );
    let snapshot = capacity::snapshot(&mut c, GROUP).await.unwrap().unwrap();
    assert_eq!(snapshot.unknown_allocations, 1);
    assert!(!snapshot.admits_bursts());
    // The released rank's bytes are not returned by a sample that omits the whole grant.
    assert_eq!(
        publish(
            &mut c,
            &fence,
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
    // A later lost reply cannot downgrade the unknown allocation back to releasing.
    assert_eq!(
        capacity::record_release(&mut c, &fence, &grant, Release::Releasing)
            .await
            .unwrap(),
        GrantState::UnknownAllocation
    );

    // The remaining rank confirms non-allocation: both ledgers settle exactly once.
    assert_eq!(
        capacity::record_release(
            &mut c,
            &fence,
            &grant,
            Release::NotAllocated(&[GPU0.into(), GPU1.into()])
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
    granted(
        capacity::grant(
            &mut c,
            &fence,
            &f.request(1, "reopened", &[bytes(GPU0, GIB)]),
        )
        .await
        .unwrap(),
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn crash_recovery_preserves_charges_until_a_current_controller_reconciles() {
    let mut f = Fixture::new(&[GPU0], 2).await;
    let mut c = f.worker().await;
    let fence = Fence {
        group_id: GROUP,
        controller_id: CTRL_A,
        epoch: open_group(&mut c, CTRL_A, 1, &[GPU0]).await,
    };
    let need = [bytes(GPU0, 4 * GIB)];

    // A grant transaction that never commits leaves neither ledger changed.
    {
        let mut crashed = f.worker().await;
        let mut tx = WriteTransaction::begin(&mut crashed).await.unwrap();
        granted(
            capacity::grant(
                tx.connection().unwrap(),
                &fence,
                &f.request(0, "crash", &need),
            )
            .await
            .unwrap(),
        );
        drop(tx);
    }
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.capacity_grants")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(grants, 0);
    assert_eq!(f.slot(0).await, ("held".into(), None, 2));
    let grant = granted(
        capacity::grant(&mut c, &fence, &f.request(0, "crash", &need))
            .await
            .unwrap(),
    );

    // The worker dies: its expired claim authorizes no new allocation.
    sqlx::query(
        "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&f.runs[0].run)
    .execute(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        capacity::grant(&mut c, &fence, &f.request(0, "after-crash", &need)).await,
        Err(Error::LeaseLost)
    );
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(grant.clone()), 2)
    );

    // The controller dies with the dispatch outcome unknown. Its successor stays closed until it
    // reconciles, and the chat floor plus the live grant stay charged throughout.
    assert_eq!(
        capacity::record_release(&mut c, &fence, &grant, Release::UnknownAllocation)
            .await
            .unwrap(),
        GrantState::UnknownAllocation
    );
    f.expire_controller_lease().await;
    let mut b = f.worker().await;
    let next = Fence {
        group_id: GROUP,
        controller_id: CTRL_B,
        epoch: capacity::acquire(&mut b, GROUP, CTRL_B, Duration::from_secs(60))
            .await
            .unwrap(),
    };
    let committed = [sample(GPU0, 4 * GIB, SPARE - 4 * GIB)];
    assert!(publish(&mut b, &next, 2, 1, &committed).await.unwrap());
    assert!(!capacity::resume(&mut b, &next).await.unwrap());
    assert_eq!(
        capacity::grant(
            &mut b,
            &next,
            &f.request(1, "during-recovery", &[bytes(GPU0, GIB)])
        )
        .await
        .unwrap(),
        Decision::Unavailable
    );
    assert_eq!(
        f.slot(0).await,
        ("handoff_committed".into(), Some(grant.clone()), 2)
    );

    // Behind its new fence the successor finds no allocation and settles the expired run's slot.
    assert_eq!(
        capacity::record_release(&mut b, &next, &grant, Release::NotAllocated(&[GPU0.into()]))
            .await
            .unwrap(),
        GrantState::Released
    );
    assert_eq!(f.slot(0).await, ("released".into(), Some(grant), 1));
    assert!(capacity::resume(&mut b, &next).await.unwrap());
    // The released bytes return only through a fresh sample; the floor stays out of reach.
    assert_eq!(
        capacity::grant(
            &mut b,
            &next,
            &f.request(1, "resumed", &[bytes(GPU0, SPARE)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    assert!(
        publish(&mut b, &next, 3, 1, &[sample(GPU0, 0, SPARE)])
            .await
            .unwrap()
    );
    assert_eq!(
        capacity::grant(
            &mut b,
            &next,
            &f.request(1, "resumed", &[bytes(GPU0, SPARE + 1)])
        )
        .await
        .unwrap(),
        Decision::Insufficient
    );
    granted(
        capacity::grant(
            &mut b,
            &next,
            &f.request(1, "resumed", &[bytes(GPU0, SPARE)]),
        )
        .await
        .unwrap(),
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));
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
