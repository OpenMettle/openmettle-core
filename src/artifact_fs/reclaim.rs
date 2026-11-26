//! A claim fences stale workers. A durable hard link pins the payload inode until the SQL
//! credit commits. Detached anchors are retried independently of normal expiry scans.
use super::{FS_TX_IDLE_TIMEOUT, TX_FENCE_BUDGET as FS_FENCE_WINDOW, *};
use std::{fs::File, time::Instant};

async fn set_fs_tx_idle_timeout(tx: &mut WriteTransaction<'_>) -> Result<(), Error> {
    sqlx::query(FS_TX_IDLE_TIMEOUT)
        .execute(tx.connection()?)
        .await?;
    Ok(())
}

fn check_fence(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        return Err(Error::Io);
    }
    Ok(())
}

pub(super) async fn lock_pin(tx: &mut WriteTransaction<'_>, expected: &str) -> Result<(), Error> {
    let pin: String = sqlx::query_scalar("SELECT openmettle.storage_lock_pinned_volume()::text")
        .fetch_one(tx.connection()?)
        .await?;
    if pin != expected {
        return Err(Error::Io);
    }
    Ok(())
}

fn lock_file(v: &Volume, dir: &File, name: &str, ino: u64, zero: bool) -> Result<File, Error> {
    let file = v.regular(dir, name, true)?;
    file.try_lock().map_err(|_| Error::InProgress)?;
    v.matches(&file, dir, name, ino)?;
    if zero && file.metadata()?.len() != 0 {
        return Err(Error::Io);
    }
    Ok(file)
}
fn anchor(
    v: &Volume,
    source: &File,
    name: &str,
    dir: &File,
    anchor: &str,
    ino: u64,
    deadline: Option<Instant>,
) -> Result<(), Error> {
    if let Some(deadline) = deadline {
        check_fence(deadline)?;
    }
    match at::linkat(source, name, dir, anchor, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(e.into()),
    }
    if v.inode(dir, anchor)? != Some(ino) {
        return Err(Error::Io);
    }
    at::fsync(dir)?;
    Ok(())
}

pub(super) async fn release(
    pool: &PgPool,
    store: &Store,
    scope: &str,
    id: &str,
    age: Option<i64>,
    spill: bool,
) -> Result<bool, Error> {
    runs::uuid(id)?;
    let Some(pin) = store.prepare(pool, false).await? else {
        return Err(Error::Io);
    };
    let mut claim = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let run: Option<String> = sqlx::query_scalar(
        "SELECT run_id::text FROM openmettle.storage_reservations
        WHERE scope_id=$1::uuid AND id=$2::uuid",
    )
    .bind(scope)
    .bind(id)
    .fetch_one(claim.connection()?)
    .await?;
    if let Some(run) = &run {
        let ok=sqlx::query("SELECT FROM openmettle.runs r WHERE id=$1::uuid AND (
            ($2 AND EXISTS (SELECT FROM openmettle.storage_reservations sr JOIN openmettle.operations o
                ON o.id=sr.operation_id AND o.run_id=r.id AND o.scope_id=r.scope_id
                WHERE sr.id=$3::uuid AND o.outcome IN ('succeeded','failed'))
                AND NOT EXISTS (SELECT FROM openmettle.artifact_revisions WHERE reservation_id=$3::uuid))
            OR (NOT $2 AND state IN ('succeeded','failed','interrupted','cancelled')
                AND NOT EXISTS (SELECT FROM openmettle.operations WHERE run_id=r.id AND outcome IN ('intent','outcome_unknown'))))
            FOR NO KEY UPDATE SKIP LOCKED").bind(run).bind(spill).bind(id).fetch_optional(claim.connection()?).await?;
        if ok.is_none() {
            return Ok(false);
        }
    }
    let row=sqlx::query("SELECT reclaim_state,payload_ino::text,gen_random_uuid()::text AS token
        FROM openmettle.storage_reservations WHERE scope_id=$1::uuid AND id=$2::uuid AND state='reserved'
        AND NOT adoption_unverified AND (operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%')=$4
        AND (reclaim_state='none' OR reclaim_lease_until<=clock_timestamp())
        AND (CASE WHEN $4 THEN created_at + $3::bigint * interval '1 millisecond' <= clock_timestamp() ELSE ($3::bigint IS NULL OR coalesce(lease_expires_at, greatest(created_at,
            (SELECT coalesce(r.execution_expires_at,r.queue_expires_at,r.created_at) FROM openmettle.runs r WHERE r.id=run_id))
            + $3 * interval '1 millisecond')<=clock_timestamp()) END)
        FOR UPDATE SKIP LOCKED").bind(scope).bind(id).bind(age).bind(spill).fetch_optional(claim.connection()?).await?;
    let Some(row) = row else { return Ok(false) };
    let truncated = row.get::<String, _>("reclaim_state") == "truncated";
    let token: String = row.get("token");
    let bound = parse_ino(row.get("payload_ino"))?;
    lock_pin(&mut claim, &pin).await?;
    sqlx::query("UPDATE openmettle.storage_reservations SET reclaim_state=CASE WHEN reclaim_state='truncated'
        THEN 'truncated' ELSE 'claiming' END,reclaim_claim_token=$2::uuid,reclaim_lease_until=clock_timestamp()+interval '60 seconds'
        WHERE id=$1::uuid").bind(id).bind(&token).execute(claim.connection()?).await?;
    claim.commit().await?;

    let v = &store.volume;
    v.verify(&pin)?;
    let name = format!(".reclaim.{id}");
    let names = (
        v.inode(&v.staging, &name),
        if truncated {
            Ok(None)
        } else {
            v.inode(&v.staging, id)
        },
        if truncated {
            Ok(None)
        } else {
            v.inode(&v.revisions, id)
        },
    );
    let (a, s, r) = match names {
        (Ok(a), Ok(s), Ok(r)) => (a, s, r),
        _ => {
            quarantine_claim(pool, store, &pin, id, &token).await?;
            return Err(Error::Io);
        }
    };
    let mut claim_ino = bound;
    let mut locked = None;
    if let Some(ino) = bound {
        if a.into_iter().chain(s).chain(r).any(|other| other != ino) || (truncated && a.is_none()) {
            quarantine_claim(pool, store, &pin, id, &token).await?;
            return Err(Error::Io);
        }
        let (dir, src) = if a.is_some() {
            (&v.staging, name.as_str())
        } else if s.is_some() {
            (&v.staging, id)
        } else if r.is_some() {
            (&v.revisions, id)
        } else {
            quarantine_claim(pool, store, &pin, id, &token).await?;
            return Err(Error::Missing);
        };
        let file = lock_file(v, dir, src, ino, false)?;
        if a.is_some() && file.metadata()?.len() != 0 {
            quarantine_claim(pool, store, &pin, id, &token).await?;
            return Err(Error::Io);
        }
        renew(pool, &pin, id, &token, ino, false, truncated).await?;
        if !truncated {
            v.verify(&pin)?;
            // Publication may have linked another name between our first probe and LOCK_EX.
            let (r, s) = match (v.inode(&v.revisions, id), v.inode(&v.staging, id)) {
                (Ok(r), Ok(s))
                    if r.into_iter().chain(s).all(|other| other == ino)
                        && v.matches(&file, dir, src, ino).is_ok() =>
                {
                    (r, s)
                }
                _ => {
                    quarantine_claim(pool, store, &pin, id, &token).await?;
                    return Err(Error::Io);
                }
            };
            file.set_len(0)?;
            file.sync_all()?;
            anchor(v, dir, src, &v.staging, &name, ino, None)?;
            if r.is_some() {
                v.unlink(&v.revisions, id, ino)?;
            }
            if s.is_some() {
                v.unlink(&v.staging, id, ino)?;
            }
        }
        locked = Some(file);
    } else if a.is_some() || r.is_some() || truncated {
        quarantine_claim(pool, store, &pin, id, &token).await?;
        return Err(Error::Io);
    } else if let Some(ino) = s {
        let file = lock_file(v, &v.staging, id, ino, false)?;
        if file.metadata()?.len() != 0 {
            quarantine_claim(pool, store, &pin, id, &token).await?;
            return Err(Error::Io);
        }
        v.matches(&file, &v.staging, id, ino)?;
        if v.inode(&v.revisions, id)?.is_some() || v.inode(&v.staging, &name)?.is_some() {
            quarantine_claim(pool, store, &pin, id, &token).await?;
            return Err(Error::Io);
        }
        // Bind only after the locked, empty file's directory entry is durable.
        at::fsync(&v.staging)?;
        renew(pool, &pin, id, &token, ino, true, false).await?;
        v.verify(&pin)?;
        v.matches(&file, &v.staging, id, ino)?;
        anchor(v, &v.staging, id, &v.staging, &name, ino, None)?;
        v.unlink(&v.staging, id, ino)?;
        claim_ino = Some(ino);
        locked = Some(file);
    }
    at::fsync(&v.staging)?;
    at::fsync(&v.revisions)?;
    if claim_ino.is_some() && !truncated {
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let n=sqlx::query("UPDATE openmettle.storage_reservations SET reclaim_state='truncated',publish_pending=false
            WHERE id=$1::uuid AND state='reserved' AND reclaim_claim_token=$2::uuid AND reclaim_state='claiming'
            AND NOT adoption_unverified AND payload_ino=$3::text::numeric").bind(id).bind(&token)
            .bind(claim_ino.map(|x|x.to_string())).execute(tx.connection()?).await?.rows_affected();
        if n != 1 {
            return Ok(false);
        }
        lock_pin(&mut tx, &pin).await?;
        tx.commit().await?;
    }
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    if let Some(run) = &run {
        sqlx::query("SELECT FROM openmettle.runs WHERE id=$1::uuid FOR NO KEY UPDATE")
            .bind(run)
            .execute(tx.connection()?)
            .await?;
    }
    let exists=sqlx::query("SELECT FROM openmettle.storage_reservations WHERE scope_id=$1::uuid AND id=$2::uuid
        AND reclaim_claim_token=$3::uuid AND NOT adoption_unverified AND NOT publish_pending AND state='reserved'
        AND (payload_ino IS NULL OR reclaim_state='truncated') FOR UPDATE").bind(scope).bind(id).bind(&token)
        .fetch_optional(tx.connection()?).await?;
    if exists.is_none() {
        return Ok(false);
    }
    lock_pin(&mut tx, &pin).await?;
    storage::release_claimed(&mut tx, scope, id, &token).await?;
    tx.commit().await?;
    drop(locked);
    if let Some(ino) = claim_ino {
        detach(pool, store, &pin, id, id, ino, false, None).await?;
    }
    Ok(true)
}

async fn quarantine_claim(
    pool: &PgPool,
    store: &Store,
    pin: &str,
    id: &str,
    token: &str,
) -> Result<(), Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET adoption_unverified=true,publish_pending=false,
        reclaim_state='none',reclaim_claim_token=NULL,reclaim_lease_until=NULL
        WHERE id=$1::uuid AND state='reserved' AND reclaim_claim_token=$2::uuid",
    )
    .bind(id)
    .bind(token)
    .execute(tx.connection()?)
    .await?;
    lock_pin(&mut tx, pin).await?;
    store.volume.verify(pin)?;
    tx.commit().await?;
    Ok(())
}

fn parse_ino(text: Option<String>) -> Result<Option<u64>, Error> {
    text.map(|s| s.parse().map_err(|_| Error::Io)).transpose()
}
async fn renew(
    pool: &PgPool,
    pin: &str,
    id: &str,
    token: &str,
    ino: u64,
    bind: bool,
    truncated: bool,
) -> Result<(), Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let result=sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$3::text::numeric,
        reclaim_lease_until=clock_timestamp()+interval '300 seconds' WHERE id=$1::uuid AND reclaim_claim_token=$2::uuid
        AND state='reserved' AND NOT adoption_unverified AND reclaim_state=$5
        AND (CASE WHEN $4 THEN payload_ino IS NULL ELSE payload_ino=$3::text::numeric END)")
        .bind(id).bind(token).bind(ino.to_string()).bind(bind).bind(if truncated {"truncated"} else {"claiming"}).execute(tx.connection()?).await?;
    if result.rows_affected() != 1 {
        return Err(Error::InProgress);
    }
    lock_pin(&mut tx, pin).await?;
    tx.commit().await?;
    Ok(())
}

async fn assert_volume_phase(
    tx: &mut WriteTransaction<'_>,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<(), Error> {
    sqlx::query("SELECT openmettle.restore_assert_volume_phase($1::uuid, $2::uuid)")
        .bind(restore_run_id)
        .bind(claim_token)
        .execute(tx.connection()?)
        .await?;
    Ok(())
}

async fn renew_volume_phase(
    pool: &PgPool,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<(), Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    sqlx::query("SELECT openmettle.restore_renew_volume_phase($1::uuid, $2::uuid)")
        .bind(restore_run_id)
        .bind(claim_token)
        .execute(tx.connection()?)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn detach(
    pool: &PgPool,
    store: &Store,
    pin: &str,
    id: &str,
    reservation: &str,
    ino: u64,
    purge: bool,
    phase: Option<(&str, &str)>,
) -> Result<(), Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    set_fs_tx_idle_timeout(&mut tx).await?;
    let (check, clear) = if purge {
        ("SELECT FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr ON sr.scope_id=r.scope_id
          AND sr.id=r.reservation_id WHERE r.id=$1::uuid AND r.state='purged' AND r.purge_stage='anchor_pending_unlink'
          AND NOT sr.adoption_unverified AND sr.payload_ino=$2::text::numeric FOR UPDATE OF r",
         "UPDATE openmettle.artifact_revisions SET purge_stage='none' WHERE id=$1::uuid")
    } else {
        ("SELECT FROM openmettle.storage_reservations WHERE id=$1::uuid AND state='released' AND NOT adoption_unverified
          AND reclaim_state='anchor_pending_unlink' AND payload_ino=$2::text::numeric FOR UPDATE",
         "UPDATE openmettle.storage_reservations SET reclaim_state='none' WHERE id=$1::uuid")
    };
    if sqlx::query(check)
        .bind(id)
        .bind(ino.to_string())
        .fetch_optional(tx.connection()?)
        .await?
        .is_none()
    {
        return Ok(());
    }
    if let Some((restore_run_id, claim_token)) = phase {
        assert_volume_phase(&mut tx, restore_run_id, claim_token).await?;
    } else if purge && !crate::restore::lock_open_gate(tx.connection()?).await? {
        return Ok(());
    }
    let fence_deadline = Instant::now() + FS_FENCE_WINDOW;
    lock_pin(&mut tx, pin).await?;
    check_fence(fence_deadline)?;
    let v = &store.volume;
    v.verify(pin)?;
    let (dir, name) = if purge {
        (&v.revisions, format!(".purge.{reservation}"))
    } else {
        (&v.staging, format!(".reclaim.{reservation}"))
    };
    if v.inode(dir, &name)?.is_some() {
        let _guard = lock_file(v, dir, &name, ino, true)?;
        v.unlink_before(dir, &name, ino, fence_deadline)?;
    }
    at::fsync(dir)?;
    sqlx::query(clear)
        .bind(id)
        .execute(tx.connection()?)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn purge_one(
    pool: &PgPool,
    store: &Store,
    pin: &str,
    scope: &str,
    id: &str,
    reservation: &str,
    ino: u64,
    phase: Option<(&str, &str)>,
) -> Result<bool, Error> {
    if let Some((restore_run_id, claim_token)) = phase {
        renew_volume_phase(pool, restore_run_id, claim_token).await?;
    }
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    store.volume.verify(pin)?;
    match storage::begin_purge(&mut tx, scope, id).await {
        Ok(()) => {}
        Err(runs::Error::NotEligible) => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    if let Some((restore_run_id, claim_token)) = phase {
        assert_volume_phase(&mut tx, restore_run_id, claim_token).await?;
    } else if !crate::restore::lock_open_gate(tx.connection()?).await? {
        return Ok(false);
    }
    lock_pin(&mut tx, pin).await?;
    tx.commit().await?;
    let v = &store.volume;
    v.verify(pin)?;
    let name = format!(".purge.{reservation}");
    let a = v.inode(&v.revisions, &name)?;
    let r = v.inode(&v.revisions, reservation)?;
    if r.is_some_and(|other| other != ino) {
        return Err(Error::Io);
    }
    let src = if a == Some(ino) {
        name.as_str()
    } else if a.is_none() && r == Some(ino) {
        reservation
    } else {
        return Err(Error::Io);
    };
    let f = lock_file(v, &v.revisions, src, ino, false)?;
    // Hold artifact_revisions FOR UPDATE -> restore_reconciliation_gate FOR SHARE ->
    // storage_volume_control FOR SHARE continuously across Stage A filesystem mutations for both
    // live `purge_due` and restore `purge_journaled`.
    let mut stage_a = WriteTransaction::begin_bounded_pool(pool, false).await?;
    set_fs_tx_idle_timeout(&mut stage_a).await?;
    let live=sqlx::query("SELECT FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr
        ON sr.id=r.reservation_id AND sr.scope_id=r.scope_id WHERE r.id=$1::uuid AND r.state='purging'
        AND NOT sr.adoption_unverified AND sr.payload_ino=$2::text::numeric FOR UPDATE OF r")
        .bind(id).bind(ino.to_string()).fetch_optional(stage_a.connection()?).await?;
    if live.is_none() {
        return Ok(false);
    }
    if let Some((restore_run_id, claim_token)) = phase {
        assert_volume_phase(&mut stage_a, restore_run_id, claim_token).await?;
    } else if !crate::restore::lock_open_gate(stage_a.connection()?).await? {
        return Ok(false);
    }
    let fence_deadline = Instant::now() + FS_FENCE_WINDOW;
    lock_pin(&mut stage_a, pin).await?;
    check_fence(fence_deadline)?;
    v.verify(pin)?;
    v.matches(&f, &v.revisions, src, ino)?;
    let a_now = v.inode(&v.revisions, &name)?;
    let r_now = v.inode(&v.revisions, reservation)?;
    let s_now = v.inode(&v.staging, reservation)?;
    if a_now.is_some_and(|other| other != ino) || r_now.is_some_and(|other| other != ino) {
        return Err(Error::Io);
    }
    let own = u64::from(a_now == Some(ino))
        + u64::from(r_now == Some(ino))
        + u64::from(s_now == Some(ino));
    if f.metadata()?.nlink() != own {
        return Err(Error::Io);
    }
    check_fence(fence_deadline)?;
    f.set_len(0)?;
    f.sync_all()?;
    anchor(
        v,
        &v.revisions,
        src,
        &v.revisions,
        &name,
        ino,
        Some(fence_deadline),
    )?;
    if r_now == Some(ino) {
        v.unlink_before(&v.revisions, reservation, ino, fence_deadline)?;
    }
    if s_now == Some(ino) {
        v.unlink_before(&v.staging, reservation, ino, fence_deadline)?;
    }
    at::fsync(&v.revisions)?;
    at::fsync(&v.staging)?;
    stage_a.commit().await?;
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    if let Some((restore_run_id, claim_token)) = phase {
        sqlx::query(
            "SELECT FROM openmettle.artifact_revisions WHERE scope_id = $1::uuid AND id = $2::uuid FOR UPDATE",
        )
        .bind(scope)
        .bind(id)
        .execute(tx.connection()?)
        .await?;
        assert_volume_phase(&mut tx, restore_run_id, claim_token).await?;
    }
    storage::confirm_purge(&mut tx, scope, id).await?;
    tx.commit().await?;
    drop(f);
    detach(pool, store, pin, id, reservation, ino, true, phase).await?;
    Ok(true)
}

#[derive(Default, Debug)]
pub(super) struct AnchorPass {
    after: Option<(String, String)>,
    upper: Option<(String, String)>,
}

async fn sweep_anchors(
    pool: &PgPool,
    store: &Store,
    pin: &str,
    limit: i64,
    purge: bool,
    phase: Option<(&str, &str)>,
) -> Result<bool, Error> {
    if let Some((restore_run_id, claim_token)) = phase {
        renew_volume_phase(pool, restore_run_id, claim_token).await?;
    }
    let (from, ts, id, res) = if purge {
        ("openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr ON sr.scope_id=r.scope_id AND sr.id=r.reservation_id
          WHERE r.state='purged' AND r.purge_stage='anchor_pending_unlink' AND NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL",
         "r.purged_at","r.id","r.reservation_id")
    } else {
        ("openmettle.storage_reservations sr WHERE sr.state='released' AND sr.reclaim_state='anchor_pending_unlink'
          AND NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL","sr.closed_at","sr.id","sr.id")
    };
    let mut pass = store.anchor_pass[usize::from(purge)].lock().await;
    if pass.upper.is_none() {
        pass.upper = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {ts}::text,{id}::text FROM {from} ORDER BY {ts} DESC,{id} DESC LIMIT 1"
        )))
        .fetch_optional(pool)
        .await?;
    }
    let Some(upper) = pass.upper.clone() else {
        return Ok(true);
    };
    let page = sqlx::query_as::<_, (String, String, String, String)>(sqlx::AssertSqlSafe(format!(
        "SELECT {ts}::text,{id}::text,{res}::text,sr.payload_ino::text FROM {from}
         AND ($1::text::timestamptz IS NULL OR ({ts},{id})>($1::text::timestamptz,$2::uuid))
         AND ({ts},{id})<=($3::text::timestamptz,$4::uuid) ORDER BY {ts},{id} LIMIT $5"
    )))
    .bind(pass.after.as_ref().map(|v| &v.0))
    .bind(pass.after.as_ref().map(|v| &v.1))
    .bind(&upper.0)
    .bind(&upper.1)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let short = page.len() < limit as usize;
    let mut error = None;
    for (ts, id, res, ino) in page {
        if let Some((restore_run_id, claim_token)) = phase {
            renew_volume_phase(pool, restore_run_id, claim_token).await?;
        }
        if let Err(e) = detach(
            pool,
            store,
            pin,
            &id,
            &res,
            ino.parse().map_err(|_| Error::Io)?,
            purge,
            phase,
        )
        .await
        {
            error = Some(e);
        }
        pass.after = Some((ts, id));
    }
    let finished = short || pass.after == pass.upper;
    if finished {
        *pass = AnchorPass::default();
    }
    error.map_or(Ok(finished), Err)
}

pub async fn reconcile_expired(
    pool: &PgPool,
    store: &Store,
    older_than: Duration,
    limit: i64,
) -> Result<usize, Error> {
    batch(limit)?;
    let staging = staging::sweep(pool, store, limit as usize).await;
    let Some(pin) = store.prepare(pool, false).await? else {
        return staging.map(|()| 0);
    };
    let anchors = sweep_anchors(pool, store, &pin, limit, false, None)
        .await
        .map(|_| ());
    let age = i64::try_from(older_than.as_millis()).map_err(|_| Error::Io)?;
    let mut count = 0;
    let mut failure = None;
    for partition in 0..4 {
        match expiry_page(pool, store, partition, age, limit).await {
            Ok(n) => count += n,
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }

    anchors?;
    staging?;
    Ok(count)
}

/// Reclaim only old, operation-bound tool spills after their outcome is known.
pub async fn reconcile_run_spills(
    pool: &PgPool,
    store: &Store,
    older_than: Duration,
    limit: i64,
) -> Result<usize, Error> {
    batch(limit)?;
    if store.prepare(pool, false).await?.is_none() {
        return Ok(0);
    }
    expiry_page(
        pool,
        store,
        4,
        i64::try_from(older_than.as_millis()).map_err(|_| Error::Io)?,
        limit,
    )
    .await
}

// Each expiry partition has its own keyset cursor and fixed pass watermark.
async fn expiry_page(
    pool: &PgPool,
    store: &Store,
    partition: usize,
    age: i64,
    limit: i64,
) -> Result<usize, Error> {
    let spill = partition == 4;
    let legacy = partition % 2 == 1;
    let (column, expiry) = if spill {
        (
            "created_at",
            "operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'",
        )
    } else if legacy {
        ("created_at", "lease_expires_at IS NULL")
    } else {
        ("lease_expires_at", "lease_expires_at IS NOT NULL")
    };
    let run = if spill {
        "run_id IS NOT NULL"
    } else if partition < 2 {
        "run_id IS NULL"
    } else {
        "run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')"
    };
    let mut pass = store.expiry_pass[partition].lock().await;
    if pass.upper.is_none() {
        let cutoff: String = sqlx::query_scalar(
            "SELECT (clock_timestamp()-$1::bigint*interval '1 millisecond')::text",
        )
        .bind(if legacy || spill { age } else { 0 })
        .fetch_one(pool)
        .await?;
        pass.upper = Some((cutoff, "ffffffff-ffff-ffff-ffff-ffffffffffff".into()));
    }
    let upper = pass.upper.as_ref().ok_or(Error::Io)?;
    let (after, id) = pass
        .after
        .as_ref()
        .map(|(t, id)| (t.as_str(), id.as_str()))
        .unwrap_or(("-infinity", "00000000-0000-0000-0000-000000000000"));
    let page=sqlx::query_as::<_,(String,String,String)>(sqlx::AssertSqlSafe(format!("SELECT {column}::text,id::text,scope_id::text
        FROM openmettle.storage_reservations WHERE state='reserved' AND NOT adoption_unverified AND {expiry} AND {run}
        AND ({column},id)>($1::text::timestamptz,$2::uuid) AND ({column},id)<=($3::text::timestamptz,$4::uuid)
        ORDER BY {column},id LIMIT $5"))).bind(after).bind(id).bind(&upper.0).bind(&upper.1).bind(limit).fetch_all(pool).await?;
    let short = page.len() < limit as usize;
    let mut count = 0;
    let mut error = None;
    for (at, id, scope) in page {
        pass.after = Some((at, id.clone()));
        match release(pool, store, &scope, &id, Some(age), spill).await {
            Ok(released) => count += usize::from(released),
            Err(e) => {
                error.get_or_insert(e);
            }
        }
    }
    if short || pass.after == pass.upper {
        *pass = AnchorPass::default();
    }
    error.map_or(Ok(count), Err)
}

pub async fn purge_due(pool: &PgPool, store: &Store, limit: i64) -> Result<usize, Error> {
    batch(limit)?;
    let Some(pin) = store.prepare(pool, false).await? else {
        return Ok(0);
    };
    let anchors = sweep_anchors(pool, store, &pin, limit, true, None)
        .await
        .map(|_| ());
    let mut pass = store.purge_pass.lock().await;
    const DUE: &str = "FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr
        ON sr.scope_id=r.scope_id AND sr.id=r.reservation_id
        WHERE NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL
        AND (r.state='purging' OR (r.state='retained' AND r.purge_after<=statement_timestamp()))";
    const KEY: &str = "coalesce(r.purge_after,'-infinity'::timestamptz)";
    if pass.upper.is_none() {
        pass.upper = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {KEY}::text,r.id::text {DUE} ORDER BY {KEY} DESC,r.id DESC LIMIT 1"
        )))
        .fetch_optional(pool)
        .await?;
    }
    let Some(upper) = &pass.upper else {
        return anchors.map(|()| 0);
    };
    let page = sqlx::query_as::<_, (String,String,String,String,String)>(sqlx::AssertSqlSafe(format!(
        "SELECT {KEY}::text,r.id::text,r.scope_id::text,r.reservation_id::text,sr.payload_ino::text {DUE}
         AND ($1::text::timestamptz IS NULL OR ({KEY},r.id)>($1::text::timestamptz,$2::uuid))
         AND ({KEY},r.id)<=($3::text::timestamptz,$4::uuid) ORDER BY {KEY},r.id LIMIT $5"
    ))).bind(pass.after.as_ref().map(|k| &k.0)).bind(pass.after.as_ref().map(|k| &k.1))
       .bind(&upper.0).bind(&upper.1).bind(limit).fetch_all(pool).await?;
    let last = page.last().map(|(t, id, ..)| (t.clone(), id.clone()));
    let finished = page.len() < limit as usize || last == pass.upper;
    let pin = pin.as_str();
    let count = sweep_items(page, |(_, id, scope, res, ino)| async move {
        purge_one(
            pool,
            store,
            pin,
            &scope,
            &id,
            &res,
            ino.parse().map_err(|_| Error::Io)?,
            None,
        )
        .await
    })
    .await;
    if finished {
        *pass = AnchorPass::default();
    } else {
        pass.after = last;
    }
    anchors?;
    count
}

/// Restore replay (ADR 0041): finishes, through the same stages, every revision named by a
/// journal record that is not yet purged while holding the active restore volume-phase lease.
/// Replay moved each to `purging`, so no reference or deadline is rechecked; one without a
/// verified payload binding stays and keeps the gate shut.
pub async fn purge_journaled(
    pool: &PgPool,
    store: &Store,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<usize, Error> {
    let Some(pin) = store.prepare(pool, false).await? else {
        return Err(Error::Io);
    };
    let pin = pin.as_str();
    let phase = Some((restore_run_id, claim_token));
    let mut count = 0usize;
    let mut after_seq: i64 = 0;
    loop {
        renew_volume_phase(pool, restore_run_id, claim_token).await?;
        let page = sqlx::query_as::<_, (i64, String, String, String, String)>(
            "SELECT j.journal_seq, r.id::text, r.scope_id::text, r.reservation_id::text, sr.payload_ino::text
               FROM openmettle.deletion_journal j
               JOIN openmettle.artifact_revisions r ON r.scope_id = j.scope_id AND r.id = j.entity_id
               JOIN openmettle.storage_reservations sr ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id
              WHERE j.event_kind = 'artifact_revision.purged'
                AND r.state = 'purging'
                AND sr.payload_ino IS NOT NULL
                AND j.journal_seq > $1
              ORDER BY j.journal_seq
              LIMIT 100",
        )
        .bind(after_seq)
        .fetch_all(pool)
        .await?;
        if page.is_empty() {
            break;
        }
        if let Some((seq, ..)) = page.last() {
            after_seq = *seq;
        }
        count += sweep_items(page, |(_, id, scope, res, ino)| async move {
            purge_one(
                pool,
                store,
                pin,
                &scope,
                &id,
                &res,
                ino.parse().map_err(|_| Error::Io)?,
                phase,
            )
            .await
        })
        .await?;
    }
    loop {
        if sweep_anchors(pool, store, pin, 100, true, phase).await? {
            break;
        }
    }
    Ok(count)
}

/// Restore replay (ADR 0041): no upload writer survives a restore (including an in-place snapshot
/// restore where `storage rebind` did not run). Under the active restore volume-phase lease, for
/// every `state = 'reserved'` reservation:
/// - If unquarantined, bound (`payload_ino IS NOT NULL`), and `reclaim_state IN ('none',
///   'claiming', 'truncated')`: acquire `LOCK_EX` on a present owned name, verify inode and link
///   count (`nlink` must equal the reservation's own names, refusing foreign hard links before any
///   truncation), then hold ONE `WriteTransaction` (`storage_reservations FOR UPDATE ->
///   restore_reconciliation_gate FOR SHARE -> storage_volume_control FOR SHARE`) continuously
///   across truncation, unconditional `file.sync_all()`, link/unlink/anchor cleanup, directory
///   `fsync`s, and the reservation state update.
/// - Then verify that NO `state = 'reserved'` reservation (including quarantined or unbound rows)
///   still has `revisions/<id>` on disk or non-zero bytes in `staging/<id>` or `.reclaim.<id>`,
///   and unconditionally `fsync` both `revisions` and `staging` before returning.
pub async fn scrub_unsettled_on_restore(
    pool: &PgPool,
    store: &Store,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<usize, Error> {
    let Some(pin) = store.prepare(pool, false).await? else {
        return Err(Error::Io);
    };
    renew_volume_phase(pool, restore_run_id, claim_token).await?;
    let v = &store.volume;
    let mut scrubbed = 0usize;
    let mut cursor: Option<String> = None;
    loop {
        renew_volume_phase(pool, restore_run_id, claim_token).await?;
        let page = sqlx::query_as::<_, (String, bool, String, Option<String>, bool)>(
            "SELECT id::text, adoption_unverified, reclaim_state, payload_ino::text, publish_pending
               FROM openmettle.storage_reservations
              WHERE state = 'reserved' AND ($1::uuid IS NULL OR id > $1::uuid)
              ORDER BY id
              LIMIT 100",
        )
        .bind(&cursor)
        .fetch_all(pool)
        .await?;
        if page.is_empty() {
            break;
        }
        for (id, quarantined, reclaim_state, payload_ino, publish_pending) in page {
            cursor = Some(id.clone());
            renew_volume_phase(pool, restore_run_id, claim_token).await?;
            let bound = parse_ino(payload_ino)?;
            v.verify(&pin)?;
            let reclaim_name = format!(".reclaim.{id}");
            let purge_name = format!(".purge.{id}");
            let s_stat = v.stat(&v.staging, &id)?;
            let r_stat = v.stat(&v.revisions, &id)?;
            let a_stat = v.stat(&v.staging, &reclaim_name)?;
            let p_stat = v.stat(&v.revisions, &purge_name)?;

            if !quarantined && matches!(reclaim_state.as_str(), "none" | "claiming" | "truncated") {
                if p_stat.is_some() {
                    return Err(Error::Io);
                }
                if let Some(ino) = bound {
                    if s_stat.is_some_and(|st| st.st_ino != ino)
                        || r_stat.is_some_and(|st| st.st_ino != ino)
                        || a_stat.is_some_and(|st| st.st_ino != ino || st.st_size != 0)
                    {
                        return Err(Error::Io);
                    }
                    let (dir, src) = match reclaim_state.as_str() {
                        "none" => {
                            if a_stat.is_some() {
                                return Err(Error::Io);
                            }
                            if s_stat.is_some() {
                                (&v.staging, id.as_str())
                            } else if r_stat.is_some() {
                                (&v.revisions, id.as_str())
                            } else {
                                return Err(Error::Missing);
                            }
                        }
                        "claiming" => {
                            if s_stat.is_some() {
                                (&v.staging, id.as_str())
                            } else if a_stat.is_some() {
                                (&v.staging, reclaim_name.as_str())
                            } else if r_stat.is_some() {
                                (&v.revisions, id.as_str())
                            } else {
                                return Err(Error::Missing);
                            }
                        }
                        "truncated" => {
                            if a_stat.is_none() || s_stat.is_some() || r_stat.is_some() {
                                return Err(Error::Io);
                            }
                            (&v.staging, reclaim_name.as_str())
                        }
                        _ => unreachable!(),
                    };
                    let file = lock_file(v, dir, src, ino, reclaim_state == "truncated")?;
                    v.verify(&pin)?;
                    let s_now = v.stat(&v.staging, &id)?;
                    let r_now = v.stat(&v.revisions, &id)?;
                    let a_now = v.stat(&v.staging, &reclaim_name)?;
                    if s_now.is_some_and(|st| st.st_ino != ino)
                        || r_now.is_some_and(|st| st.st_ino != ino)
                        || a_now.is_some_and(|st| st.st_ino != ino || st.st_size != 0)
                        || (reclaim_state == "none" && a_now.is_some())
                        || (reclaim_state == "truncated"
                            && (a_now.is_none() || s_now.is_some() || r_now.is_some()))
                    {
                        return Err(Error::Io);
                    }
                    let own = u64::from(s_now.is_some())
                        + u64::from(r_now.is_some())
                        + u64::from(a_now.is_some());
                    let meta = file.metadata()?;
                    if meta.nlink() != own {
                        return Err(Error::Io);
                    }

                    // Hold storage_reservations FOR UPDATE -> restore_reconciliation_gate FOR SHARE
                    // -> storage_volume_control FOR SHARE continuously across every filesystem
                    // mutation and durability sync so no concurrent rebind/adopt/gate-open can
                    // race with truncation or unlinking.
                    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
                    set_fs_tx_idle_timeout(&mut tx).await?;
                    let eligible = sqlx::query(
                        "SELECT FROM openmettle.storage_reservations
                          WHERE id = $1::uuid AND state = 'reserved'
                            AND NOT adoption_unverified AND reclaim_state = $2
                            AND payload_ino = $3::text::numeric
                            FOR UPDATE",
                    )
                    .bind(&id)
                    .bind(&reclaim_state)
                    .bind(ino.to_string())
                    .fetch_optional(tx.connection()?)
                    .await?;
                    if eligible.is_none() {
                        return Err(Error::Io);
                    }
                    assert_volume_phase(&mut tx, restore_run_id, claim_token).await?;
                    let fence_deadline = Instant::now() + FS_FENCE_WINDOW;
                    lock_pin(&mut tx, &pin).await?;
                    check_fence(fence_deadline)?;

                    v.verify(&pin)?;
                    v.matches(&file, dir, src, ino)?;
                    match reclaim_state.as_str() {
                        "none" => {
                            let mut mutated = false;
                            if meta.len() != 0 {
                                check_fence(fence_deadline)?;
                                file.set_len(0)?;
                                mutated = true;
                            }
                            file.sync_all()?;
                            if s_now.is_none() {
                                check_fence(fence_deadline)?;
                                at::linkat(
                                    &v.revisions,
                                    id.as_str(),
                                    &v.staging,
                                    id.as_str(),
                                    AtFlags::empty(),
                                )?;
                                if v.inode(&v.staging, &id)? != Some(ino) {
                                    return Err(Error::Io);
                                }
                                mutated = true;
                            }
                            // Unconditionally sync `staging` strictly BEFORE unlinking
                            // `revisions/<id>` (even on retries where `staging/<id>` already
                            // existed) so the surviving staged entry is durable first.
                            at::fsync(&v.staging)?;
                            if r_now.is_some() {
                                v.unlink_before(&v.revisions, &id, ino, fence_deadline)?;
                                mutated = true;
                            }
                            at::fsync(&v.revisions)?;
                            if publish_pending || mutated {
                                let updated = sqlx::query(
                                    "UPDATE openmettle.storage_reservations
                                        SET publish_pending = false
                                      WHERE id = $1::uuid AND state = 'reserved'
                                        AND NOT adoption_unverified AND reclaim_state = 'none'
                                        AND payload_ino = $2::text::numeric",
                                )
                                .bind(&id)
                                .bind(ino.to_string())
                                .execute(tx.connection()?)
                                .await?
                                .rows_affected();
                                if updated != 1 {
                                    return Err(Error::Io);
                                }
                                scrubbed += 1;
                            }
                        }
                        "claiming" => {
                            if meta.len() != 0 {
                                check_fence(fence_deadline)?;
                                file.set_len(0)?;
                            }
                            file.sync_all()?;
                            anchor(
                                v,
                                dir,
                                src,
                                &v.staging,
                                &reclaim_name,
                                ino,
                                Some(fence_deadline),
                            )?;
                            if r_now.is_some() {
                                v.unlink_before(&v.revisions, &id, ino, fence_deadline)?;
                            }
                            if s_now.is_some() {
                                v.unlink_before(&v.staging, &id, ino, fence_deadline)?;
                            }
                            at::fsync(&v.revisions)?;
                            at::fsync(&v.staging)?;
                            let updated = sqlx::query(
                                "UPDATE openmettle.storage_reservations
                                    SET publish_pending = false,
                                        reclaim_state = 'truncated',
                                        reclaim_lease_until = clock_timestamp()
                                  WHERE id = $1::uuid AND state = 'reserved'
                                    AND NOT adoption_unverified AND reclaim_state = 'claiming'
                                    AND payload_ino = $2::text::numeric",
                            )
                            .bind(&id)
                            .bind(ino.to_string())
                            .execute(tx.connection()?)
                            .await?
                            .rows_affected();
                            if updated != 1 {
                                return Err(Error::Io);
                            }
                            scrubbed += 1;
                        }
                        "truncated" => {
                            file.sync_all()?;
                            at::fsync(&v.revisions)?;
                            at::fsync(&v.staging)?;
                            let updated = sqlx::query(
                                "UPDATE openmettle.storage_reservations
                                    SET publish_pending = false,
                                        reclaim_lease_until = clock_timestamp()
                                  WHERE id = $1::uuid AND state = 'reserved'
                                    AND NOT adoption_unverified AND reclaim_state = 'truncated'
                                    AND payload_ino = $2::text::numeric",
                            )
                            .bind(&id)
                            .bind(ino.to_string())
                            .execute(tx.connection()?)
                            .await?
                            .rows_affected();
                            if updated != 1 {
                                return Err(Error::Io);
                            }
                            if publish_pending {
                                scrubbed += 1;
                            }
                        }
                        _ => unreachable!(),
                    }
                    tx.commit().await?;
                    drop(file);
                }
            }

            // Fail closed if ANY reserved row (including quarantined, unbound or mid-reclaim rows)
            // still has a published name or non-zero staged/anchor bytes on disk.
            let r_after = v.stat(&v.revisions, &id)?;
            let s_after = v.stat(&v.staging, &id)?;
            let a_after = v.stat(&v.staging, &reclaim_name)?;
            if r_after.is_some()
                || s_after.is_some_and(|st| st.st_size != 0)
                || a_after.is_some_and(|st| st.st_size != 0)
            {
                return Err(Error::Io);
            }
        }
    }
    renew_volume_phase(pool, restore_run_id, claim_token).await?;
    v.verify(&pin)?;
    at::fsync(&v.revisions)?;
    at::fsync(&v.staging)?;
    Ok(scrubbed)
}

/// Remove any leftover reservation files on disk for revisions already marked `'lost'` (for
/// example after replaying an `artifact_revision.lost` journal entry onto an older backup whose
/// artifact volume still holds the old bytes). Fenced by `restore_assert_volume_phase` and
/// `storage_volume_control FOR SHARE`; refuses foreign hard links and active locks.
pub async fn cleanup_lost_on_restore(
    pool: &PgPool,
    store: &Store,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<u64, Error> {
    let Some(pin) = store.prepare(pool, false).await? else {
        return Err(Error::Io);
    };
    let v = &store.volume;
    v.verify(&pin)?;

    let mut cleaned = 0u64;
    let mut cursor: Option<String> = None;
    loop {
        renew_volume_phase(pool, restore_run_id, claim_token).await?;
        let batch: Vec<(String, String, String, bool)> = sqlx::query_as(
            "SELECT s.id::text, s.scope_id::text, r.id::text, s.payload_ino IS NOT NULL
               FROM openmettle.storage_reservations s
               JOIN openmettle.artifact_revisions r
                 ON r.scope_id = s.scope_id AND r.reservation_id = s.id
              WHERE s.state = 'settled'
                AND r.state = 'lost'
                AND ($1::uuid IS NULL OR s.id > $1::uuid)
              ORDER BY s.id ASC
              LIMIT $2",
        )
        .bind(&cursor)
        .bind(MAX_BATCH)
        .fetch_all(pool)
        .await?;
        if batch.is_empty() {
            break;
        }
        for (res_id, scope_id, rev_id, has_ino) in batch {
            cursor = Some(res_id.clone());
            let names = super::rebind::reservation_names(&res_id);
            let entries = super::rebind::stat_reservation(v, &names)
                .map_err(|_| Error::Io)?
                .ok_or(Error::Io)?;
            let has_files = entries.iter().any(Option::is_some);
            if !has_files && !has_ino {
                continue;
            }
            let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
            set_fs_tx_idle_timeout(&mut tx).await?;
            let locked_row: Option<(bool,)> = sqlx::query_as(
                "SELECT s.payload_ino IS NOT NULL
                   FROM openmettle.storage_reservations s
                  WHERE s.scope_id = $1::uuid AND s.id = $2::uuid AND s.state = 'settled'
                    FOR UPDATE",
            )
            .bind(&scope_id)
            .bind(&res_id)
            .fetch_optional(tx.connection()?)
            .await?;
            let Some((still_has_ino,)) = locked_row else {
                return Err(Error::Io);
            };
            let rev_lost: Option<bool> = sqlx::query_scalar(
                "SELECT state = 'lost'
                   FROM openmettle.artifact_revisions
                  WHERE scope_id = $1::uuid AND id = $2::uuid
                    FOR UPDATE",
            )
            .bind(&scope_id)
            .bind(&rev_id)
            .fetch_optional(tx.connection()?)
            .await?;
            if rev_lost != Some(true) {
                return Err(Error::Io);
            }
            assert_volume_phase(&mut tx, restore_run_id, claim_token).await?;
            let fence_deadline = Instant::now() + FS_FENCE_WINDOW;
            lock_pin(&mut tx, &pin).await?;
            check_fence(fence_deadline)?;
            v.verify(&pin)?;

            let entries = super::rebind::stat_reservation(v, &names)
                .map_err(|_| Error::Io)?
                .ok_or(Error::Io)?;
            let locked_files = super::rebind::lock_reservation_files(v, &names, &entries, true)
                .map_err(|err| {
                    if err.0 == "reservation in use" {
                        Error::InProgress
                    } else {
                        Error::Io
                    }
                })?;
            let unlinked = if entries.iter().any(Option::is_some) {
                super::rebind::unlink_reservation_files(v, &names, &entries, Some(fence_deadline))
                    .map_err(|_| Error::Io)?
            } else {
                0
            };
            drop(locked_files);
            if still_has_ino {
                sqlx::query(
                    "UPDATE openmettle.storage_reservations
                        SET payload_ino = NULL, adoption_unverified = false
                      WHERE scope_id = $1::uuid AND id = $2::uuid",
                )
                .bind(&scope_id)
                .bind(&res_id)
                .execute(tx.connection()?)
                .await?;
            }
            tx.commit().await?;
            if unlinked > 0 || still_has_ino {
                cleaned += 1;
            }
        }
    }
    renew_volume_phase(pool, restore_run_id, claim_token).await?;
    v.verify(&pin)?;
    at::fsync(&v.revisions)?;
    at::fsync(&v.staging)?;
    Ok(cleaned)
}
