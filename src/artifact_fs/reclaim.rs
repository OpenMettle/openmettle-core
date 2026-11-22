//! A claim fences stale workers. A durable hard link pins the payload inode until the SQL
//! credit commits. Detached anchors are retried independently of normal expiry scans.
use super::*;
use std::fs::File;

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
) -> Result<(), Error> {
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
        let ok=sqlx::query("SELECT FROM openmettle.runs WHERE id=$1::uuid AND state IN ('succeeded','failed','interrupted','cancelled')
            AND NOT EXISTS (SELECT FROM openmettle.operations WHERE run_id=$1::uuid AND outcome IN ('intent','outcome_unknown'))
            FOR NO KEY UPDATE SKIP LOCKED").bind(run).fetch_optional(claim.connection()?).await?;
        if ok.is_none() {
            return Ok(false);
        }
    }
    let row=sqlx::query("SELECT reclaim_state,payload_ino::text,gen_random_uuid()::text AS token
        FROM openmettle.storage_reservations WHERE scope_id=$1::uuid AND id=$2::uuid AND state='reserved'
        AND NOT adoption_unverified AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')
        AND (reclaim_state='none' OR reclaim_lease_until<=clock_timestamp())
        AND ($3::bigint IS NULL OR coalesce(lease_expires_at, greatest(created_at,
            (SELECT coalesce(r.execution_expires_at,r.queue_expires_at,r.created_at) FROM openmettle.runs r WHERE r.id=run_id))
            + $3 * interval '1 millisecond')<=clock_timestamp())
        FOR UPDATE SKIP LOCKED").bind(scope).bind(id).bind(age).fetch_optional(claim.connection()?).await?;
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
            v.matches(&file, dir, src, ino)?;
            file.set_len(0)?;
            file.sync_all()?;
            anchor(v, dir, src, &v.staging, &name, ino)?;
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
        anchor(v, &v.staging, id, &v.staging, &name, ino)?;
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
        detach(pool, store, &pin, id, id, ino, false).await?;
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

async fn detach(
    pool: &PgPool,
    store: &Store,
    pin: &str,
    id: &str,
    reservation: &str,
    ino: u64,
    purge: bool,
) -> Result<(), Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
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
    lock_pin(&mut tx, pin).await?;
    let v = &store.volume;
    v.verify(pin)?;
    let (dir, name) = if purge {
        (&v.revisions, format!(".purge.{reservation}"))
    } else {
        (&v.staging, format!(".reclaim.{reservation}"))
    };
    if v.inode(dir, &name)?.is_some() {
        let _guard = lock_file(v, dir, &name, ino, true)?;
        v.unlink(dir, &name, ino)?;
    }
    at::fsync(dir)?;
    sqlx::query(clear)
        .bind(id)
        .execute(tx.connection()?)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn purge_one(
    pool: &PgPool,
    store: &Store,
    pin: &str,
    scope: &str,
    id: &str,
    reservation: &str,
    ino: u64,
) -> Result<bool, Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    store.volume.verify(pin)?;
    match storage::begin_purge(&mut tx, scope, id).await {
        Ok(()) => {}
        Err(runs::Error::NotEligible) => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    lock_pin(&mut tx, pin).await?;
    tx.commit().await?;
    let v = &store.volume;
    v.verify(pin)?;
    let name = format!(".purge.{reservation}");
    let a = v.inode(&v.revisions, &name)?;
    let r = v.inode(&v.revisions, reservation)?;
    let src = if a == Some(ino) {
        name.as_str()
    } else if a.is_none() && r == Some(ino) {
        reservation
    } else {
        return Err(Error::Io);
    };
    let f = lock_file(v, &v.revisions, src, ino, false)?;
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let live=sqlx::query("SELECT FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr
        ON sr.id=r.reservation_id AND sr.scope_id=r.scope_id WHERE r.id=$1::uuid AND r.state='purging'
        AND NOT sr.adoption_unverified AND sr.payload_ino=$2::text::numeric FOR UPDATE OF r")
        .bind(id).bind(ino.to_string()).fetch_optional(tx.connection()?).await?;
    if live.is_none() {
        return Ok(false);
    }
    lock_pin(&mut tx, pin).await?;
    tx.commit().await?;
    v.verify(pin)?;
    v.matches(&f, &v.revisions, src, ino)?;
    f.set_len(0)?;
    f.sync_all()?;
    anchor(v, &v.revisions, src, &v.revisions, &name, ino)?;
    if r == Some(ino) {
        v.unlink(&v.revisions, reservation, ino)?;
    }
    if v.inode(&v.staging, reservation)? == Some(ino) {
        v.unlink(&v.staging, reservation, ino)?;
    }
    at::fsync(&v.revisions)?;
    at::fsync(&v.staging)?;
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    storage::confirm_purge(&mut tx, scope, id).await?;
    tx.commit().await?;
    drop(f);
    detach(pool, store, pin, id, reservation, ino, true).await?;
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
) -> Result<(), Error> {
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
        return Ok(());
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
        if let Err(e) = detach(
            pool,
            store,
            pin,
            &id,
            &res,
            ino.parse().map_err(|_| Error::Io)?,
            purge,
        )
        .await
        {
            error = Some(e);
        }
        pass.after = Some((ts, id));
    }
    if short || pass.after == pass.upper {
        *pass = AnchorPass::default();
    }
    error.map_or(Ok(()), Err)
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
    let anchors = sweep_anchors(pool, store, &pin, limit, false).await;
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

// Keep four separate cursors because the partial indexes have different keys and predicates.
async fn expiry_page(
    pool: &PgPool,
    store: &Store,
    partition: usize,
    age: i64,
    limit: i64,
) -> Result<usize, Error> {
    let legacy = partition % 2 == 1;
    let (column, expiry) = if legacy {
        ("created_at", "lease_expires_at IS NULL")
    } else {
        ("lease_expires_at", "lease_expires_at IS NOT NULL")
    };
    let run = if partition < 2 {
        "run_id IS NULL"
    } else {
        "run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')"
    };
    let mut pass = store.expiry_pass[partition].lock().await;
    if pass.upper.is_none() {
        let cutoff: String = sqlx::query_scalar(
            "SELECT (clock_timestamp()-$1::bigint*interval '1 millisecond')::text",
        )
        .bind(if legacy { age } else { 0 })
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
        match release(pool, store, &scope, &id, Some(age)).await {
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
    let anchors = sweep_anchors(pool, store, &pin, limit, true).await;
    let page=sqlx::query_as::<_,(String,String,String,String)>("SELECT r.scope_id::text,r.id::text,r.reservation_id::text,sr.payload_ino::text
        FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations sr ON sr.scope_id=r.scope_id AND sr.id=r.reservation_id
        WHERE NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL AND ((r.state='retained' AND r.purge_after<=now()) OR r.state='purging')
        ORDER BY r.purge_after,r.id LIMIT $1").bind(limit).fetch_all(pool).await?;
    let pin = pin.as_str();
    let count = sweep_items(page, |(scope, id, res, ino)| async move {
        purge_one(
            pool,
            store,
            pin,
            &scope,
            &id,
            &res,
            ino.parse().map_err(|_| Error::Io)?,
        )
        .await
    })
    .await?;
    anchors?;
    Ok(count)
}
