//! Offline verification of an existing artifact volume before pinning its identity.
use super::volume::Volume;
use crate::runs::is_canonical_uuid;
use rustix::fs::{self as at, AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row, postgres::PgRow};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};

pub struct Options<'a> {
    pub root: &'a Path,
    pub replace: Option<&'a str>,
    pub expected_fs: Option<&'a str>,
    pub expected_directory: Option<(u64, u64)>,
    pub confirm_absent: bool,
}

#[derive(Debug)]
pub struct Failure(pub &'static str);
impl From<sqlx::Error> for Failure {
    fn from(_: sqlx::Error) -> Self {
        Self("database operation failed")
    }
}
impl From<io::Error> for Failure {
    fn from(_: io::Error) -> Self {
        Self("volume verification failed")
    }
}
impl From<rustix::io::Errno> for Failure {
    fn from(_: rustix::io::Errno) -> Self {
        Self("volume operation failed")
    }
}

// PostgreSQL uuid_send returns the 16-byte, network-order UUID.
type Uuid = [u8; 16];

const INVENTORY: &str =
    "SELECT s.id::text,pg_catalog.uuid_send(s.id) AS reservation_uuid,s.scope_id::text,s.state,s.reclaim_state,s.payload_ino::text,s.max_bytes,
    r.id::text AS revision,r.state AS revision_state,r.purge_stage,r.size_bytes,r.content_digest
    FROM openmettle.storage_reservations s LEFT JOIN openmettle.artifact_revisions r
    ON r.scope_id=s.scope_id AND r.reservation_id=s.id ORDER BY s.id";

#[derive(Default)]
struct Evidence {
    owners: HashMap<(u64, u64), String>,
    files: Vec<File>,
    verified: HashMap<String, u64>,
    quarantine: HashSet<String>,
    clear_reclaim: Vec<String>,
    clear_purge: Vec<String>,
    finish_purge: Vec<(String, String, i64)>,
    digests: usize,
    survivors: usize,
    mismatch: Option<&'static str>,
}
impl Evidence {
    fn owner(&mut self, id: &str, dev: u64, ino: u64) -> Result<(), Failure> {
        if let Some(other) = self.owners.insert((dev, ino), id.to_owned())
            && other != id
        {
            self.quarantine.insert(other);
            self.quarantine.insert(id.into());
            return Err(Failure("cross_reservation_inode_alias"));
        }
        Ok(())
    }
    fn inspect_all(
        &mut self,
        v: &Volume,
        rows: &[PgRow],
        locks: &mut HashMap<(u64, u64), Uuid>,
    ) -> Result<(), Failure> {
        for row in rows {
            if let Err(error) = self.inspect(v, row, locks) {
                if error.0 == "reservation in use" {
                    return Err(error);
                }
                if row.try_get::<&str, _>("state")? == "reserved" {
                    self.quarantine.insert(row.try_get("id")?);
                }
                if error.0 == "cross_reservation_inode_alias" {
                    self.mismatch = Some(error.0);
                } else {
                    self.mismatch.get_or_insert(error.0);
                }
            }
        }
        Ok(())
    }
    fn inspect(
        &mut self,
        v: &Volume,
        row: &PgRow,
        locks: &mut HashMap<(u64, u64), Uuid>,
    ) -> Result<(), Failure> {
        match self.inspect_entries(v, row, locks) {
            Err(Failure("entry moved")) => self.inspect_entries(v, row, locks),
            result => result,
        }
    }

    fn inspect_entries(
        &mut self,
        v: &Volume,
        row: &PgRow,
        locks: &mut HashMap<(u64, u64), Uuid>,
    ) -> Result<(), Failure> {
        let id: &str = row.try_get("id")?;
        let uuid: Uuid = row
            .try_get::<&[u8], _>("reservation_uuid")?
            .try_into()
            .map_err(|_| Failure("invalid reservation UUID"))?;
        let state: &str = row.try_get("state")?;
        let reclaim: &str = row.try_get("reclaim_state")?;
        let rev: Option<&str> = row.try_get("revision_state")?;
        let purge: Option<&str> = row.try_get("purge_stage")?;
        let bound: Option<u64> = row
            .try_get::<Option<&str>, _>("payload_ino")?
            .map(str::parse)
            .transpose()
            .map_err(|_| Failure("invalid inode"))?;
        if state == "released" && reclaim == "none"
            || rev == Some("purged") && purge == Some("none")
        {
            return Ok(());
        }
        let reclaim_name = format!(".reclaim.{id}");
        let purge_name = format!(".purge.{id}");
        // Retired identities stop participating as soon as the last anchor is detached.
        if state == "released" && v.inode(&v.staging, &reclaim_name)?.is_none() {
            self.clear_reclaim.push(id.into());
            return Ok(());
        }
        if rev == Some("purged") && v.inode(&v.revisions, &purge_name)?.is_none() {
            self.clear_purge.push(id.into());
            return Ok(());
        }
        let mut problem = None;
        let mut probe = |dir: &File, name: &str| match v.inode(dir, name) {
            Ok(value) => value,
            Err(_) => {
                problem = Some(Failure("invalid volume entry"));
                None
            }
        };
        let s = probe(&v.staging, id);
        let mut a = probe(&v.staging, &reclaim_name);
        let mut r = probe(&v.revisions, id);
        let p = probe(&v.revisions, &purge_name);
        if state == "reserved" && s.is_none() && a.is_none() && r.is_none() {
            a = probe(&v.staging, &reclaim_name);
            r = probe(&v.revisions, id);
        }
        let seen = [
            (s, &v.staging, id),
            (a, &v.staging, reclaim_name.as_str()),
            (r, &v.revisions, id),
            (p, &v.revisions, purge_name.as_str()),
        ];
        let mut identity = bound;
        let mut present = false;
        let mut alias = false;
        if let Some(ino) = bound {
            alias = self.owner(id, v.dev, ino).is_err();
        }
        for (ino, dir, name) in seen {
            let Some(ino) = ino else { continue };
            present = true;
            alias |= self.owner(id, v.dev, ino).is_err();
            if identity.is_some_and(|known| known != ino) {
                problem.get_or_insert(Failure(
                    if state == "settled" && name == id && s.is_some() && s != r {
                        "foreign_staging_collision"
                    } else {
                        "intra_reservation_inode_mismatch"
                    },
                ));
            }
            identity.get_or_insert(ino);
            if state != "reserved" || bound.is_some_and(|known| known != ino) {
                continue;
            }
            let f = match v.regular(dir, name, true) {
                Ok(f) => f,
                Err(_) if name == id && v.inode(dir, name)?.is_none() => {
                    return Err(Failure("entry moved"));
                }
                Err(_) => {
                    problem.get_or_insert(Failure("invalid volume entry"));
                    continue;
                }
            };
            let held = locks.get(&(v.dev, ino));
            if held.is_some_and(|owner| *owner != uuid) {
                alias = true;
                continue;
            }
            if held.is_none() {
                match f.try_lock() {
                    Ok(()) => {}
                    Err(std::fs::TryLockError::WouldBlock) => {
                        return Err(Failure("reservation in use"));
                    }
                    Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
                }
            }
            if v.matches(&f, dir, name, ino).is_err() {
                if name == id && v.inode(dir, name)?.is_none() {
                    return Err(Failure("entry moved"));
                }
                problem.get_or_insert(Failure("size or identity mismatch"));
                continue;
            }
            if held.is_none() {
                locks.insert((v.dev, ino), uuid);
                self.files.push(f.try_clone()?);
            }
            if f.metadata()?.len() > row.try_get::<i64, _>("max_bytes")? as u64 {
                problem.get_or_insert(Failure("size or identity mismatch"));
            }
        }
        if alias {
            return Err(Failure("cross_reservation_inode_alias"));
        }
        if let Some(problem) = problem {
            return Err(problem);
        }
        self.survivors += usize::from(present);
        if a.is_some() && !matches!(reclaim, "claiming" | "truncated" | "anchor_pending_unlink") {
            return Err(Failure("unexpected reclaim anchor"));
        }
        if p.is_some() && !matches!(rev, Some("purging" | "purged")) {
            return Err(Failure("unexpected purge anchor"));
        }
        for (ino, dir, name) in [
            (a, &v.staging, &reclaim_name),
            (p, &v.revisions, &purge_name),
        ] {
            if ino.is_some() && v.regular(dir, name, false)?.metadata()?.len() != 0 {
                return Err(Failure("anchor is not empty"));
            }
        }
        if state == "reserved" {
            if reclaim == "truncated" && (a.is_none() || r.is_some() || s.is_some()) {
                return Err(Failure("truncated_visible_name_present"));
            }
            if let Some(ino) = identity.filter(|_| present) {
                self.verified.insert(id.into(), ino);
            } else {
                self.quarantine.insert(id.into());
            }
        } else if let Some("active" | "retained" | "purging") = rev {
            let size: i64 = row.try_get("size_bytes")?;
            if let Some(ino) = r {
                let mut f = v.regular(&v.revisions, id, false)?;
                let m = f.metadata()?;
                if rev != Some("purging") || m.len() != 0 || bound.is_none() {
                    let mut h = Sha256::new();
                    let mut buf = [0; 65536];
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        h.update(&buf[..n]);
                    }
                    if m.len() != size as u64
                        || h.finalize().as_slice() != row.try_get::<&[u8], _>("content_digest")?
                    {
                        return Err(Failure("size_or_digest_mismatch"));
                    }
                    self.digests += 1;
                }
                v.matches(&f, &v.revisions, id, ino)?;
                self.verified.insert(id.into(), ino);
            } else if rev == Some("purging") && bound.is_none() && s.is_some() {
                return Err(Failure("ambiguous_legacy_purging_staging_survivor"));
            } else if rev == Some("purging") && bound.is_none() && !present {
                self.finish_purge
                    .push((row.try_get("scope_id")?, row.try_get("revision")?, size));
            } else if !(rev == Some("purging") && bound.is_some() && p == bound) {
                return Err(Failure("missing revision"));
            }
        }
        Ok(())
    }
}

fn qualify(v: &Volume, id: &str) -> Result<(), Failure> {
    let name = format!(".openmettle-volume-id.tmp.probe.{id}");
    let f = File::from(at::openat(
        &v.staging,
        name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?);
    let result = (|| {
        f.try_lock()
            .map_err(|_| Failure("filesystem lock unavailable"))?;
        f.sync_all()?;
        at::linkat(
            &v.staging,
            name.as_str(),
            &v.revisions,
            name.as_str(),
            AtFlags::empty(),
        )?;
        let ok = at::linkat(
            &v.staging,
            name.as_str(),
            &v.revisions,
            name.as_str(),
            AtFlags::empty(),
        ) == Err(rustix::io::Errno::EXIST)
            && v.inode(&v.revisions, &name)? == Some(f.metadata()?.ino());
        at::fsync(&v.revisions)?;
        v.unlink(&v.revisions, &name, f.metadata()?.ino())?;
        if !ok {
            return Err(Failure("hard link qualification failed"));
        }
        Ok(())
    })();
    v.unlink(&v.staging, &name, f.metadata()?.ino())?;
    at::fsync(&v.staging)?;
    at::fsync(&v.revisions)?;
    result
}
fn independent_identity(v: &Volume, opts: &Options<'_>) -> bool {
    let Some(uuid) = opts.expected_fs.filter(|s| is_canonical_uuid(s)) else {
        return false;
    };
    let Ok(meta) = v.revisions.metadata() else {
        return false;
    };
    opts.expected_directory == Some((meta.dev(), meta.ino()))
        && std::fs::metadata(Path::new("/dev/disk/by-uuid").join(uuid))
            .is_ok_and(|m| m.file_type().is_block_device() && m.rdev() == v.dev)
}

pub async fn adopt(c: &mut PgConnection, opts: &Options<'_>) -> Result<(), Failure> {
    let v = Volume::open(opts.root, false)?;
    let (owner, run): (bool, String) =
        sqlx::query_as("SELECT current_user='openmettle_owner',gen_random_uuid()::text")
            .fetch_one(&mut *c)
            .await?;
    if !owner {
        return Err(Failure("owner login required"));
    }
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT volume_id::text FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(&mut *c)
    .await?;
    if let Some(id) = existing.as_deref() {
        v.verify(id)?;
    }
    qualify(&v, &run)?;
    let mut barrier = c.begin().await?;
    let (pin, prior): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT volume_id::text,adoption_run_id::text
        FROM openmettle.storage_volume_control WHERE id FOR UPDATE",
    )
    .fetch_one(&mut *barrier)
    .await?;
    if let Some(id) = &pin {
        v.verify(id)?;
    }
    if prior.as_deref() != opts.replace {
        return Err(Failure("adoption ownership mismatch"));
    }
    sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id=$1::uuid WHERE id")
        .bind(&run)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    let result = verify_and_pin(c, opts, &v, &run, pin.as_deref()).await;
    if result.is_err() {
        sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id=NULL WHERE id AND adoption_run_id=$1::uuid")
            .bind(&run).execute(c).await?;
    }
    result
}

async fn verify_and_pin(
    c: &mut PgConnection,
    opts: &Options<'_>,
    v: &Volume,
    run: &str,
    pin: Option<&str>,
) -> Result<(), Failure> {
    loop {
        let rows = sqlx::query(INVENTORY).fetch_all(&mut *c).await?;
        let identity = |row: &PgRow| {
            (
                row.get::<String, _>("id"),
                row.get::<Option<String>, _>("revision"),
                row.get::<String, _>("state"),
                row.get::<Option<String>, _>("revision_state"),
            )
        };
        let scanned: HashSet<_> = rows.iter().map(identity).collect();
        // The potentially long pre-scan has no SQL lock. Revalidate the locked snapshot below.
        let mut pre = Evidence::default();
        let mut held_candidate_locks: HashMap<(u64, u64), Uuid> = HashMap::new();
        pre.inspect_all(v, &rows, &mut held_candidate_locks)?;
        let mut tx = c.begin().await?;
        sqlx::query("SELECT id FROM openmettle.storage_reservations ORDER BY id FOR UPDATE")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT id FROM openmettle.artifact_revisions ORDER BY id FOR UPDATE")
            .execute(&mut *tx)
            .await?;
        let own:Option<bool>=sqlx::query_scalar("SELECT adoption_run_id=$1::uuid FROM openmettle.storage_volume_control WHERE id FOR UPDATE")
        .bind(run).fetch_one(&mut *tx).await?;
        if own != Some(true) {
            return Err(Failure("adoption ownership changed"));
        }
        sqlx::query(
            "SELECT scope_id FROM openmettle.storage_accounts ORDER BY scope_id FOR UPDATE",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT id FROM openmettle.storage_instance WHERE id FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
        v.recheck()?;
        if let Some(pin) = pin {
            v.verify(pin)?;
        }
        let rows = sqlx::query(INVENTORY).fetch_all(&mut *tx).await?;
        if rows.iter().any(|r| !scanned.contains(&identity(r))) {
            tx.rollback().await?;
            continue;
        }
        // Retain the pre-scan file descriptions and LOCK_EX through the Phase 3C commit.
        let mut evidence = Evidence {
            files: pre.files,
            mismatch: pre.mismatch,
            quarantine: if pre.mismatch.is_some() {
                pre.quarantine
            } else {
                HashSet::new()
            },
            ..Evidence::default()
        };
        evidence.inspect_all(v, &rows, &mut held_candidate_locks)?;
        if !rows.is_empty()
            && evidence.digests == 0
            && (!independent_identity(v, opts) || (evidence.survivors == 0 && !opts.confirm_absent))
        {
            evidence
                .mismatch
                .get_or_insert("independent volume evidence required");
        }
        if evidence.mismatch.is_none() || pin.is_some() {
            for id in &evidence.quarantine {
                sqlx::query("UPDATE openmettle.storage_reservations SET adoption_unverified=true,
                publish_pending=false,reclaim_state='none',reclaim_claim_token=NULL,reclaim_lease_until=NULL
                WHERE id=$1::uuid AND state='reserved'").bind(id).execute(&mut *tx).await?;
            }
        }
        if evidence.mismatch.is_none() {
            for (id, ino) in &evidence.verified {
                sqlx::query("UPDATE openmettle.storage_reservations SET adoption_unverified=false,
                reclaim_lease_until=CASE WHEN reclaim_state IN ('claiming','truncated') THEN clock_timestamp() END
                WHERE id=$1::uuid AND state='reserved'").bind(id).execute(&mut *tx).await?;
                sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$2::text::numeric
                WHERE id=$1::uuid AND payload_ino IS NULL AND NOT adoption_unverified")
                .bind(id).bind(ino.to_string()).execute(&mut *tx).await?;
            }
            for id in &evidence.clear_reclaim {
                sqlx::query(
                "UPDATE openmettle.storage_reservations SET reclaim_state='none' WHERE id=$1::uuid",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            }
            for id in &evidence.clear_purge {
                sqlx::query("UPDATE openmettle.artifact_revisions SET purge_stage='none' WHERE reservation_id=$1::uuid").bind(id).execute(&mut *tx).await?;
            }
            for (scope, rev, size) in &evidence.finish_purge {
                sqlx::query("UPDATE openmettle.artifact_revisions SET state='purged',purged_at=clock_timestamp() WHERE id=$1::uuid")
                .bind(rev).execute(&mut *tx).await?;
                sqlx::query("UPDATE openmettle.storage_accounts SET retained_bytes=retained_bytes-$2 WHERE scope_id=$1::uuid")
                .bind(scope).bind(size).execute(&mut *tx).await?;
                sqlx::query(
                "UPDATE openmettle.storage_instance SET retained_bytes=retained_bytes-$1 WHERE id",
            )
            .bind(size)
            .execute(&mut *tx)
            .await?;
            }
            v.remove_stale_temps()?;
            let id = match pin {
                Some(id) => id.to_owned(),
                None => v.publish_identity(run)?,
            };
            sqlx::query("UPDATE openmettle.storage_volume_control SET volume_id=$1::uuid,bootstrap_auto_pin_allowed=false WHERE id")
            .bind(id).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id=NULL WHERE id AND adoption_run_id=$1::uuid")
        .bind(run).execute(&mut *tx).await?;
        tx.commit().await?;
        return evidence.mismatch.map_or(Ok(()), |e| Err(Failure(e)));
    }
}
