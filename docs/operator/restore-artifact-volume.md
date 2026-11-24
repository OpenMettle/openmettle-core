# Restore the artifact volume

Use this procedure after restoring the artifact directory by file copy (`cp -a`, `tar`, restic or a similar tool) into a new volume, together with the PostgreSQL database from the same recovery point. It covers the artifact store only. The [database restore checklist](../../README.md#database-backup-restore-pre-worker-checklist) still applies, and step 3 of that checklist is this page.

A copy keeps every payload byte and the volume identity files, and gives every file a new inode number. The database pins each payload to its inode number ([ADR 0040](../adr/0040-transactional-quotas-and-reservation-reconciliation.md)). Until the volume is rebound, every read of an existing artifact fails, and reservation cleanup and purge fail. `openmettle-admin storage rebind` verifies the copied files against the ledger and records the new inode numbers.

## Before you start

- **Start nothing on the restored volume.** Keep every API and worker process stopped until step 3 has passed. Rebind takes a database barrier that makes artifact operations fail while it runs, but it cannot prove that nothing ran earlier.
- **Restore the database and the volume from the same recovery point.**
- **Use a copy that preserves hard links.** `cp -a`, GNU `tar` and restic do. `rsync` needs `-H`. Rebind reports a reservation whose names were split into separate files and does not repair it.
- **Use the owner login.** Supply `OPENMETTLE_ADMIN_DATABASE_URL` through the deployment secret mechanism, with the `openmettle_owner` login. Mount the restored tree readable and writable under the service's filesystem identity.
- The volume must already be pinned. A volume that was never adopted needs [`storage adopt`](storage-adoption-and-quota-upgrade.md), not this procedure.

## Procedure

1. Run rebind on the absolute artifact root, the directory that contains `staging` and `revisions`.

   ```sh
   openmettle-admin storage rebind "$ARTIFACT_ROOT"
   ```

2. Read the result. A complete run exits with status 0 and prints one line:

   ```text
   rebound 7, emptied 2, unchanged 0, quarantined 0, failed 0
   ```

   | Count | Meaning |
   | --- | --- |
   | `rebound` | Reservations now bound to the copied file. |
   | `emptied` | Unsettled uploads whose bytes were discarded (see below). |
   | `unchanged` | Reservations whose files already matched. |
   | `quarantined` | Reservations that were already quarantined. Rebind leaves them alone. |
   | `failed` | Reservations that did not verify. Each is listed with its reason. |

3. Run the filesystem drift check. It is the required post-restore check and must exit with status 0.

   ```sh
   openmettle-admin quota verify "$ARTIFACT_ROOT"
   ```

   The SQL function `openmettle.quota_verify_accounting_drift()` is not sufficient on its own. It compares no file and reports a copied volume as healthy.

4. Continue with the rest of the restore checklist, then start the API and worker.

Running rebind again, or running it on a volume that was not copied, verifies every settled payload again and writes nothing.

## What rebind accepts

- **Settled payloads** (active or retained revisions, and revisions claimed for purge whose bytes are still present): the new inode is accepted only when the file's size and SHA-256 equal the values recorded when the upload settled.
- **Unsettled uploads are emptied.** An upload that was in flight, or published but not settled, at the recovery point has no recorded size or hash, and no process survives a restore to finish it. Rebind truncates its file to zero bytes and binds the reservation to the empty file. The reservation stays reserved and charged, and the worker releases it under its normal rules. The backup still holds the discarded bytes. Nothing that was acknowledged to a client before the backup is affected, and no unsettled upload becomes an artifact.
- **Cleanup markers** (reclaim and purge anchors, payloads already truncated by a purge): accepted only when the file is empty.

Rebind never empties a file that another reservation or a name outside the reservation also links to.

## When a run reports failures

A run with failures exits with status 1. It keeps every reservation that verified, leaves the failed ones untouched, and **keeps the volume closed**: the barrier stays set, so the API and worker refuse to start and every artifact operation fails. The error output names the value to continue with:

```text
rebound 6, emptied 2, unchanged 0, quarantined 0, failed 1
failed 5f0c2f0e-7d0a-4c55-9a43-3d0b8a2f6c11: size_or_digest_mismatch
the volume stays closed; repair the listed payloads and re-run with --replace-adoption-run 0d6b1c5e-2f0e-4a0b-9a57-0f6a6f1f2b3c
openmettle-admin: storage rebind incomplete
```

Repair the listed files, for example by restoring them from another copy of the same recovery point, and run rebind again with that value. Each failed run prints a new value; always use the latest. If the output is lost, read it from the database:

```sql
SELECT adoption_run_id FROM openmettle.storage_volume_control;
```

| Reason | Meaning |
| --- | --- |
| `size_or_digest_mismatch` | The copied payload is not the settled content. |
| `missing revision`, `missing reservation file` | The copy does not contain the file. |
| `intra_reservation_inode_mismatch` | The copy split one file into several; restore with hard links preserved. |
| `cross_reservation_inode_alias` | Two reservations share one file. Both are left untouched. |
| `foreign hard link` | An unsettled upload is also linked from a name outside its reservation. |
| `anchor is not empty`, `truncated_visible_name_present`, `invalid volume entry` | A cleanup marker or entry is not in a state the store writes. |
| `cannot read revision digest` | The payload could not be read. |

A run that is refused outright (`OMQ03` followed by a reason such as `owner login required`, `volume is not pinned`, `reservation in use` or `adoption ownership mismatch`) changes no row and leaves the barrier as it found it. `reservation in use` means another process holds a payload open: stop it and run rebind again.

If rebind is killed, the barrier stays set. Confirm the process has exited, read `adoption_run_id` as above and re-run with `--replace-adoption-run`. A run interrupted while applying may already have emptied unsettled uploads; the next run binds them.

## Known gaps

- **A payload that cannot be recovered blocks start-up.** If a settled payload is lost or damaged in every copy, rebind cannot complete and the volume stays closed until the owner resolves that reservation by hand. A supported step to declare a payload lost does not exist yet.
- **A process started before rebind can cause damage that rebind does not undo.** A worker quarantines unsettled uploads whose files changed and claims due revisions for purge. You see `worker.sweep.failed`, reads answering 500, a non-zero `quarantined` count from rebind and from `quota verify`, and a failing drift check. The supported recovery is to restore the database again from the same recovery point and run rebind before starting anything.
- **Exercised copy tools:** `cp -a`, GNU `tar` 1.34 and restic 0.14 on Linux, on a local filesystem. Velero file backup, NFS volumes, CSI snapshots and a real cluster restore have not been tested.
