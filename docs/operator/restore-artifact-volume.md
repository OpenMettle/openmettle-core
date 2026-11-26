# Restore the artifact volume

Use this procedure after restoring the artifact directory by file copy (`cp -a`, `tar`, restic or a similar tool) into a new volume, together with the PostgreSQL database from the same recovery point. It covers the artifact store only. The [database restore checklist](../../README.md#database-backup-restore-pre-worker-checklist) still applies, and step 3 of that checklist is this page.

A copy keeps every payload byte and the volume identity files, and it creates new files. Their inode numbers usually differ from the originals and can also be the same by chance. The database pins each payload to its inode number ([ADR 0040](../adr/0040-transactional-quotas-and-reservation-reconciliation.md)), so rebind never relies on the numbers: `openmettle-admin storage rebind` verifies the copied files against the ledger by content and then records the inode numbers it found. Until the volume is rebound, the store cannot serve its existing payloads or clean up correctly. A check refuses a copied volume in most cases (see [Start-up check](#start-up-check)), but it is a backstop and can miss one. The prerequisite is yours: keep every service stopped until rebind has succeeded.

Rebind is a post-restore command. Do not run it on a volume in service. It always empties interrupted uploads (see [What rebind accepts](#what-rebind-accepts)), also on a volume that was not copied.

## Before you start

- **Keep every service stopped until rebind has succeeded.** No API or worker process may run on the restored volume before step 3 has passed. Do not rely on the start-up check to enforce this: it does not detect every copied volume.
- **Nothing else may touch the volume while rebind runs.** No restore, repair or other process may create, replace, link or remove files under the artifact root during the run. Rebind takes a database barrier that makes the store's own operations fail, and it rechecks each file before it acts on it. It detects only what those rechecks can see.
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
   | `rebound` | Reservations now bound to another inode number. |
   | `emptied` | Unsettled uploads whose bytes were discarded (see below). |
   | `unchanged` | Reservations that verified under the inode number they already carried. |
   | `quarantined` | Reservations that were already quarantined. Rebind lists each one and leaves it exactly as it was. |
   | `failed` | Reservations that did not verify. Each is listed with its reason. |

   A run can also exit with status 0 and report states it did not change (see [Quarantines and accounting drift](#quarantines-and-accounting-drift)).

3. Replay the deletion journal export (`openmettle-admin restore replay "$EXPORT_FILE" "$ARTIFACT_ROOT"`, [Restore the deletion journal](storage-adoption-and-quota-upgrade.md#restore-the-deletion-journal-after-a-database-restore), locking the gate with `--required-lifecycle-origin` and `--required-lifecycle-baseline-digest` from the schema-42+ export), which replays any pre-42 retention upgrade baseline along with journaled deadline commitments, pre-expiry restores and purges, deletes resurrected payloads, scrubs any remaining unsettled `revisions/<id>` links, verifies drift and opens `restore_reconciliation_gate` (until then `openmettle-api` refuses mutating `/v1` routes and content/run-history read routes — downloads, message history, run snapshots, run approvals and run event streams — with `503 unavailable`, and `openmettle-worker` claims no run or purge). Then run the filesystem drift check. It is the required post-restore check.

   ```sh
   openmettle-admin quota verify "$ARTIFACT_ROOT"
   ```

   Run it after rebind and replay, not before. Before rebind it is normally refused on a copied volume, with a message that names `storage rebind`; where the copy check misses the copy (for example a volume that holds only interrupted uploads), it runs and reports file mismatches instead. After rebind and replay it must report `file mismatches 0` and `unsettled payloads 0`. Rebind makes the same verification as its last step and opens the volume only when there is no file mismatch, so a file mismatch here means the volume changed after rebind. The SQL function `openmettle.quota_verify_accounting_drift()` is not sufficient on its own. It compares no file and reports a copied volume as healthy.

4. Continue with the rest of the restore checklist, then start the API and worker.

Running rebind again verifies every settled payload again and changes nothing.

## What rebind accepts

- **Settled payloads** (active or retained revisions, and revisions claimed for purge whose bytes are still present): accepted only when the file's size and SHA-256 equal the values recorded when the upload settled. This holds whether or not the inode number changed.
- **Unsettled uploads are emptied.** An upload that was in flight, or published but not settled, at the recovery point has no recorded size or hash, and no process survives a restore to finish it. Rebind truncates its file to zero bytes, binds the reservation to the empty file and withdraws its publication mark. The reservation stays reserved and charged, and the worker releases it under its normal rules. The backup still holds the discarded bytes. Nothing that was acknowledged to a client before the backup is affected, and no unsettled upload becomes an artifact.
- **Cleanup markers** (reclaim and purge anchors, payloads already truncated by a purge): accepted only when the file is empty.

Rebind never empties a file that another reservation or a name outside the reservation also links to. Before the database change commits, it syncs every file it accepted, whether or not its inode number changed, and the artifact directories.

## When the volume stays closed

Rebind opens the volume only when every reservation verified **and** the filesystem verification finds no file mismatch: no recorded inode number, size or hash that disagrees with a file, and no file the reservations' states do not allow. Otherwise it exits with status 1, keeps every reservation that verified, leaves the others untouched, and keeps its database barrier: the API and worker refuse to start and every artifact operation fails. This holds for a run that reached its apply step. A run refused before any write (see [Refused runs](#refused-runs)) puts the barrier back as it found it, even if it had already seen a damaged payload; if the volume was open before that run, it is open after it. The error output names the value to continue with:

```text
rebound 6, emptied 2, unchanged 0, quarantined 0, failed 1
failed 5f0c2f0e-7d0a-4c55-9a43-3d0b8a2f6c11: size_or_digest_mismatch
the volume stays closed; resolve what is reported and re-run with --replace-adoption-run 0d6b1c5e-2f0e-4a0b-9a57-0f6a6f1f2b3c
openmettle-admin: storage rebind incomplete
```

Resolve what is reported, for example by restoring a listed file from another copy of the same recovery point, and run rebind again with that value. Each such run prints a new value; always use the latest. If the output is lost, or a value is refused, read the current one from the database:

```sql
SELECT adoption_run_id FROM openmettle.storage_volume_control;
```

| Reason | Meaning |
| --- | --- |
| `size_or_digest_mismatch` | The copied payload is not the settled content. |
| `missing revision`, `missing reservation file` | The copy does not contain the file the reservation's state requires. |
| `payload is not accessible` | The file exists but cannot be opened for reading and writing, for example because it was restored with a wrong mode or owner, or the open returned an I/O error. |
| `reservation has no recorded inode` | A settled reservation was never bound to a file. Binding it is `storage adopt`'s task. |
| `intra_reservation_inode_mismatch` | The copy split one file into several; restore with hard links preserved. |
| `cross_reservation_inode_alias` | Two reservations share one file. Both are left untouched. |
| `foreign hard link` | An unsettled upload is also linked from a name outside its reservation. |
| `unexpected payload`, `unexpected reclaim anchor`, `unexpected purge anchor`, `anchor is not empty`, `truncated_visible_name_present`, `invalid volume entry` | A file is present that the reservation's state does not allow, or a cleanup marker is not in a state the store writes. |
| `cannot read revision digest` | The payload could not be read. |

When every reservation verified but a file mismatch remains, rebind prints the same line as `quota verify` instead of `failed` lines. It usually means a file that no reservation owns:

```text
rebound 2, emptied 1, unchanged 0, quarantined 0, failed 0
storage mismatches 0, budget mismatches 0, settlement mismatches 0, pending gateway 0, file mismatches 1, quarantined 0, unsettled payloads 0
```

### Quarantines and accounting drift

Quarantined reservations and accounting drift that is not a file mismatch do not keep the volume closed. A running system tolerates both; they are alarms, not outages. Rebind lists them, states that it did not change them, and exits with status 0 if nothing else failed:

```text
rebound 4, emptied 0, unchanged 0, quarantined 1, failed 0
quarantined 5f0c2f0e-7d0a-4c55-9a43-3d0b8a2f6c11: left unchanged
storage mismatches 1, budget mismatches 0, settlement mismatches 0, pending gateway 0, file mismatches 0, quarantined 1, unsettled payloads 0
rebind did not change the quarantined reservations or the accounting drift reported above
```

`quota verify` then exits with a non-zero status for the same reasons. Compare its result with the state at the recovery point:

- **Quarantined reservations or accounting drift that already existed at the recovery point** are the state the system was in before the backup. The restore is complete; handle them with the normal procedures for those conditions ([Verify accounting](storage-adoption-and-quota-upgrade.md#verify-accounting)).
- **Quarantines that were not there before the backup** mean a service was started on the volume before rebind. It may have changed both the database and the volume. Stop every service, restore the matched database and volume again, and restart the [restore checklist](../../README.md#database-backup-restore-pre-worker-checklist) at its first step. Restoring the database alone would undo the session invalidation and revocation steps you already completed and would leave the volume as the service changed it.

### Unbound staged files

A reservation that never recorded an inode but has bytes under its staging name is reported as a warning. Rebind leaves the reservation and the file exactly as they are, and the warning does not keep the volume closed. The worker's reconciler quarantines such a reservation when it expires, as it does on a running system:

```text
warning 5f0c2f0e-7d0a-4c55-9a43-3d0b8a2f6c11: unbound reservation with a staged file; left unchanged, the reconciler will quarantine it
```

### Refused runs

A run that is refused outright prints `OMQ03` and a reason such as `owner login required`, `volume is not pinned`, `reservation in use` or `adoption ownership mismatch`, then `storage rebind refused; nothing was changed`. No file and no row changed, and the barrier is as the run found it. `reservation in use` means another process holds a payload open: stop it and run rebind again.

If a run fails after it has started to empty uploads, it cannot say that nothing changed. It keeps the barrier and prints the value to continue with:

```text
OMQ03: database operation failed
the volume stays closed and uploads may already be emptied; re-run with --replace-adoption-run 0d6b1c5e-2f0e-4a0b-9a57-0f6a6f1f2b3c
openmettle-admin: storage rebind incomplete
```

If a database commit gets no answer, for example because the connection drops, rebind cannot know whether the commit took effect, so it claims neither state. It prints the value it used and tells you to read the real one:

```text
OMQ03: commit outcome unknown
this run used the barrier value 0d6b1c5e-2f0e-4a0b-9a57-0f6a6f1f2b3c; whether the volume is closed under it is not known
read the current value before the next command: SELECT adoption_run_id FROM openmettle.storage_volume_control;
openmettle-admin: storage rebind interrupted
```

Run the query, then choose the next command from its result:

```sql
SELECT adoption_run_id FROM openmettle.storage_volume_control;
```

- It returns the value the run printed, or another value: the volume is closed. Re-run rebind with `--replace-adoption-run` and the value the query returned.
- It returns no value (null): no barrier is set. Run rebind again without the option. If the run had finished its work, this run changes nothing and confirms the result.

### Taking over a barrier

If rebind is killed, the barrier stays set. Read `adoption_run_id` as above and re-run with `--replace-adoption-run`. There is no liveness check: the value also takes over a run that is still scanning. The run that was taken over is fenced out when it tries to apply and stops with `adoption ownership changed`. Confirm the earlier process has exited before you take over.

`storage adopt` accepts the same value. An adoption that is refused or fails verification hands the barrier back as it found it, so a failed adoption cannot open a volume that an incomplete rebind closed. An adoption that succeeds clears the barrier, as it always has.

## Start-up check

The API and worker compare up to 16 live settled payloads with the ledger before they do any artifact work. When a published file has another inode number than the ledger, start-up exits with status 78 and says what to do:

```text
configuration error: invalid ARTIFACTS_DIR: the volume was restored by file copy; run `openmettle-admin storage rebind` first
```

If the database cannot be reached at start-up, the process starts, and each artifact operation repeats the check and fails until it has passed once. Those later failures carry the store's general I/O error (`worker.sweep.failed`, a 500 for an API request), not this message.

`openmettle-admin quota verify ROOT` makes the same check. On a copied volume that the check detects, it is refused until rebind has completed, so do not plan on it as a diagnostic before rebind:

```text
openmettle-admin: the artifact volume was restored by file copy and is not rebound; run `openmettle-admin storage rebind` first
```

`storage rebind` and `storage adopt` are not behind this check. They read the volume and the ledger directly.

The check never refuses a healthy volume. It is a backstop, not the control that keeps services off an unrebound volume: it misses a copied volume that holds no live settled payload (for example only interrupted uploads), and one whose sampled files received the same inode numbers by chance. On such a volume a service starts and `quota verify ROOT` runs.

## Known gaps

- **A payload that cannot be recovered keeps the volume closed.** If a settled payload is lost or damaged in every copy, rebind cannot complete until the owner resolves that reservation by hand. A supported step to declare a payload lost does not exist yet.
- **A quarantined reservation stays quarantined.** Rebind does not verify or rebind it, and nothing supported clears a quarantine on a copied volume. It does not keep the volume closed; the owner resolves it by hand, as before the backup.
- **A process that got past the start-up check before rebind can cause damage that rebind does not undo.** A worker quarantines unsettled uploads whose files changed and claims due revisions for purge. You see `worker.sweep.failed`, reads answering 500 and a non-zero `quarantined` count. The supported recovery is to stop every service, restore the matched database and volume again, and restart the restore checklist at its first step.
- **Exercised copy tools:** `cp -a`, GNU `tar` 1.34 and restic 0.14 on Linux, on a local filesystem. Velero file backup, NFS volumes, CSI snapshots and a real cluster restore have not been tested.

## External connection vault keys

External connection credentials in `openmettle.external_connections` are encrypted with versioned master keys kept outside PostgreSQL and artifact volume backups ([ADR 0045](../adr/0045-credential-vault-and-external-connection-lifecycle.md)). After opening the restore gate, verify key coverage with `openmettle-admin vault status` and follow [Credential vault and key recovery](credential-vault-and-key-recovery.md) before enabling external tool traffic.
