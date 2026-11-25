//! Composable persistence primitives, not admission or execution policy (ADR 0004).
//! Writers temporarily own the outer transaction while opening/using/closing a savepoint.
//! Cancellation drops that transaction and leaves WriteTransaction unusable. Only the caller
//! can commit; ordinary errors restore the owner after successful savepoint rollback.
use sha2::{Digest, Sha256};
use sqlx::{Acquire, Connection, PgConnection, PgPool, Postgres, Row, Transaction};

pub enum Error {
    Invalid,
    Conflict,
    NotFound,
    StaleRevision,
    TransactionUnavailable,
    Database(sqlx::Error),
    /// Owner scope storage limit is not configured; new reservations are refused.
    LimitUnconfigured,
    /// Instance storage budget is not configured; new reservations are refused.
    InstanceLimitUnconfigured,
    /// The owner scope's byte limit would be exceeded.
    OwnerLimit,
    /// The instance's logical storage budget would be exceeded.
    InstanceLimit,
    /// A linked external operation has no known outcome; capacity stays reserved.
    Unresolved,
    /// The lifecycle state or deadline does not permit this transition now.
    NotEligible,
}
impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}
// Do not disclose SQL, row values or private payloads through Display.
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid persistence input",
            Self::Conflict => "identity conflict",
            Self::NotFound => "record not found",
            Self::StaleRevision => "stale operation revision",
            Self::TransactionUnavailable => {
                "transaction unavailable after cancellation or cleanup failure"
            }
            Self::Database(_) => "persistence database error",
            Self::LimitUnconfigured => "storage limits are not configured",
            Self::InstanceLimitUnconfigured => "instance storage budget is not configured",
            Self::OwnerLimit => "owner storage limit exceeded",
            Self::InstanceLimit => "instance storage budget exceeded",
            Self::Unresolved => "linked operation outcome unresolved",
            Self::NotEligible => "lifecycle transition not eligible",
        })
    }
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy)]
pub struct Payload<'a> {
    pub format: &'a str,
    pub version: i32,
    pub bytes: &'a [u8],
}
impl Payload<'_> {
    fn validate(&self, limit: usize) -> Result<(), Error> {
        if !bounded(self.format, 128) || self.version <= 0 || self.bytes.len() > limit {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
pub(crate) fn bounded(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.contains('\0')
}
pub(crate) fn is_canonical_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}
pub(crate) fn uuid(s: &str) -> Result<(), Error> {
    is_canonical_uuid(s).then_some(()).ok_or(Error::Invalid)
}
/// Domain is a fixed ASCII constant, then each field is u64 big-endian length + bytes.
/// Numeric fields are fixed-width big-endian bytes inside that envelope.
pub(crate) fn identity(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut result = domain.to_vec();
    for field in fields {
        result.extend_from_slice(&(field.len() as u64).to_be_bytes());
        result.extend_from_slice(field);
    }
    result
}
pub(crate) fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
/// Caller-controlled composition boundary. No raw Transaction can be extracted or borrowed.
/// A cancelled helper permanently consumes the inner transaction. Begin a new owner on the
/// connection after dropping this one. Discard the connection after cancellation if protocol
/// cleanup is uncertain (especially during savepoint release); use a fresh connection.
/// Raw connection access is for statement composition, not manual transaction control.
pub struct WriteTransaction<'c> {
    inner: Option<Transaction<'c, Postgres>>,
}
impl<'c> WriteTransaction<'c> {
    /// Start a root transaction; reject nesting into someone else's transaction.
    pub async fn begin(connection: &'c mut PgConnection) -> Result<Self, Error> {
        if connection.is_in_transaction() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            inner: Some(Connection::begin(connection).await?),
        })
    }
    /// Start a bounded `READ COMMITTED` root transaction with 2 s lock and 3 s statement limits.
    pub(crate) async fn begin_bounded(
        connection: &'c mut PgConnection,
        read_only: bool,
    ) -> Result<Self, Error> {
        Self::begin(connection).await?.with_bounds(read_only).await
    }
    /// Own the pool connection so a blocking filesystem operation can keep its row lock
    /// until the operation finishes, even if the caller drops the sweep.
    pub(crate) async fn begin_bounded_pool(
        pool: &PgPool,
        read_only: bool,
    ) -> Result<WriteTransaction<'static>, Error> {
        WriteTransaction {
            inner: Some(pool.begin().await?),
        }
        .with_bounds(read_only)
        .await
    }
    async fn with_bounds(mut self, read_only: bool) -> Result<Self, Error> {
        let setup: &[&'static str] = if read_only {
            &[
                "SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY",
                "SET LOCAL lock_timeout = '2s'",
                "SET LOCAL statement_timeout = '3s'",
            ]
        } else {
            &[
                "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
                "SET LOCAL synchronous_commit = on",
                "SET LOCAL lock_timeout = '2s'",
                "SET LOCAL statement_timeout = '3s'",
            ]
        };
        for &sql in setup {
            if let Err(error) = sqlx::query(sql).execute(self.connection()?).await {
                self.rollback().await?;
                return Err(error.into());
            }
        }
        Ok(self)
    }
    // SQLx can lose its root depth when a raw borrowed savepoint is cancelled. Never
    // turn that state into a no-op successful commit or let a helper open a new root.
    fn ensure_active(&mut self) -> Result<(), Error> {
        if !self.inner.as_mut().is_some_and(|tx| tx.is_in_transaction()) {
            self.inner.take();
            return Err(Error::TransactionUnavailable);
        }
        Ok(())
    }
    pub(crate) fn take_active(&mut self) -> Result<Transaction<'c, Postgres>, Error> {
        self.ensure_active()?;
        self.inner.take().ok_or(Error::TransactionUnavailable)
    }
    /// Compose SQL in the same transaction. Unavailable after cancellation/cleanup failure.
    pub fn connection(&mut self) -> Result<&mut PgConnection, Error> {
        self.ensure_active()?;
        self.inner
            .as_deref_mut()
            .ok_or(Error::TransactionUnavailable)
    }
    /// Restore the transaction a helper took, after its savepoint closed successfully.
    /// No await point may separate savepoint cleanup from this call.
    pub(crate) fn restore(&mut self, tx: Transaction<'c, Postgres>) {
        self.inner = Some(tx);
    }
    pub async fn commit(mut self) -> Result<(), Error> {
        self.take_active()?.commit().await?;
        Ok(())
    }
    pub async fn rollback(mut self) -> Result<(), Error> {
        self.take_active()?.rollback().await?;
        Ok(())
    }
}

// Outer Err means cleanup failed: never restore a commit-capable handle. Inner Err is an
// ordinary helper error whose savepoint rollback succeeded, preserving prior caller writes.
pub(crate) async fn finish<T>(
    tx: Transaction<'_, Postgres>,
    result: Result<T, Error>,
) -> Result<Result<T, Error>, Error> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(Ok(value))
        }
        Err(error) => {
            tx.rollback().await?;
            Ok(Err(error))
        }
    }
}

pub struct RunInput<'a> {
    pub scope: &'a str,
    pub actor: &'a str,
    pub conversation: &'a str,
    pub branch: &'a str,
    pub message: &'a str,
    pub key: &'a str,
    pub format: &'a str,
    pub version: i32,
    pub input: &'a [u8],
    pub config: &'a [u8],
}
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

/// The ADR 0004 run identity; also validates the input.
pub(crate) fn run_identity(r: &RunInput<'_>) -> Result<Vec<u8>, Error> {
    for id in [r.scope, r.actor, r.conversation, r.branch, r.message] {
        uuid(id)?;
    }
    if !bounded(r.key, 128)
        || !bounded(r.format, 128)
        || r.version <= 0
        || r.input.len().saturating_add(r.config.len()) > MAX_SNAPSHOT_BYTES
    {
        return Err(Error::Invalid);
    }
    Ok(identity(
        b"openmettle/run/1\0",
        &[
            r.scope.as_bytes(),
            r.actor.as_bytes(),
            r.conversation.as_bytes(),
            r.branch.as_bytes(),
            r.message.as_bytes(),
            r.key.as_bytes(),
            r.format.as_bytes(),
            &r.version.to_be_bytes(),
            r.input,
            r.config,
        ],
    ))
}

/// Server admission decisions (ADR 0032), written by the same `INSERT` as the run. They are
/// outside `request_identity`, so a replay never compares them.
pub(crate) struct AdmissionColumns<'a> {
    pub approval: &'a str,
    pub round_limit: i32,
    pub queue_timeout_ms: i64,
}

/// Insert or recover the same run. Initial event is deterministic and empty; callers may
/// compose messages/reservations before calling. Rejected outer work must be rolled back.
/// The run's admission columns stay `NULL`: it is never claimed and expiry fails it.
pub async fn create_run(tx: &mut WriteTransaction<'_>, r: &RunInput<'_>) -> Result<String, Error> {
    insert_run(tx, r, None).await.map(|(run, _)| run)
}

/// [`create_run`], optionally with admission columns. Returns the run and whether this call
/// inserted it; an existing identical run is returned with `false`.
pub(crate) async fn insert_run(
    tx: &mut WriteTransaction<'_>,
    r: &RunInput<'_>,
    admission: Option<&AdmissionColumns<'_>>,
) -> Result<(String, bool), Error> {
    insert_admitted(tx, r, admission, None).await
}

pub(crate) struct EffectAdmission<'a> {
    pub mode: &'static str,
    pub session: &'a str,
    pub evidence: Vec<u8>,
}

pub(crate) async fn insert_admitted(
    tx: &mut WriteTransaction<'_>,
    r: &RunInput<'_>,
    admission: Option<&AdmissionColumns<'_>>,
    effect: Option<&EffectAdmission<'_>>,
) -> Result<(String, bool), Error> {
    let id = run_identity(r)?;
    let hash = digest(&id);
    // A bare insert names only the pre-19 columns, so it also works on an older schema.
    const BASE: &str = "INSERT INTO openmettle.runs
        (scope_id, actor_user_id, conversation_id, branch_id, input_message_id, idempotency_key,
         snapshot_format, snapshot_version, input_snapshot, config_snapshot, request_identity, request_digest";
    const VALUES: &str =
        ") VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,$8,$9,$10,$11,$12";
    let (columns, values) = match (admission, effect) {
        (Some(_), Some(_)) => (
            ",actor_approval_id,round_limit,queue_expires_at,execution_mode,originating_session_id,admission_evidence",
            ",$13::uuid,$14,clock_timestamp() + $15::bigint * interval '1 millisecond',$16,$17,$18",
        ),
        (Some(_), None) => (
            ",actor_approval_id,round_limit,queue_expires_at",
            ",$13::uuid,$14,clock_timestamp() + $15::bigint * interval '1 millisecond'",
        ),
        (None, None) => ("", ""),
        _ => return Err(Error::Invalid),
    };
    let sql = format!(
        "{BASE}{columns}{VALUES}{values}) ON CONFLICT (scope_id,actor_user_id,idempotency_key) DO NOTHING RETURNING id::text"
    );
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        let mut insert = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(r.scope).bind(r.actor).bind(r.conversation).bind(r.branch).bind(r.message).bind(r.key).bind(r.format).bind(r.version).bind(r.input).bind(r.config).bind(&id).bind(&hash);
        if let Some(a) = admission {
            insert = insert.bind(a.approval).bind(a.round_limit).bind(a.queue_timeout_ms);
        }
        if let Some(e) = effect {
            insert = insert.bind(e.mode).bind(e.session).bind(&e.evidence);
        }
        let inserted: Option<String> = insert.fetch_optional(&mut *sp).await?;
        if let Some(run) = inserted {
            let payload = Payload { format: "openmettle.run-created", version: 1, bytes: b"" };
            let event_id = event_identity(r.scope, &run, "run-created", payload);
            append_locked(&mut sp, r.scope, &run, "run-created", &event_id, payload).await?;
            Ok((run, true))
        } else {
            let row = sqlx::query("SELECT id::text, request_identity, request_digest, conversation_id::text, branch_id::text,
             input_message_id::text, snapshot_format, snapshot_version, input_snapshot, config_snapshot FROM
             openmettle.runs WHERE scope_id=$1::uuid AND actor_user_id=$2::uuid AND idempotency_key=$3")
                .bind(r.scope).bind(r.actor).bind(r.key).fetch_one(&mut *sp).await?;
            if row.get::<Vec<u8>,_>("request_identity") != id || row.get::<Vec<u8>,_>("request_digest") != hash
                || row.get::<String,_>("conversation_id") != r.conversation || row.get::<String,_>("branch_id") != r.branch
                || row.get::<String,_>("input_message_id") != r.message || row.get::<String,_>("snapshot_format") != r.format
                || row.get::<i32,_>("snapshot_version") != r.version || row.get::<Vec<u8>,_>("input_snapshot") != r.input || row.get::<Vec<u8>,_>("config_snapshot") != r.config { return Err(Error::Conflict); }
            Ok((row.get("id"), false))
        }
    }.await;
    let result = finish(sp, result).await?;
    tx.inner = Some(outer);
    result
}

pub(crate) async fn lock_run(
    tx: &mut Transaction<'_, Postgres>,
    scope: &str,
    run: &str,
) -> Result<(), Error> {
    // Column UPDATE privilege suffices for a row lock; no ownership/state UPDATE is granted.
    let exists: Option<i64> = sqlx::query_scalar("SELECT last_event_sequence FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid FOR NO KEY UPDATE")
        .bind(scope).bind(run).fetch_optional(&mut **tx).await?;
    exists.ok_or(Error::NotFound).map(|_| ())
}
async fn existing_event(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    key: &str,
    id: &[u8],
    p: Payload<'_>,
) -> Result<Option<i64>, Error> {
    let row = sqlx::query("SELECT sequence,identity,digest,format,format_version,payload FROM openmettle.run_events WHERE
             scope_id=$1::uuid AND run_id=$2::uuid AND append_key=$3")
        .bind(scope).bind(run).bind(key).fetch_optional(&mut *c).await?;
    match row {
        None => Ok(None),
        Some(row) => {
            if row.get::<Vec<u8>, _>("identity") != id
                || row.get::<Vec<u8>, _>("digest") != digest(id)
                || row.get::<String, _>("format") != p.format
                || row.get::<i32, _>("format_version") != p.version
                || row.get::<Vec<u8>, _>("payload") != p.bytes
            {
                return Err(Error::Conflict);
            }
            Ok(Some(row.get("sequence")))
        }
    }
}
async fn append_locked(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    key: &str,
    id: &[u8],
    p: Payload<'_>,
) -> Result<i64, Error> {
    if let Some(seq) = existing_event(c, scope, run, key, id, p).await? {
        return Ok(seq);
    }
    let seq: i64 = sqlx::query_scalar("UPDATE openmettle.runs SET last_event_sequence=last_event_sequence+1 WHERE scope_id=$1::uuid AND
             id=$2::uuid RETURNING last_event_sequence")
        .bind(scope).bind(run).fetch_one(&mut *c).await?;
    sqlx::query("INSERT INTO openmettle.run_events
             (scope_id,run_id,sequence,append_key,format,format_version,payload,identity,digest) VALUES
             ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9)")
        .bind(scope).bind(run).bind(seq).bind(key).bind(p.format).bind(p.version).bind(p.bytes).bind(id).bind(digest(id)).execute(&mut *c).await?;
    Ok(seq)
}
/// Append to a run whose row the caller's transaction already holds `FOR NO KEY UPDATE`
/// (ADR 0032 claim and terminal events). No savepoint: an error aborts the caller's work.
pub(crate) async fn append_to_locked_run(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    key: &str,
    p: Payload<'_>,
) -> Result<i64, Error> {
    let id = event_identity(scope, run, key, p);
    append_locked(c, scope, run, key, &id, p).await
}
fn event_identity(scope: &str, run: &str, key: &str, p: Payload<'_>) -> Vec<u8> {
    identity(
        b"openmettle/event/1\0",
        &[
            scope.as_bytes(),
            run.as_bytes(),
            key.as_bytes(),
            p.format.as_bytes(),
            &p.version.to_be_bytes(),
            p.bytes,
        ],
    )
}
pub async fn append_event(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    run: &str,
    key: &str,
    p: Payload<'_>,
) -> Result<i64, Error> {
    uuid(scope)?;
    uuid(run)?;
    p.validate(65536)?;
    if !bounded(key, 128) {
        return Err(Error::Invalid);
    }
    let id = event_identity(scope, run, key, p);
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        lock_run(&mut sp, scope, run).await?;
        append_locked(&mut sp, scope, run, key, &id, p).await
    }
    .await;
    let result = finish(sp, result).await?;
    tx.inner = Some(outer);
    result
}

pub struct Intent<'a> {
    pub scope: &'a str,
    pub run: &'a str,
    pub key: &'a str,
    pub target: &'a str,
    pub capability: &'a str,
    pub request: Payload<'a>,
}
pub async fn record_intent(tx: &mut WriteTransaction<'_>, r: &Intent<'_>) -> Result<String, Error> {
    let identity = intent_identity(r)?;
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        lock_run(&mut sp, r.scope, r.run).await?;
        if let Some(id) = existing_intent(&mut sp, r, None, &identity).await? { return Ok(id); }
        let operation = sqlx::query_scalar::<_, String>("INSERT INTO openmettle.operations
            (scope_id,run_id,logical_key,target,capability,format,format_version,request,request_identity,request_digest)
            VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id::text")
            .bind(r.scope).bind(r.run).bind(r.key).bind(r.target).bind(r.capability).bind(r.request.format)
            .bind(r.request.version).bind(r.request.bytes).bind(&identity).bind(digest(&identity)).fetch_one(&mut *sp).await?;
        intent_event(&mut sp, r, &operation, &identity).await?;
        Ok(operation)
    }.await;
    let result = finish(sp, result).await?;
    tx.inner = Some(outer);
    result
}

/// Validate the proposal and frame its immutable ADR 0004 identity.
pub(crate) fn intent_identity(r: &Intent<'_>) -> Result<Vec<u8>, Error> {
    uuid(r.scope)?;
    uuid(r.run)?;
    r.request.validate(65536)?;
    if !bounded(r.key, 128)
        || !bounded(r.target, 512)
        || !["repeatable_read", "idempotent", "lookup", "non_repeatable"].contains(&r.capability)
    {
        return Err(Error::Invalid);
    }
    Ok(identity(
        b"openmettle/intent/1\0",
        &[
            r.scope.as_bytes(),
            r.run.as_bytes(),
            r.key.as_bytes(),
            r.target.as_bytes(),
            r.capability.as_bytes(),
            r.request.format.as_bytes(),
            &r.request.version.to_be_bytes(),
            r.request.bytes,
        ],
    ))
}

pub(crate) async fn existing_intent(
    c: &mut PgConnection,
    r: &Intent<'_>,
    approval: Option<&str>,
    id: &[u8],
) -> Result<Option<String>, Error> {
    let old = sqlx::query("SELECT id::text,request_identity,request_digest,target,capability,format,format_version,request,
             to_jsonb(o)->>'approval_id' AS approval FROM openmettle.operations o
             WHERE scope_id=$1::uuid AND run_id=$2::uuid AND logical_key=$3")
            .bind(r.scope).bind(r.run).bind(r.key).fetch_optional(&mut *c).await?;
    if let Some(row) = old {
        if row.get::<Vec<u8>, _>("request_identity") != id
            || row.get::<Vec<u8>, _>("request_digest") != digest(id)
            || row.get::<String, _>("target") != r.target
            || row.get::<String, _>("capability") != r.capability
            || row.get::<String, _>("format") != r.request.format
            || row.get::<i32, _>("format_version") != r.request.version
            || row.get::<Vec<u8>, _>("request") != r.request.bytes
        {
            return Err(Error::Conflict);
        }
        if row.get::<Option<String>, _>("approval").as_deref() != approval {
            return Err(Error::Conflict);
        }
        return Ok(Some(row.get("id")));
    }
    Ok(None)
}

pub(crate) async fn intent_event(
    c: &mut PgConnection,
    r: &Intent<'_>,
    operation: &str,
    id: &[u8],
) -> Result<(), Error> {
    let event_id = identity(b"openmettle/intent-event/1\0", &[operation.as_bytes(), id]);
    append_locked(
        c,
        r.scope,
        r.run,
        &format!("intent:{operation}"),
        &event_id,
        Payload {
            format: "openmettle.operation-intent",
            version: 1,
            bytes: operation.as_bytes(),
        },
    )
    .await?;
    Ok(())
}
pub struct Observation<'a> {
    pub scope: &'a str,
    pub run: &'a str,
    pub operation: &'a str,
    pub key: &'a str,
    pub expected_revision: i64,
    pub outcome: &'a str,
    pub handle: Option<&'a str>,
    pub evidence: Payload<'a>,
}
/// Observation key is in the run's event namespace. Exact retries recover their original
/// revision even after later observations. Known outcomes are immutable through this helper.
pub async fn record_observation(
    tx: &mut WriteTransaction<'_>,
    o: &Observation<'_>,
) -> Result<i64, Error> {
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        uuid(o.scope)?;
        uuid(o.run)?;
        lock_run(&mut sp, o.scope, o.run).await?;
        record_observation_locked(&mut sp, o).await
    }
    .await;
    let result = finish(sp, result).await?;
    tx.inner = Some(outer);
    result
}

/// Record an observation directly inside an already-open caller transaction (holding the run lock).
pub(crate) async fn record_observation_locked(
    c: &mut PgConnection,
    o: &Observation<'_>,
) -> Result<i64, Error> {
    uuid(o.scope)?;
    uuid(o.run)?;
    uuid(o.operation)?;
    o.evidence.validate(65536)?;
    if !bounded(o.key, 128)
        || o.expected_revision < 0
        || o.expected_revision == i64::MAX
        || !["outcome_unknown", "succeeded", "failed"].contains(&o.outcome)
        || (o.outcome != "outcome_unknown" && o.evidence.bytes.is_empty())
        || o.handle.is_some_and(|h| !bounded(h, 2048))
    {
        return Err(Error::Invalid);
    }
    let present = [u8::from(o.handle.is_some())];
    let id = identity(
        b"openmettle/observation/1\0",
        &[
            o.scope.as_bytes(),
            o.run.as_bytes(),
            o.operation.as_bytes(),
            o.key.as_bytes(),
            &o.expected_revision.to_be_bytes(),
            o.outcome.as_bytes(),
            &present,
            o.handle.unwrap_or("").as_bytes(),
            o.evidence.format.as_bytes(),
            &o.evidence.version.to_be_bytes(),
            o.evidence.bytes,
        ],
    );
    if existing_event(c, o.scope, o.run, o.key, &id, o.evidence)
        .await?
        .is_some()
    {
        return Ok(o.expected_revision + 1);
    }
    let row = sqlx::query(
        "SELECT revision,outcome,downstream_handle FROM openmettle.operations WHERE scope_id=$1::uuid AND
             run_id=$2::uuid AND id=$3::uuid FOR UPDATE",
    )
    .bind(o.scope)
    .bind(o.run)
    .bind(o.operation)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::NotFound)?;
    if row.get::<i64, _>("revision") != o.expected_revision {
        return Err(Error::StaleRevision);
    }
    if ["succeeded", "failed"].contains(&row.get::<String, _>("outcome").as_str()) {
        return Err(Error::Conflict);
    }
    // Once learned, retain the handle; a conflicting handle needs separate reconciliation.
    let old_handle: Option<String> = row.get("downstream_handle");
    if old_handle.as_deref().is_some_and(|h| Some(h) != o.handle) {
        return Err(Error::Conflict);
    }
    sqlx::query(
        "UPDATE openmettle.operations SET
             revision=revision+1,outcome=$4,downstream_handle=$5,observation_format=$6,observation_version=$7,evidence=$8
             WHERE scope_id=$1::uuid AND run_id=$2::uuid AND id=$3::uuid",
    )
    .bind(o.scope)
    .bind(o.run)
    .bind(o.operation)
    .bind(o.outcome)
    .bind(o.handle)
    .bind(o.evidence.format)
    .bind(o.evidence.version)
    .bind(o.evidence.bytes)
    .execute(&mut *c)
    .await?;
    append_locked(c, o.scope, o.run, o.key, &id, o.evidence).await?;
    Ok(o.expected_revision + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_and_domains_are_unambiguous() {
        assert_ne!(
            identity(b"a", &[b"ab", b"c"]),
            identity(b"a", &[b"a", b"bc"])
        );
        assert_ne!(identity(b"a", &[b"x"]), identity(b"b", &[b"x"]));
        assert_ne!(identity(b"a", &[]), identity(b"a", &[b""]));
        assert_eq!(
            digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }
    #[test]
    fn bounds_and_uuid_spelling() {
        assert!(uuid("00000000-0000-0000-0000-00000000000a").is_ok());
        assert!(uuid("00000000-0000-0000-0000-00000000000A").is_err());
        assert!(
            Payload {
                format: "x",
                version: 1,
                bytes: &[0; 65536]
            }
            .validate(65536)
            .is_ok()
        );
        assert!(
            Payload {
                format: "x",
                version: 1,
                bytes: &[0; 65537]
            }
            .validate(65536)
            .is_err()
        );
        assert!(!bounded("a\0b", 128));
    }
}
