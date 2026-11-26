//! Run snapshots and ordered replay from the primary database (ADR 0034).
use super::*;
use crate::auth_config::CursorKeys;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::body::Frame;
use ring::hmac;
use sqlx::{Row, postgres::PgRow};
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, watch},
    time::Instant,
};

pub(super) const SSE_MAX_IN_FLIGHT: usize = 128;
const BATCH_LIMIT: i64 = 16;
const CHANNEL_FRAMES: usize = 8;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const REAUTH_INTERVAL: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT: Bytes = Bytes::from_static(b": heartbeat\n\n");
const INVALID_CURSOR: Problem = problem(
    StatusCode::BAD_REQUEST,
    "invalid_cursor",
    "Discard the cursor and fetch the current run snapshot.",
);

/// The untrusted sequence can select a bounded index range. Only `verify` accepts a cursor.
struct Cursor {
    kid: String,
    sequence: i64,
    tag: [u8; 32],
}

impl Cursor {
    fn parse(text: &str) -> Result<Self, Problem> {
        if text.len() > 142 {
            return Err(INVALID_CURSOR);
        }
        let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| INVALID_CURSOR)?;
        let [1, length, rest @ ..] = bytes.as_slice() else {
            return Err(INVALID_CURSOR);
        };
        let k = usize::from(*length);
        if !(1..=64).contains(&k) || rest.len() != k + 40 || URL_SAFE_NO_PAD.encode(&bytes) != text
        {
            return Err(INVALID_CURSOR);
        }
        let kid = std::str::from_utf8(&rest[..k]).map_err(|_| INVALID_CURSOR)?;
        if !CursorKeys::valid_id(kid) {
            return Err(INVALID_CURSOR);
        }
        let sequence = i64::from_be_bytes(rest[k..k + 8].try_into().map_err(|_| INVALID_CURSOR)?);
        if sequence < 0 {
            return Err(INVALID_CURSOR);
        }
        Ok(Self {
            kid: kid.to_owned(),
            sequence,
            tag: rest[k + 8..].try_into().map_err(|_| INVALID_CURSOR)?,
        })
    }
}

struct Binding<'a> {
    scope: &'a str,
    run: &'a str,
    user: &'a str,
}
impl Binding<'_> {
    fn input(&self, kid: &str, sequence: i64) -> Vec<u8> {
        crate::runs::identity(
            b"openmettle/v1-cursor/1\0",
            &[
                b"run-events",
                kid.as_bytes(),
                self.scope.as_bytes(),
                self.run.as_bytes(),
                self.user.as_bytes(),
                &sequence.to_be_bytes(),
            ],
        )
    }
    fn sign(&self, keys: &CursorKeys, sequence: i64) -> String {
        let (kid, key) = &keys.active;
        let mut token = vec![1, kid.len() as u8];
        token.extend_from_slice(kid.as_bytes());
        token.extend_from_slice(&sequence.to_be_bytes());
        token.extend_from_slice(hmac::sign(key, &self.input(kid, sequence)).as_ref());
        URL_SAFE_NO_PAD.encode(token)
    }
    fn verify(&self, keys: &CursorKeys, cursor: &Cursor, last: i64) -> Result<(), Problem> {
        let (_, key) = std::iter::once(&keys.active)
            .chain(&keys.verify_only)
            .find(|(id, _)| id == &cursor.kid)
            .ok_or(INVALID_CURSOR)?;
        hmac::verify(key, &self.input(&cursor.kid, cursor.sequence), &cursor.tag)
            .map_err(|_| INVALID_CURSOR)?;
        if cursor.sequence > last {
            return Err(INVALID_CURSOR);
        }
        Ok(())
    }
}

/// Parse both sources structurally. Only the selected cursor needs a current key and MAC.
fn request_cursor(parts: &Parts) -> Result<Option<Cursor>, Problem> {
    let mut after = None;
    for pair in parts.uri.query().into_iter().flat_map(|q| q.split('&')) {
        match pair.split_once('=') {
            Some(("after", value)) if after.is_none() => after = Some(value),
            _ => return Err(INVALID),
        }
    }
    let header = single_header(
        &parts.headers,
        HeaderName::from_static("last-event-id"),
        INVALID,
    )?
    .map(|v| v.to_str().map_err(|_| INVALID_CURSOR))
    .transpose()?;
    let after = after.map(Cursor::parse).transpose()?;
    let header = header.map(Cursor::parse).transpose()?;
    Ok(header.or(after))
}

const SNAPSHOT: &str = "SELECT r.branch_id::text, r.input_message_id::text, r.scope_id::text, r.conversation_id::text, r.state, r.last_event_sequence,
    (extract(epoch FROM r.created_at)*1000000)::bigint AS created_us,
    CASE WHEN t.sequence IS NOT NULL THEN ROW(t.sequence, t.format, t.format_version, t.payload,
        (extract(epoch FROM t.created_at)*1000000)::bigint) END AS terminal
    FROM openmettle.runs r LEFT JOIN openmettle.run_events t ON t.run_id=r.id AND t.append_key='run-terminal'
    WHERE r.id=$1::uuid";

// ARRAY preserves the indexed subquery's order and returns an empty array for an idle run.
// PostgreSQL 18 adds a second Sort above a lateral left join with an outer ORDER BY.
const BATCH: &str =
    "SELECT r.scope_id::text, r.conversation_id::text, r.state, r.last_event_sequence,
    ARRAY(SELECT ROW(e.sequence, e.format, e.format_version, e.payload,
                     (extract(epoch FROM e.created_at)*1000000)::bigint)
            FROM openmettle.run_events e
           WHERE e.scope_id=r.scope_id AND e.run_id=r.id AND e.sequence > $2
           ORDER BY e.sequence LIMIT $3) AS events
    FROM openmettle.runs r WHERE r.id=$1::uuid";

/// The five selected fields of an event record in both read statements.
type StoredEvent = (i64, String, i32, Vec<u8>, i64);

struct Batch {
    scope: String,
    terminal: bool,
    last: i64,
    events: Vec<StoredEvent>,
}

fn last_sequence(row: &PgRow) -> Result<i64, Problem> {
    let last: i64 = row.get("last_event_sequence");
    if last < 1 {
        return Err(INTERNAL);
    }
    Ok(last)
}

fn wire_state(state: &str) -> &str {
    if state == "reconciling" {
        "running"
    } else {
        state
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventReason {
    reason: String,
}

fn projection(
    format: &str,
    version: i32,
    bytes: &[u8],
) -> Result<Option<(&'static str, Value)>, Problem> {
    let event = match (format, version) {
        ("openmettle.run-created", 1) if bytes.is_empty() => ("run.created", json!({})),
        ("openmettle.run-created", 1) => return Err(INTERNAL),
        (format, 1) => {
            let empty = |kind, data| {
                parse::<Empty>(bytes).map_err(|_| INTERNAL)?;
                Ok((kind, data))
            };
            let reason = |kind, allowed: &[&str]| {
                let event: EventReason = parse(bytes).map_err(|_| INTERNAL)?;
                if !allowed.contains(&event.reason.as_str()) {
                    return Err(INTERNAL);
                }
                Ok((kind, json!({"reason": event.reason})))
            };
            match format {
                "openmettle.run-claimed" => empty("run.started", json!({})),
                "openmettle.run-expired" => empty("run.failed", json!({"reason":"queue_expired"})),
                "openmettle.run-approval-requested" => empty("run.approval_requested", json!({})),
                "openmettle.run-approval-decided" => empty("run.approval_decided", json!({})),
                "openmettle.run-resumed" => empty("run.resumed", json!({})),
                "openmettle.run-waiting" => reason("run.waiting", &["approval"]),
                "openmettle.run-approval-expired" => reason("run.failed", &["approval_expired"]),
                "openmettle.run-invalid-wait" => reason("run.failed", &["invalid_wait"]),
                "openmettle.run-cancelled" => reason("run.cancelled", &["requested", "revoked"]),
                _ => return Ok(None),
            }?
        }
        _ => return Ok(None),
    };
    Ok(Some(event))
}

fn event(run: &str, stored: &StoredEvent) -> Result<Option<Value>, Problem> {
    let (sequence, format, version, payload, micros) = stored;
    let Some((kind, data)) = projection(format, *version, payload)? else {
        return Ok(None);
    };
    Ok(Some(
        json!({ "run_id": run, "sequence": sequence.to_string(), "type": kind, "type_version": 1,
        "occurred_at": timestamp(*micros)?, "data": data }),
    ))
}

fn frame(cursor: &str, event: &Value) -> Result<Bytes, Problem> {
    let data = event.to_string();
    if data.len() > 131_072 || data.contains(['\r', '\n']) {
        return Err(INTERNAL);
    }
    Ok(format!("id: {cursor}\ndata: {data}\n\n").into())
}

async fn authorize(
    c: &mut PgConnection,
    context: &sessions::Context,
    row: &PgRow,
    min_now_ms: i64,
) -> Result<(), StoreError> {
    crate::restore::require_open_gate(c).await?;
    let now_ms = authz::store::post_lock_clock_ms(c, min_now_ms.max(context.observed_ms())).await?;
    let principal = principal_at(c, context, now_ms).await?;
    let conversation = projects::read_resource(
        c,
        &principal,
        ResourceKind::Conversation,
        row.get("conversation_id"),
        now_ms,
    )
    .await?;
    if conversation.scope_id != row.get::<&str, _>("scope_id") {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

struct Frames(mpsc::Receiver<Bytes>);
impl HttpBody for Frames {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(cx)
            .map(|next| next.map(|bytes| Ok(Frame::data(bytes))))
    }
}

impl Api {
    pub(super) async fn snapshot(
        &self,
        parts: &Parts,
        session: Session,
        run: &str,
    ) -> Result<Response, Problem> {
        if parts.uri.query().is_some() {
            return Err(INVALID);
        }
        let keys = parts
            .extensions
            .get::<Arc<CursorKeys>>()
            .ok_or(PROVISIONING)?;
        let context = self.authenticate(&session).await?;
        self.run_response(&context, keys, run, StatusCode::OK, context.observed_ms())
            .await
    }

    pub(super) async fn run_response(
        &self,
        context: &sessions::Context,
        keys: &CursorKeys,
        run: &str,
        status: StatusCode,
        min_now_ms: i64,
    ) -> Result<Response, Problem> {
        let row = self
            .database(async |c| {
                crate::restore::require_open_gate(c).await?;
                let row = sqlx::query(SNAPSHOT)
                    .bind(run)
                    .fetch_optional(&mut *c)
                    .await?
                    .ok_or(StoreError::NotFound)?;
                authorize(c, context, &row, min_now_ms).await?;
                Ok(row)
            })
            .await?;
        let last = last_sequence(&row)?;
        let binding = Binding {
            scope: row.get("scope_id"),
            run,
            user: context.user_id(),
        };
        let terminal = row
            .get::<Option<StoredEvent>, _>("terminal")
            .map(|stored| event(run, &stored))
            .transpose()?
            .flatten();
        Ok(reply(
            status,
            json!({
                "branch_id": row.get::<&str,_>("branch_id"), "input_message_id": row.get::<&str,_>("input_message_id"),
                "run_id": run, "conversation_id": row.get::<&str,_>("conversation_id"),
                "state": wire_state(row.get("state")), "created_at": timestamp(row.get("created_us"))?,
                "last_sequence": last.to_string(), "resume_cursor": binding.sign(keys, last), "terminal": terminal
            }),
        ))
    }

    pub(super) async fn stream_events(
        self: &Arc<Self>,
        parts: Parts,
        body: Body,
        permit: OwnedSemaphorePermit,
    ) -> Result<Response, Problem> {
        let stop = parts.extensions.get::<watch::Receiver<bool>>().cloned();
        tokio::select! {
            biased;
            _ = stopping(stop.clone()) => Err(UNAVAILABLE),
            response = self.open_stream(parts, body, permit, stop) => response,
        }
    }

    async fn open_stream(
        self: &Arc<Self>,
        parts: Parts,
        body: Body,
        permit: OwnedSemaphorePermit,
        stop: Option<watch::Receiver<bool>>,
    ) -> Result<Response, Problem> {
        let session = self.session(&parts)?;
        let run = path_id(&parts, 3)?;
        let cursor = request_cursor(&parts);
        // Duplicate fields and unknown query names are request-shape errors. Cursor
        // content (including bad syntax) is refused only after the visibility decision.
        if matches!(cursor, Err(INVALID)) {
            return Err(INVALID);
        }
        read_body(Op::StreamRunEvents, &parts.headers, body).await?;
        let keys = parts
            .extensions
            .get::<Arc<CursorKeys>>()
            .ok_or(PROVISIONING)?
            .clone();
        let context = self.authenticate(&session).await?;
        let position = cursor
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map_or(0, |c| c.sequence);
        let mut stream = Subscription {
            api: self.clone(),
            session,
            run: run.to_owned(),
            user: context.user_id().to_owned(),
            keys,
            position,
            authorized_at: Instant::now(),
        };
        let first = stream.batch(true).await?;
        if let Some(cursor) = cursor? {
            stream
                .binding(&first.scope)
                .verify(&stream.keys, &cursor, first.last)?;
        }
        if first.terminal && position == first.last {
            return Ok(no_content());
        }

        let body = if parts.method == Method::HEAD {
            Body::empty()
        } else {
            let (tx, rx) = mpsc::channel(CHANNEL_FRAMES);
            let id = parts.extensions.get::<RequestId>().copied();
            tokio::spawn(async move {
                let _permit = permit;
                tokio::select! {
                    biased;
                    _ = stopping(stop) => (),
                    _ = tx.closed() => (),
                    result = stream.deliver(first, &tx) => {
                        if result == Err(INTERNAL) {
                            crate::telemetry::run_stream_failed(id);
                        }
                    }
                }
            });
            Body::new(Frames(rx))
        };
        let mut response = Response::new(body);
        let headers = response.headers_mut();
        response_headers(headers);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        Ok(response)
    }
}

async fn stopping(stop: Option<watch::Receiver<bool>>) {
    match stop {
        Some(mut rx) => {
            let _ = rx.wait_for(|stopping| *stopping).await;
        }
        None => std::future::pending().await,
    }
}

struct Subscription {
    api: Arc<Api>,
    session: Session,
    run: String,
    user: String,
    keys: Arc<CursorKeys>,
    position: i64,
    authorized_at: Instant,
}
impl Subscription {
    fn binding<'a>(&'a self, scope: &'a str) -> Binding<'a> {
        Binding {
            scope,
            run: &self.run,
            user: &self.user,
        }
    }

    /// The native and browser validators manage their own checkout. Release the batch
    /// checkout first, so revalidation works even with a single primary pool slot.
    async fn batch(&mut self, first: bool) -> Result<Batch, Problem> {
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            let row = self
                .api
                .database(async |c| {
                    crate::restore::require_open_gate(c).await?;
                    sqlx::query(BATCH)
                        .bind(&self.run)
                        .bind(self.position)
                        .bind(BATCH_LIMIT)
                        .fetch_optional(c)
                        .await?
                        .ok_or(StoreError::NotFound)
                })
                .await?;
            let events: Vec<StoredEvent> = row.get("events");
            if first || !events.is_empty() || self.authorized_at.elapsed() >= REAUTH_INTERVAL {
                let context = self.api.authenticate(&self.session).await?;
                if context.user_id() != self.user {
                    return Err(UNAUTHENTICATED);
                }
                self.api
                    .database(async |c| authorize(c, &context, &row, context.observed_ms()).await)
                    .await?;
                self.authorized_at = Instant::now();
            }
            Ok(Batch {
                scope: row.get("scope_id"),
                terminal: authz::runs::is_terminal(row.get("state")),
                last: last_sequence(&row)?,
                events,
            })
        })
        .await
        .map_err(|_| TIMEOUT)?
    }

    async fn deliver(&mut self, mut batch: Batch, tx: &mpsc::Sender<Bytes>) -> Result<(), Problem> {
        send(tx, HEARTBEAT).await?;
        let mut last_write = Instant::now();
        loop {
            let full = batch.events.len() == BATCH_LIMIT as usize;
            for stored in batch.events {
                let sequence = stored.0;
                if let Some(event) = event(&self.run, &stored)? {
                    let id = self.binding(&batch.scope).sign(&self.keys, sequence);
                    send(tx, frame(&id, &event)?).await?;
                    last_write = Instant::now();
                }
                self.position = sequence;
            }
            if batch.terminal && (self.position >= batch.last || !full) {
                return Ok(());
            }
            if last_write.elapsed() >= HEARTBEAT_INTERVAL {
                send(tx, HEARTBEAT).await?;
                last_write = Instant::now();
            }
            if !full {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            batch = self.batch(false).await?;
        }
    }
}

async fn send(tx: &mpsc::Sender<Bytes>, bytes: Bytes) -> Result<(), Problem> {
    tokio::time::timeout(WRITE_TIMEOUT, tx.send(bytes))
        .await
        .map_err(|_| TIMEOUT)?
        .map_err(|_| UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_vector_integrity_and_binding() {
        let key = std::array::from_fn::<_, 32, _>(|i| i as u8);
        let keys = CursorKeys {
            active: ("key-A".into(), hmac::Key::new(hmac::HMAC_SHA256, &key)),
            verify_only: vec![],
        };
        let scope = "00000000-0000-0000-0000-000000000001";
        let run = "00000000-0000-0000-0000-000000000002";
        let user = "00000000-0000-0000-0000-000000000003";
        let b = Binding { scope, run, user };
        let text = b.sign(&keys, 42);
        assert_eq!(
            text,
            "AQVrZXktQQAAAAAAAAAqcyKj75P8xu_ZzTczpMf43-jnEmVaL37RGAxQTb1kSoI"
        );
        let verify = |s: &str| b.verify(&keys, &Cursor::parse(s)?, 42);
        assert_eq!(verify(&text), Ok(()));
        let raw = URL_SAFE_NO_PAD.decode(&text).unwrap();
        for i in 0..raw.len() {
            let mut tampered = raw.clone();
            tampered[i] ^= 1;
            assert_eq!(
                verify(&URL_SAFE_NO_PAD.encode(tampered)),
                Err(INVALID_CURSOR)
            );
            assert_eq!(
                verify(&URL_SAFE_NO_PAD.encode(&raw[..i])),
                Err(INVALID_CURSOR)
            );
        }
        assert_eq!(
            verify(&URL_SAFE_NO_PAD.encode([raw.as_slice(), &[0]].concat())),
            Err(INVALID_CURSOR)
        );
        assert_eq!(verify(&(text.clone() + "=")), Err(INVALID_CURSOR));
        assert_eq!(
            verify(&(text[..text.len() - 1].to_owned() + "J")),
            Err(INVALID_CURSOR)
        );
        let c = Cursor::parse(&text).unwrap();
        for other in [
            Binding { scope: user, ..b },
            Binding { run: user, ..b },
            Binding { user: run, ..b },
        ] {
            assert_eq!(other.verify(&keys, &c, 42), Err(INVALID_CURSOR));
        }
        assert_eq!(b.verify(&keys, &c, 41), Err(INVALID_CURSOR));
        let rotated = CursorKeys {
            active: ("other".into(), hmac::Key::new(hmac::HMAC_SHA256, &[9; 32])),
            verify_only: vec![keys.active.clone()],
        };
        assert_eq!(b.verify(&rotated, &c, 42), Ok(()));
        assert_ne!(b.sign(&rotated, 42), text);
    }

    #[test]
    fn header_precedes_a_well_formed_url_cursor() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[1; 32]);
        let keys = CursorKeys {
            active: ("a".into(), key),
            verify_only: vec![],
        };
        let binding = Binding {
            scope: "s",
            run: "r",
            user: "u",
        };
        let old = binding.sign(&keys, 2);
        let new = binding.sign(&keys, 9);
        let after = format!("?after={old}");
        for (query, headers, expected) in [
            ("", vec![], Ok(None)),
            (after.as_str(), vec![], Ok(Some(2))),
            (after.as_str(), vec![new.as_str()], Ok(Some(9))),
            ("?cursor=x", vec![], Err(INVALID)),
            ("?after=x&after=y", vec![], Err(INVALID)),
            ("", vec!["x", "y"], Err(INVALID)),
            (after.as_str(), vec![""], Err(INVALID_CURSOR)),
            ("?after=x", vec![new.as_str()], Err(INVALID_CURSOR)),
            ("?after=%ff", vec![new.as_str()], Err(INVALID_CURSOR)),
            ("", vec![" "], Err(INVALID_CURSOR)),
        ] {
            let mut request = Request::builder().uri(format!("/events{query}"));
            for h in headers {
                request = request.header("last-event-id", h);
            }
            let parts = request.body(()).unwrap().into_parts().0;
            assert_eq!(
                request_cursor(&parts).map(|cursor| cursor.map(|c| c.sequence)),
                expected
            );
        }
    }

    #[test]
    fn query_shape_errors_take_precedence_over_malformed_header_bytes() {
        for (uri, expected) in [
            ("/events?cursor=x", INVALID),
            ("/events?after=x&after=y", INVALID),
            ("/events", INVALID_CURSOR),
        ] {
            let request = Request::builder()
                .uri(uri)
                .header("last-event-id", &[0xff][..])
                .body(())
                .unwrap();
            assert_eq!(
                request_cursor(&request.into_parts().0).err(),
                Some(expected)
            );
        }
    }

    #[test]
    fn only_valid_allowlisted_payloads_reach_one_data_line() {
        assert_eq!(
            projection("openmettle.operation-intent", 1, b"private"),
            Ok(None)
        );
        assert_eq!(
            projection("openmettle.run-cancelled", 2, b"private"),
            Ok(None)
        );
        for (format, bytes) in [
            ("openmettle.run-created", b"{}".as_slice()),
            (
                "openmettle.run-approval-requested",
                br#"{"approval_id":"private"}"#,
            ),
            (
                "openmettle.run-approval-decided",
                br#"{"decision":"approve"}"#,
            ),
            ("openmettle.run-resumed", br#"{"handle":"private"}"#),
            (
                "openmettle.run-waiting",
                br#"{"reason":"approval","arguments":{}}"#,
            ),
            (
                "openmettle.run-approval-expired",
                br#"{"reason":"invalid_wait"}"#,
            ),
            (
                "openmettle.run-invalid-wait",
                br#"{"reason":"approval_expired"}"#,
            ),
            ("openmettle.run-claimed", b"[]"),
            ("openmettle.run-expired", br#"{"detail":"private"}"#),
            ("openmettle.run-cancelled", br#"{"reason":"secret"}"#),
            (
                "openmettle.run-cancelled",
                br#"{"reason":"requested","reason":"revoked"}"#,
            ),
        ] {
            assert_eq!(projection(format, 1, bytes), Err(INTERNAL));
        }
        assert_eq!(wire_state("reconciling"), "running");
        assert_eq!(wire_state("interrupted"), "interrupted");
        assert_eq!(
            frame("id", &json!({"text":"x\r\ny"})).unwrap(),
            "id: id\ndata: {\"text\":\"x\\r\\ny\"}\n\n"
        );
    }

    #[tokio::test]
    async fn full_channel_write_timeout_releases_stream_permit_and_preserves_queued_frames() {
        use http_body_util::BodyExt;

        let streams = Arc::new(Semaphore::new(1));
        let permit = streams.clone().try_acquire_owned().unwrap();
        let (tx, rx) = mpsc::channel(CHANNEL_FRAMES);
        for index in 0..CHANNEL_FRAMES {
            tx.try_send(Bytes::from(format!("frame-{index}"))).unwrap();
        }
        let (_stop_tx, stop_rx) = watch::channel(false);
        let started = Instant::now();
        let task = tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                biased;
                _ = stopping(Some(stop_rx)) => Ok(()),
                _ = tx.closed() => Ok(()),
                result = send(&tx, Bytes::from_static(b"overflow")) => result,
            }
        });

        // While the channel stays full within `WRITE_TIMEOUT`, the stream task stays alive and
        // retains its permit.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!task.is_finished());
        assert!(streams.clone().try_acquire_owned().is_err());

        let result =
            tokio::time::timeout_at(started + WRITE_TIMEOUT + Duration::from_secs(5), task)
                .await
                .expect("full-channel send did not time out within WRITE_TIMEOUT")
                .unwrap();
        assert_eq!(result, Err(TIMEOUT));
        assert!(started.elapsed() >= WRITE_TIMEOUT);
        // Exiting on `WRITE_TIMEOUT` drops `_permit` immediately while `Frames(rx)` retains
        // the `CHANNEL_FRAMES` already-queued frames followed by clean EOF.
        assert!(streams.try_acquire_owned().is_ok());

        let mut body = Frames(rx);
        let mut drained = Vec::new();
        while let Some(frame) = body.frame().await {
            drained.push(frame.unwrap().into_data().unwrap());
        }
        let expected: Vec<Bytes> = (0..CHANNEL_FRAMES)
            .map(|index| Bytes::from(format!("frame-{index}")))
            .collect();
        assert_eq!(drained, expected);
    }
}
