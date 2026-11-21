use super::{turn::Assembly, *};
use crate::model_config::Profile;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::time::timeout;

fn status(status: u16, h: &HeaderMap) -> Error {
    match status {
        429 => {
            let values = h.get_all(header::RETRY_AFTER);
            let delay = if values.iter().count() == 1 {
                h.get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|s| s.parse::<u32>().ok())
                    .filter(|n| *n <= 86400)
            } else {
                None
            };
            Error::RateLimited(delay)
        }
        503 => Error::Unavailable,
        504 => Error::Timeout,
        _ => Error::Provider,
    }
}
fn media(h: &HeaderMap, stream: bool) -> Result<(), Error> {
    let mut parts = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Malformed)?
        .split(';')
        .map(str::trim);
    if !parts.next().unwrap_or("").eq_ignore_ascii_case(if stream {
        "text/event-stream"
    } else {
        "application/json"
    }) {
        return Err(Error::Malformed);
    }
    if let Some(parameter) = parts.next() {
        let (k, v) = parameter.split_once('=').ok_or(Error::Malformed)?;
        if !k.trim().eq_ignore_ascii_case("charset")
            || !(v.trim().eq_ignore_ascii_case("utf-8")
                || v.trim().eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}

pub(super) async fn receive<F: Future<Output = ()>>(
    response: hyper::Response<Incoming>,
    q: &Qualification,
    p: &Profile,
    request: &Request,
    server: bool,
    idle: Duration,
    mut visible: impl FnMut(VisibleDelta) -> F,
) -> Result<Turn, Error> {
    let (head, mut body) = response.into_parts();
    if !head.status.is_success() {
        return Err(status(head.status.as_u16(), &head.headers));
    }
    let length = transport::framed_length(&head, BODY)?;
    media(&head.headers, request.stream)?;
    let mut total = 0;
    let mut bytes = Vec::new();
    let mut sse = stream::Sse::default();
    let mut responses = responses::Events::default();
    let mut state = Assembly::default();
    while let Some(frame) = timeout(idle, body.frame())
        .await
        .map_err(|_| Error::Timeout)?
    {
        let data = frame
            .map_err(|_| Error::Malformed)?
            .into_data()
            .map_err(|_| Error::Malformed)?;
        if data.len() > BODY - total {
            return Err(Error::Malformed);
        }
        total += data.len();
        if !request.stream {
            bytes.extend_from_slice(&data);
            continue;
        }
        for &b in &data {
            let Some(stream::Event { name, data: event }) = sse.byte(b)? else {
                continue;
            };
            if state.terminal {
                return Err(Error::Malformed);
            }
            if name.as_deref() == Some("error") {
                return Err(Error::Provider);
            }
            if q.protocol == Protocol::Chat && event == b"[DONE]" {
                state.terminal = true;
                continue;
            }
            let v = json::parse(&event)?;
            let deltas = match q.protocol {
                Protocol::Chat => chat::accept(&mut state, &v, true, q.tool_separator_whitespace)?,
                Protocol::Responses => {
                    if name
                        .as_deref()
                        .is_some_and(|n| n != "message" && v["type"] != n)
                    {
                        return Err(Error::Malformed);
                    }
                    responses.event(&mut state, &v)?
                }
            };
            for delta in deltas {
                visible(delta).await;
            }
        }
    }
    if length.is_some_and(|n| n != total as u64) || !sse.ended() {
        return Err(Error::Malformed);
    }
    if request.stream {
        return state.finish(q, p, request, server);
    }
    let v = json::parse(&bytes)?;
    match q.protocol {
        Protocol::Chat => chat::accept(&mut state, &v, false, false)?,
        Protocol::Responses => responses.complete(&mut state, &v)?,
    };
    state.finish(q, p, request, server)
}
