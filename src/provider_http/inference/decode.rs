use super::{turn::Assembly, *};
use crate::model_config::Profile;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::time::timeout;

fn retry_delay(headers: &HeaderMap) -> Option<u32> {
    let mut values = headers.get_all(header::RETRY_AFTER).iter();
    let s = values.next()?.to_str().ok()?;
    if values.next().is_some() || s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| *n <= 86400)
}

fn status(code: u16, headers: &HeaderMap) -> Error {
    match code {
        429 => Error::RateLimited(retry_delay(headers)),
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

fn classify_io_kind(kind: std::io::ErrorKind) -> Error {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::InvalidData | ErrorKind::InvalidInput => Error::Malformed,
        ErrorKind::UnexpectedEof
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::NotConnected
        | ErrorKind::NetworkDown
        | ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable
        | ErrorKind::TimedOut
        | ErrorKind::Interrupted => Error::Incomplete,
        _ => Error::Malformed,
    }
}

fn body_error(e: &hyper::Error) -> Error {
    if e.is_parse() {
        return Error::Malformed;
    }
    let mut src = std::error::Error::source(e);
    while let Some(err) = src {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return classify_io_kind(io.kind());
        }
        src = err.source();
    }
    if e.is_incomplete_message() || e.is_closed() || e.is_canceled() || e.is_body_write_aborted() {
        Error::Incomplete
    } else {
        Error::Malformed
    }
}

pub(super) async fn receive<F: Future<Output = ()>>(
    response: hyper::Response<Incoming>,
    gateway: &Gateway,
    p: &Profile,
    request: &Request,
    server: bool,
    mut visible: impl FnMut(VisibleDelta) -> F,
    metric: &crate::provider_http::ProviderMetricSlot,
) -> Result<Turn, Error> {
    use crate::telemetry::metrics::ProviderOutcome;

    let q = &gateway.qualification;
    let idle = gateway.timeouts.idle;
    let (head, mut body) = response.into_parts();
    if !head.status.is_success() {
        metric.finish(ProviderOutcome::HttpError);
        return Err(status(head.status.as_u16(), &head.headers));
    }
    if head.status != hyper::StatusCode::OK {
        metric.finish(ProviderOutcome::HttpError);
        return Err(Error::Malformed);
    }
    let length = transport::framed_length(&head, BODY).map_err(|err| {
        metric.finish(crate::provider_http::provider_error_outcome(err));
        Error::from(err)
    })?;
    media(&head.headers, request.stream)?;
    let mut total = 0;
    let mut bytes = Vec::new();
    let mut sse = stream::Sse::default();
    let mut responses = responses::Events::default();
    let mut state = Assembly::default();
    while let Some(frame) = timeout(idle, body.frame()).await.map_err(|_| {
        metric.finish(ProviderOutcome::Timeout);
        Error::Timeout
    })? {
        let data = frame
            .map_err(|e| body_error(&e))?
            .into_data()
            .map_err(|_| Error::Malformed)?;
        if data.len() > BODY - total {
            metric.finish(ProviderOutcome::BodyLimit);
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
    if length.is_some_and(|n| n != total as u64) {
        return Err(Error::Incomplete);
    }
    if !sse.ended() {
        return Err(if state.terminal {
            Error::Malformed
        } else {
            Error::Incomplete
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn io_interruption_kinds_including_network_loss_map_to_incomplete() {
        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
            ErrorKind::NetworkDown,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
        ] {
            assert_eq!(classify_io_kind(kind), Error::Incomplete, "{kind:?}");
        }
        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert_eq!(classify_io_kind(kind), Error::Malformed, "{kind:?}");
        }
    }
}
