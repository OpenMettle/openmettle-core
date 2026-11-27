//! Test-only HTTP/1.1 OTLP delay relay for `tests/telemetry_kind/qualify.py`.
//!
//! Forwards Alloy `otelcol.exporter.otlphttp` requests to Prometheus with 0 ms overhead during
//! normal operation, and supports arming a single one-shot delay matched on a specific
//! `service.instance.id` UUID inside an uncompressed OTLP/HTTP protobuf body to prove live
//! serialized downstream delivery (`sending_queue { num_consumers = 1 }`).
//!
//! Zero external crates, zero `unsafe`. Never shipped in production images.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_DELAY_MS: u64 = 10_000;
const IO_TIMEOUT: Duration = Duration::from_secs(15);

struct State {
    upstream: String,
    armed: Mutex<Option<(u64, Vec<u8>)>>,
    forwarded: AtomicU64,
    delayed: AtomicU64,
    status_4xx: AtomicU64,
}

struct HttpMessage {
    start_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn main() {
    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:9091".to_owned());
    let upstream = std::env::var("UPSTREAM_ADDR").unwrap_or_else(|_| {
        "prometheus.openmettle-qualification-telemetry.svc.cluster.local:9090".to_owned()
    });
    let listener = TcpListener::bind(&bind).unwrap_or_else(|err| {
        eprintln!("otlp-delay-relay: failed to bind {bind}: {err}");
        std::process::exit(1);
    });
    eprintln!("otlp-delay-relay: listening on {bind}, forwarding to {upstream}");

    let state = Arc::new(State {
        upstream,
        armed: Mutex::new(None),
        forwarded: AtomicU64::new(0),
        delayed: AtomicU64::new(0),
        status_4xx: AtomicU64::new(0),
    });

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || handle_client(stream, &state));
            }
            Err(err) => {
                eprintln!("otlp-delay-relay: accept error: {err}");
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, state: &State) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_nodelay(true);

    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(read_half);
    let req = match read_http_message(&mut reader, Some(&mut stream), false) {
        Ok(Some(msg)) => msg,
        Ok(None) => return,
        Err(err) => {
            let _ = write_simple(&mut stream, "400 Bad Request", "text/plain", &format!("{err}\n"));
            return;
        }
    };

    let mut parts = req.start_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };

    match (method, path) {
        ("GET", "/healthz") => {
            let _ = write_simple(&mut stream, "200 OK", "text/plain", "ok\n");
        }
        ("GET", "/stats") => {
            let armed_ms = state
                .armed
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|(ms, _)| *ms))
                .unwrap_or(0);
            let json = format!(
                "{{\"forwarded\":{},\"delayed\":{},\"armed_ms\":{},\"status_4xx\":{}}}\n",
                state.forwarded.load(Ordering::Relaxed),
                state.delayed.load(Ordering::Relaxed),
                armed_ms,
                state.status_4xx.load(Ordering::Relaxed),
            );
            let _ = write_simple(&mut stream, "200 OK", "application/json", &json);
        }
        ("POST", "/arm-delay") => {
            let mut delay_ms: u64 = 1500;
            let mut needle = Vec::new();
            if let Some(q) = query {
                for pair in q.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        match k {
                            "ms" => {
                                if let Ok(parsed) = v.parse::<u64>() {
                                    delay_ms = parsed.min(MAX_DELAY_MS);
                                }
                            }
                            "match" => {
                                needle = v.as_bytes().to_vec();
                            }
                            _ => {}
                        }
                    }
                }
            }
            if let Ok(mut guard) = state.armed.lock() {
                *guard = if delay_ms > 0 {
                    Some((delay_ms, needle))
                } else {
                    None
                };
            }
            let _ = write_simple(&mut stream, "200 OK", "text/plain", "armed\n");
        }
        _ => forward_to_upstream(&mut stream, &req, method, target, state),
    }
}

fn forward_to_upstream(
    client: &mut TcpStream,
    req: &HttpMessage,
    method: &str,
    target: &str,
    state: &State,
) {
    let maybe_delay = {
        let mut guard = state.armed.lock().unwrap_or_else(|e| e.into_inner());
        let matches = guard
            .as_ref()
            .is_some_and(|(_, needle)| needle.is_empty() || contains_subslice(&req.body, needle));
        if matches {
            guard.take().map(|(ms, _)| ms)
        } else {
            None
        }
    };

    if let Some(ms) = maybe_delay {
        state.delayed.fetch_add(1, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(ms));
    }

    let mut upstream = match TcpStream::connect(&state.upstream) {
        Ok(s) => s,
        Err(err) => {
            let _ = write_simple(
                client,
                "502 Bad Gateway",
                "text/plain",
                &format!("upstream connect failed: {err}\n"),
            );
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(IO_TIMEOUT));
    let _ = upstream.set_nodelay(true);

    let mut out = format!("{method} {target} HTTP/1.1\r\n");
    out.push_str(&format!("Host: {}\r\n", state.upstream));
    for (k, v) in &req.headers {
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "expect"
        ) {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    out.push_str("Connection: close\r\n\r\n");

    if upstream.write_all(out.as_bytes()).is_err()
        || upstream.write_all(&req.body).is_err()
        || upstream.flush().is_err()
    {
        let _ = write_simple(client, "502 Bad Gateway", "text/plain", "upstream write failed\n");
        return;
    }

    let mut up_reader = BufReader::new(upstream);
    let resp = match read_http_message(&mut up_reader, None, true) {
        Ok(Some(msg)) => msg,
        _ => {
            let _ = write_simple(client, "502 Bad Gateway", "text/plain", "upstream read failed\n");
            return;
        }
    };

    state.forwarded.fetch_add(1, Ordering::Relaxed);
    if let Some(code) = resp
        .start_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        && (400..500).contains(&code)
    {
        state.status_4xx.fetch_add(1, Ordering::Relaxed);
    }

    let mut resp_head = format!("{}\r\n", resp.start_line);
    for (k, v) in &resp.headers {
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "content-length"
        ) {
            continue;
        }
        resp_head.push_str(&format!("{k}: {v}\r\n"));
    }
    resp_head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    resp_head.push_str("Connection: close\r\n\r\n");

    let _ = client.write_all(resp_head.as_bytes());
    let _ = client.write_all(&resp.body);
    let _ = client.flush();
}

fn read_http_message<R: BufRead>(
    reader: &mut R,
    continue_writer: Option<&mut TcpStream>,
    read_to_eof_if_unsized: bool,
) -> io::Result<Option<HttpMessage>> {
    let mut start_line = String::new();
    let n = read_line_bounded(reader, &mut start_line, MAX_HEADER_BYTES)?;
    if n == 0 {
        return Ok(None);
    }
    let start_line = trim_crlf(&start_line).to_owned();
    let mut header_bytes = n;
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut expect_continue = false;

    loop {
        let mut line = String::new();
        let read = read_line_bounded(reader, &mut line, MAX_HEADER_BYTES - header_bytes)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof before end of headers",
            ));
        }
        header_bytes += read;
        let trimmed = trim_crlf(&line);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_owned();
            let val = v.trim().to_owned();
            let lower = key.to_ascii_lowercase();
            if lower == "content-length" {
                content_length = val.parse::<usize>().ok();
            } else if lower == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if lower == "expect" && val.eq_ignore_ascii_case("100-continue") {
                expect_continue = true;
            }
            headers.push((key, val));
        }
    }

    if expect_continue
        && let Some(writer) = continue_writer
    {
        writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        writer.flush()?;
    }

    let body = if chunked {
        read_chunked_body(reader)?
    } else if let Some(len) = content_length {
        if len > MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "body exceeds limit",
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        buf
    } else if read_to_eof_if_unsized {
        let mut buf = Vec::new();
        reader
            .take((MAX_BODY_BYTES + 1) as u64)
            .read_to_end(&mut buf)?;
        if buf.len() > MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response body exceeds limit",
            ));
        }
        buf
    } else {
        Vec::new()
    };

    Ok(Some(HttpMessage {
        start_line,
        headers,
        body,
    }))
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if read_line_bounded(reader, &mut size_line, 1024)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof in chunk size",
            ));
        }
        let hex = trim_crlf(&size_line)
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            // Drain trailer lines until empty line.
            loop {
                let mut trailer = String::new();
                if read_line_bounded(reader, &mut trailer, 4096)? == 0 {
                    break;
                }
                if trim_crlf(&trailer).is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body exceeds limit",
            ));
        }
        let start = out.len();
        out.resize(start + size, 0);
        reader.read_exact(&mut out[start..])?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    Ok(out)
}

fn read_line_bounded<R: BufRead>(reader: &mut R, out: &mut String, limit: usize) -> io::Result<usize> {
    let mut total = 0usize;
    let mut raw = Vec::new();
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if total + take > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header line exceeds limit",
                ));
            }
            raw.extend_from_slice(&buf[..take]);
            reader.consume(take);
            total += take;
            break;
        }
        let len = buf.len();
        if total + len > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header line exceeds limit",
            ));
        }
        raw.extend_from_slice(buf);
        reader.consume(len);
        total += len;
    }
    *out = String::from_utf8_lossy(&raw).into_owned();
    Ok(total)
}

fn trim_crlf(s: &str) -> &str {
    s.trim_end_matches(['\r', '\n'])
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn write_simple(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}
