//! Readers for the responses recorded from one real SGLang deployment on 23 Nov 2026
//! (`tests/fixtures/sglang-recorded/README.md`), shared by the decoder replay and the gateway
//! proxy tests.

pub(crate) const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/sglang-recorded"
);
/// The capture client gave up mid-stream; the recording has neither `[DONE]` nor usage.
pub(crate) const ABORTED: &str = "08-chat-stream-abort";

pub(crate) fn file(case: &str, ext: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{case}.{ext}")).unwrap()
}
/// Exact recorded body. Each body file carries one extra trailing LF for repository hygiene.
pub(crate) fn body(case: &str) -> Vec<u8> {
    let mut b = file(case, "body");
    assert_eq!(b.pop(), Some(b'\n'), "{case}: missing hygiene LF");
    b
}
/// Recorded status line and headers, stored with LF and sent with CRLF.
pub(crate) fn head(case: &str) -> String {
    String::from_utf8(file(case, "headers"))
        .unwrap()
        .replace('\n', "\r\n")
}
pub(crate) fn chunked(case: &str) -> bool {
    head(case)
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
}
/// The body split after each blank line that ends an SSE event. The recording de-chunked the
/// body, so original chunk boundaries are not preserved.
pub(crate) fn events(body: &[u8]) -> Vec<&[u8]> {
    let (mut events, mut rest) = (Vec::new(), body);
    while !rest.is_empty() {
        let end = rest
            .windows(2)
            .position(|w| w == b"\n\n")
            .map_or(rest.len(), |i| i + 2);
        let (event, tail) = rest.split_at(end);
        events.push(event);
        rest = tail;
    }
    events
}
