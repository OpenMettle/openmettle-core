use crate::model_config::{Catalog, Effective, Selection};
use crate::provider_http::{
    Trust,
    fixture::{self, Ca, Received, Reply, Server},
    inference::*,
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

pub const MODES: [(Protocol, bool); 4] = [
    (Protocol::Chat, false),
    (Protocol::Chat, true),
    (Protocol::Responses, false),
    (Protocol::Responses, true),
];
pub const TOKEN: &str = "canary-bearer-inference-19b";
pub const PROMPT: &str = "canary-prompt-inference-19b";
pub const ANSWER: &str = "canary-answer-inference-19b";
pub const THINK: &str = "canary-reason-inference-19b";
pub const ARG: &str = "canary-argument-inference-19b";
pub const ECHO: &str = "canary-echo-inference-19b";
pub const NORMAL: Timeouts = Timeouts {
    setup: Duration::from_secs(3),
    idle: Duration::from_secs(3),
    overall: Duration::from_secs(6),
};
pub fn path(p: Protocol) -> &'static str {
    if p == Protocol::Chat {
        "/v1/chat/completions"
    } else {
        "/v1/responses"
    }
}
pub fn catalog(p: Protocol, qualify: bool) -> Catalog {
    let mut doc: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let m = &mut doc["models"]["a"];
    let format = if p == Protocol::Chat {
        "reasoning_content"
    } else {
        "responses.reasoning"
    };
    m["pin"]["provider"] = if !qualify || p == Protocol::Chat {
        "synthetic-sglang"
    } else {
        "synthetic-external"
    }
    .into();
    m["reasoning_format"] = format.into();
    if qualify {
        m["replay"] = json!([{"source":{"format":format,"profile":m["pin"]},"max_tokens_per_byte":2,"fixed_tokens":7}]);
    }
    Catalog::load(&serde_json::to_vec(&doc).unwrap()).unwrap()
}
pub fn effective(c: &Catalog, explicit: bool) -> Effective {
    let mut sel = json!({"preset":"study"});
    if explicit {
        sel["layer"] = json!({"controls":{"reasoning_effort":"default"}});
    }
    c.resolve(
        &Selection::default(),
        &serde_json::from_value(sel).unwrap(),
        None,
        |_, _| true,
    )
    .unwrap()
}
pub fn tools() -> Vec<Tool> {
    ["left","right"].map(|name|Tool{name:name.into(),description:"Synthetic function".into(),parameters:json!({"type":"object","properties":{"v":{"type":"string"}},"required":["v"],"additionalProperties":false})}).into()
}
pub fn request(stream: bool) -> Request {
    Request {
        history: vec![History::User(PROMPT.into())],
        tools: Some(tools()),
        parallel: None,
        stream,
    }
}
pub struct Mock {
    pub server: Server,
    pub ca: Ca,
    pub captured: Arc<Mutex<Vec<Value>>>,
    pub protocol: Protocol,
}
impl Mock {
    pub async fn new(
        p: Protocol,
        script: impl Fn(&Received) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let ca = Ca::new();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let seen = captured.clone();
        let server = Server::start(ca.leaf(fixture::HOST, false), move |r| {
            if !r
                .head
                .starts_with(&format!("POST {} HTTP/1.1\r\n", path(p)))
            {
                return Reply::Bytes(fixture::response(404, &[], b""));
            }
            let auth: Vec<_> = r
                .head
                .lines()
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.trim())
                .collect();
            if auth != [format!("Bearer {TOKEN}")] {
                return Reply::Bytes(fixture::response(403, &[], ECHO.as_bytes()));
            }
            seen.lock()
                .unwrap()
                .push(serde_json::from_slice(&r.body).unwrap());
            script(r)
        })
        .await;
        Self {
            server,
            ca,
            captured,
            protocol: p,
        }
    }
    /// All DNS in the fixture leads to this peer. Inspect every observed request for a tool dispatch or a retry.
    pub fn assert_inference_only(&self, count: usize) {
        let heads = self.server.heads.lock().unwrap();
        assert_eq!(heads.len(), count);
        let expected = format!("POST {} HTTP/1.1\r\n", path(self.protocol));
        assert_eq!(
            heads
                .iter()
                .filter(|head| !head.starts_with(&expected))
                .count(),
            0
        );
    }
    pub fn gateway(&self, e: &Effective, time: Timeouts) -> Gateway {
        self.configured(e, time, |_| {})
    }
    pub fn configured(
        &self,
        e: &Effective,
        time: Timeouts,
        configure: impl FnOnce(&mut Qualification),
    ) -> Gateway {
        let mut q = Qualification {
            model: e.model.clone(),
            pin: e.profile.clone(),
            protocol: self.protocol,
            json: true,
            sse: true,
            functions: Some(SchemaSubset::Nested),
            images: false,
            parallel: true,
            usage: true,
            tool_separator_whitespace: true,
        };
        configure(&mut q);
        let mut g = Gateway::new(
            &format!(
                "https://{}:{}{}",
                fixture::HOST,
                self.server.port,
                path(self.protocol)
            ),
            Trust::Bundle(&self.ca.pem()),
            &[],
            q,
            time,
        )
        .unwrap();
        g.fixture_lookup(Arc::new(fixture::loopback));
        g
    }
}
pub fn event(v: Value) -> String {
    format!("data: {v}\r\n\r\n")
}
pub fn chunk(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend(data);
    out.extend(b"\r\n");
    out
}
pub fn sse_head() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: Text/Event-Stream; Charset=UTF-8\r\n\r\n".into()
}
pub fn sse(data: &str) -> Vec<u8> {
    let mut out = sse_head();
    // One payload byte per HTTP frame splits multibyte UTF-8, JSON tokens and CRLF.
    for b in data.as_bytes() {
        out.extend(chunk(std::slice::from_ref(b)));
    }
    out.extend(b"0\r\n\r\n");
    out
}
pub fn delta(msg: Value, reason: Value) -> String {
    event(json!({"choices":[{"index":0,"delta":msg,"finish_reason":reason}]}))
}
pub fn message(text: &str) -> Value {
    json!({"type":"message","id":"msg","role":"assistant","status":"completed","content":[{"type":"output_text","text":text}]})
}
pub fn function(id: &str, name: &str, args: &str) -> Value {
    json!({"type":"function_call","id":format!("item-{id}"),"call_id":id,"name":name,"arguments":args})
}
pub fn reasoning(text: &str) -> Value {
    json!({"type":"reasoning","id":"why","summary":[{"type":"summary_text","text":text}]})
}
pub fn completed(items: Vec<Value>) -> Value {
    json!({"status":"completed","output":items})
}
pub fn chat_json(msg: Value, reason: Value) -> Value {
    json!({"choices":[{"index":0,"message":msg,"finish_reason":reason}]})
}
pub fn wire(p: Protocol, stream: bool, msg: Value, reason: Value, items: Vec<Value>) -> Vec<u8> {
    match (p, stream) {
        (Protocol::Chat, false) => fixture::json(chat_json(msg, reason).to_string().as_bytes()),
        (Protocol::Chat, true) => sse(&(delta(msg, reason) + "data: [DONE]\r\n\r\n")),
        (Protocol::Responses, false) => fixture::json(completed(items).to_string().as_bytes()),
        (Protocol::Responses, true) => sse(&event(
            json!({"type":"response.completed","response":completed(items)}),
        )),
    }
}
pub async fn once(p: Protocol, stream: bool, bytes: Vec<u8>) -> Result<Turn, Error> {
    let c = catalog(p, true);
    let e = effective(&c, false);
    let mock = Mock::new(p, move |_| Reply::Bytes(bytes.clone())).await;
    let r = mock
        .gateway(&e, NORMAL)
        .caller(
            &c,
            &e,
            &request(stream),
            Credential::Bearer(TOKEN),
            |_| async {},
        )
        .await;
    mock.assert_inference_only(1);
    r
}

pub fn canary_turn(p: Protocol, stream: bool) -> Vec<u8> {
    let args = json!({"v":ARG}).to_string();
    let msg = json!({
        "role":"assistant","content":ANSWER,"reasoning_content":THINK,
        "tool_calls":[{"index":0,"type":"function","id":"c","function":{"name":"left","arguments":args}}]
    });
    wire(
        p,
        stream,
        msg,
        "tool_calls".into(),
        vec![
            reasoning(THINK),
            message(ANSWER),
            function("c", "left", &args),
        ],
    )
}
