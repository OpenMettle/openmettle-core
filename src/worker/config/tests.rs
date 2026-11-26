//! Inference document loader tests with real files in a per-test directory (ADR 0043). No
//! network, DNS or database.
use super::*;
use crate::{
    auth_config::tests::support::{self, Dir},
    provider_http::fixture::Ca,
};
use serde_json::json;

const CATALOG: &[u8] = include_bytes!("../../../tests/fixtures/conversation-catalog-v1.json");

struct Fixture {
    dir: Dir,
    document: Value,
}
impl Fixture {
    fn new() -> Self {
        let dir = Dir::new();
        let catalog: Value = serde_json::from_slice(CATALOG).unwrap();
        let document =
            support::inference_document(&dir, &catalog, &Ca::new().pem(), "gw.example.test:8443");
        Self { dir, document }
    }
    fn load_bytes(&self, bytes: &[u8]) -> Result<InferenceConfig, Error> {
        load(Path::new(&self.dir.write("inference.json", bytes)))
    }
    fn load(&self) -> Result<InferenceConfig, Error> {
        self.load_bytes(self.document.to_string().as_bytes())
    }
    /// The refusal after replacing the value at a JSON pointer.
    fn with(&self, pointer: &str, value: Value) -> Error {
        let mut document = self.document.clone();
        *document.pointer_mut(pointer).unwrap() = value;
        refusal(self.load_bytes(document.to_string().as_bytes()))
    }
    /// The refusal after removing the member at a JSON pointer.
    fn without(&self, pointer: &str) -> Error {
        let mut document = self.document.clone();
        let (parent, name) = pointer.rsplit_once('/').unwrap();
        let parent = document
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap();
        assert!(parent.remove(name).is_some(), "{pointer}");
        refusal(self.load_bytes(document.to_string().as_bytes()))
    }
    /// A catalog file changed by `edit`, named by the document.
    fn catalog(&mut self, edit: impl FnOnce(&mut Value)) {
        let mut catalog: Value = serde_json::from_slice(CATALOG).unwrap();
        edit(&mut catalog);
        let path = self
            .dir
            .write("edited-catalog.json", catalog.to_string().as_bytes());
        self.document["catalog_file"] = json!(path);
    }
}

fn refusal(result: Result<InferenceConfig, Error>) -> Error {
    match result {
        Ok(_) => panic!("document was accepted"),
        Err(error) => error,
    }
}

fn shape(error: Shape) -> Error {
    Error::Document(error)
}

#[test]
fn valid_document_routes_every_catalog_model_through_metered_gateways() {
    let mut fixture = Fixture::new();
    fixture.document["routes"]["b"]["stream"] = json!(true);
    fixture.document["routes"]["b"]["protocol"] = json!("responses");
    fixture.document["routes"]["b"]["trust"] = json!({"roots": "native"});
    fixture.document["routes"]["b"]["private_cidrs"] = json!(["10.20.0.0/16"]);
    let config = fixture.load().unwrap();
    assert_eq!(config.catalog.revision(), "catalog/1");
    let routes = &config.routes;
    assert_eq!(routes.installation, "00000000-0000-4000-8000-0000000000c1");
    let streams: Vec<_> = routes
        .models
        .iter()
        .map(|(m, (_, s))| (m.as_str(), *s))
        .collect();
    assert_eq!(streams, [("a", false), ("b", true)]);
}

/// Inside the cluster a route may reach the gateway over plain HTTP (ADR 0044). It then has no
/// TLS, so it names no trust anchors; every other transport rule still applies.
#[test]
fn a_route_may_use_plain_http_without_trust_anchors() {
    let mut fixture = Fixture::new();
    let route = &mut fixture.document["routes"]["a"];
    route["endpoint"] = json!("http://gw.example.test:8082/v1/chat/completions");
    route.as_object_mut().unwrap().remove("trust");
    route["private_cidrs"] = json!(["10.20.0.0/16"]);
    fixture.load().unwrap();
    // A plain route with trust anchors is not a TLS route: the member is unknown there.
    let mut anchored = fixture.document.clone();
    anchored["routes"]["a"]["trust"] = json!({"roots": "native"});
    assert_eq!(
        refusal(fixture.load_bytes(anchored.to_string().as_bytes())),
        shape(Shape::UnknownField)
    );
    for endpoint in [
        "http://10.0.0.1/v1/chat/completions",
        "http://localhost/v1/chat/completions",
        "http://gw.example.test:80/v1/chat/completions",
        "http://gw.example.test/v1/chat/completions?model=a",
        "http://user@gw.example.test/v1/chat/completions",
        "http://GW.example.test/v1/chat/completions",
    ] {
        assert_eq!(
            fixture.with("/routes/a/endpoint", json!(endpoint)),
            Error::Route,
            "{endpoint}"
        );
    }
    // Plain HTTP stays inside the cluster: a plain route must name the ranges of every
    // gateway address, so one without ranges is refused at start-up.
    assert_eq!(
        fixture.with("/routes/a/private_cidrs", json!([])),
        Error::PlainRange
    );
    // Every other scheme is refused, with trust anchors or without.
    let mut other = Fixture::new();
    for endpoint in ["ftp://gw.example.test/v1", "HTTP://gw.example.test/v1"] {
        assert_eq!(
            other.with("/routes/a/endpoint", json!(endpoint)),
            Error::Route,
            "{endpoint}"
        );
    }
    other.document["routes"]["a"]
        .as_object_mut()
        .unwrap()
        .remove("trust");
    assert_eq!(
        other.with("/routes/a/endpoint", json!("ftp://gw.example.test/v1")),
        shape(Shape::MissingField)
    );
}

#[test]
fn document_shape_is_strict() {
    let fixture = Fixture::new();
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/version", json!("1")),
        ("/version", Value::Null),
    ] {
        assert_eq!(
            fixture.with(pointer, value),
            shape(Shape::Version),
            "{pointer}"
        );
    }
    assert_eq!(fixture.without("/version"), shape(Shape::Version));
    for pointer in [
        "/catalog_file",
        "/installation",
        "/routes",
        "/routes/a/endpoint",
        "/routes/a/trust",
        "/routes/a/private_cidrs",
        "/routes/a/pin",
        "/routes/a/pin/gateway",
        "/routes/a/protocol",
        "/routes/a/stream",
        "/routes/a/images",
        "/routes/a/usage",
        "/routes/a/setup_timeout_milliseconds",
        "/routes/a/idle_timeout_milliseconds",
        "/routes/a/overall_timeout_milliseconds",
    ] {
        assert_eq!(
            fixture.without(pointer),
            shape(Shape::MissingField),
            "{pointer}"
        );
    }
    for pointer in ["", "/routes/a", "/routes/a/pin", "/routes/a/trust"] {
        let mut document = fixture.document.clone();
        let target = document.pointer_mut(pointer).unwrap();
        target["unexpected"] = json!(true);
        let error = refusal(fixture.load_bytes(document.to_string().as_bytes()));
        assert_eq!(error, shape(Shape::UnknownField), "{pointer}");
    }
    // The key ring ADR 0044 superseded is no longer a member: a document still carrying it is
    // refused rather than read or ignored.
    let mut ring = fixture.document.clone();
    ring["gateway_keys"] = json!({
        "active": {"id": "gateway-b", "path": fixture.dir.write("gateway-key-b", &[0xc2; 32])},
        "decrypt_only": []
    });
    assert_eq!(
        refusal(fixture.load_bytes(ring.to_string().as_bytes())),
        shape(Shape::UnknownField)
    );
    for (pointer, value) in [
        ("/routes", json!([])),
        ("/routes/a", json!("route")),
        ("/routes/a/protocol", json!("chat")),
        ("/routes/a/stream", json!("false")),
        ("/routes/a/usage", Value::Null),
        ("/routes/a/setup_timeout_milliseconds", json!(-1)),
        ("/routes/a/idle_timeout_milliseconds", json!("45000")),
        ("/routes/a/overall_timeout_milliseconds", json!(1.5)),
        ("/routes/a/private_cidrs", json!([10])),
        ("/routes/a/trust/roots", json!("system")),
        ("/routes/a/pin/runtime", json!(1)),
        ("/installation", json!(1)),
    ] {
        assert_eq!(
            fixture.with(pointer, value),
            shape(Shape::Field),
            "{pointer}"
        );
    }
    let text = fixture.document.to_string();
    let repeated = text.replacen("{\"catalog_file\"", "{\"version\":1,\"catalog_file\"", 1);
    assert_ne!(repeated, text);
    assert_eq!(
        refusal(fixture.load_bytes(repeated.as_bytes())),
        shape(Shape::DuplicateField)
    );
    assert_eq!(refusal(fixture.load_bytes(b"{")), shape(Shape::Json));
    assert_eq!(refusal(fixture.load_bytes(b"[]")), shape(Shape::Version));
    assert_eq!(
        refusal(load(Path::new("relative/inference.json"))),
        shape(Shape::Path)
    );
    assert_eq!(
        refusal(load(Path::new(&fixture.dir.path("absent.json")))),
        shape(Shape::ConfigFile)
    );
}

#[test]
fn installation_coverage_and_profiles_are_checked_against_the_catalog() {
    let fixture = Fixture::new();
    for installation in ["00000000-0000-4000-8000-0000000000C1", "installation", ""] {
        assert_eq!(
            fixture.with("/installation", json!(installation)),
            Error::Installation
        );
    }
    assert_eq!(fixture.without("/routes/b"), Error::Coverage);
    let extra = fixture.document["routes"]["a"].clone();
    assert_eq!(
        fixture.with(
            "/routes",
            json!({"a": extra, "b": extra.clone(), "c": extra})
        ),
        Error::Coverage
    );
    assert_eq!(
        fixture.with("/routes/a/pin/revision", json!("profile-a/2")),
        Error::Profile
    );
    // A route qualified for another model's profile is not this model's route.
    let other = fixture.document["routes"]["b"]["pin"].clone();
    assert_eq!(fixture.with("/routes/a/pin", other), Error::Profile);
    let mut device = Fixture::new();
    device.catalog(|c| c["models"]["b"]["requires_device_slot"] = json!(true));
    assert_eq!(refusal(device.load()), Error::DeviceSlot);
    let mut invalid = Fixture::new();
    invalid.catalog(|c| c["revision"] = json!(""));
    assert_eq!(refusal(invalid.load()), shape(Shape::Catalog));
    assert_eq!(
        fixture.with("/catalog_file", json!("catalog.json")),
        shape(Shape::Path)
    );
}

/// Repeated members cannot pick one of two catalog profiles or routes (ADR 0043).
#[test]
fn repeated_models_and_routes_are_refused() {
    let mut fixture = Fixture::new();
    let catalog: Value = serde_json::from_slice(CATALOG).unwrap();
    let mut other = catalog["models"]["a"].clone();
    other["pin"]["revision"] = json!("profile-a/2");
    let repeated = support::repeated(&catalog.to_string(), "models", "a", &other.to_string());
    fixture.document["catalog_file"] = json!(
        fixture
            .dir
            .write("repeated-catalog.json", repeated.as_bytes())
    );
    assert_eq!(refusal(fixture.load()), shape(Shape::Catalog));
    let fixture = Fixture::new();
    let route = fixture.document["routes"]["a"].to_string();
    let text = support::repeated(&fixture.document.to_string(), "routes", "a", &route);
    assert_eq!(
        refusal(fixture.load_bytes(text.as_bytes())),
        shape(Shape::DuplicateField)
    );
}

#[test]
fn routes_keep_the_transport_rules_and_bounded_timeouts() {
    let fixture = Fixture::new();
    for endpoint in [
        "https://10.0.0.1/v1/chat/completions",
        "https://localhost/v1/chat/completions",
        "https://gw.example.test/v1/chat/completions?model=a",
        "https://user@gw.example.test/v1/chat/completions",
        "https://GW.example.test/v1/chat/completions",
    ] {
        assert_eq!(
            fixture.with("/routes/a/endpoint", json!(endpoint)),
            Error::Route,
            "{endpoint}"
        );
    }
    for ranges in [
        json!(["10.0.0.1/8"]),
        json!(["8.8.8.0/24"]),
        json!(["127.0.0.0/8"]),
        json!(["10.0.0.0/08"]),
    ] {
        assert_eq!(
            fixture.with("/routes/a/private_cidrs", ranges.clone()),
            Error::Route,
            "{ranges}"
        );
    }
    let not_pem = fixture.dir.write("not-pem", b"not a certificate");
    assert_eq!(
        fixture.with(
            "/routes/a/trust",
            json!({"roots": "bundle", "bundle_path": not_pem})
        ),
        Error::Route
    );
    assert_eq!(
        fixture.with(
            "/routes/a/trust",
            json!({"roots": "bundle", "bundle_path": fixture.dir.path("absent.pem")})
        ),
        shape(Shape::TrustBundleFile)
    );
    let [setup, idle, overall] = [
        "/routes/a/setup_timeout_milliseconds",
        "/routes/a/idle_timeout_milliseconds",
        "/routes/a/overall_timeout_milliseconds",
    ];
    for (pointer, value) in [
        (setup, 99),
        (setup, 30_001),
        (idle, 999),
        (idle, 3_600_001),
        (overall, 999),
        (overall, 86_400_001),
        // Idle beyond the overall bound.
        (overall, 44_999),
    ] {
        assert_eq!(
            fixture.with(pointer, json!(value)),
            Error::Route,
            "{pointer}"
        );
    }
    let mut setup_beyond = fixture.document.clone();
    setup_beyond["routes"]["a"]["setup_timeout_milliseconds"] = json!(2000);
    setup_beyond["routes"]["a"]["idle_timeout_milliseconds"] = json!(1000);
    setup_beyond["routes"]["a"]["overall_timeout_milliseconds"] = json!(1500);
    assert_eq!(
        refusal(fixture.load_bytes(setup_beyond.to_string().as_bytes())),
        Error::Route
    );
}

#[test]
fn refusals_carry_no_configuration_values() {
    let fixture = Fixture::new();
    let canary = "CANARY";
    let errors = [
        fixture.with("/installation", json!(canary)),
        fixture.with(
            "/routes/a/endpoint",
            json!("https://canary.example.test/CANARY?CANARY"),
        ),
        fixture.with("/routes/a/private_cidrs", json!(["CANARY"])),
        fixture.with("/routes/a/pin/checkpoint", json!(canary)),
        fixture.with("/routes/a/protocol", json!(canary)),
        fixture.with("/catalog_file", json!(fixture.dir.path("CANARY"))),
        fixture.with(
            "/routes/a/endpoint",
            json!("http://canary.example.test/CANARY?CANARY"),
        ),
        {
            let mut plain = fixture.document.clone();
            let route = &mut plain["routes"]["a"];
            route["endpoint"] = json!("http://canary.example.test:8082/CANARY");
            route.as_object_mut().unwrap().remove("trust");
            refusal(fixture.load_bytes(plain.to_string().as_bytes()))
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(!text.contains(canary) && !text.contains("/"), "{text}");
        assert!(!format!("{error:?}").contains(canary));
    }
}

/// The gateway a loaded route holds sends over plain HTTP only with a committed round dispatch
/// (ADR 0044). Its ordinary caller path, with a bearer but no dispatch, is refused before name
/// resolution and before any connection, and nothing reaches the server.
#[tokio::test]
async fn a_plain_route_refuses_a_send_without_a_committed_dispatch() {
    use crate::{
        model_config::Selection,
        provider_http::inference::{Credential, History, Request},
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut fixture = Fixture::new();
    let route = &mut fixture.document["routes"]["a"];
    route["endpoint"] = json!(format!("http://gw.example.test:{port}/v1/chat/completions"));
    route.as_object_mut().unwrap().remove("trust");
    route["private_cidrs"] = json!(["10.20.0.0/16"]);
    let config = fixture.load().unwrap();
    let InferenceConfig {
        catalog, routes, ..
    } = config;
    let (gateway, _) = routes.models.into_iter().next().unwrap().1;
    let mut gateway = Arc::try_unwrap(gateway).ok().unwrap();
    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&lookups);
    gateway.fixture_lookup(Arc::new(move |_, _| {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))])
    }));
    let effective = catalog
        .resolve(
            &Selection::default(),
            &serde_json::from_value(json!({"preset": "study"})).unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let request = Request {
        history: vec![History::User("no dispatch".into())],
        tools: None,
        parallel: None,
        stream: false,
    };
    let sent = gateway
        .caller(
            &catalog,
            &effective,
            &request,
            Credential::Bearer("synthetic-bearer-without-a-dispatch"),
            |_| async {},
        )
        .await;
    assert!(sent.is_err());
    assert_eq!(
        lookups.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the refusal came after name resolution"
    );
    let reached = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(reached.is_err(), "the plain route reached the server");
}

#[test]
fn external_mcp_configuration_validates_transports_refresh_routes_and_contracts() {
    let mut fixture = Fixture::new();
    let ca_path = fixture.dir.write("mcp-ca.pem", &Ca::new().pem());
    let conn_id = "00000000-0000-4000-8000-000000004551";
    fixture.document["routes"]["a"]["functions"] = json!("flat");
    fixture.document["external_mcp"] = json!({
        "connections": {
            conn_id: {
                "endpoint": "https://mcp.vendor.example.test/mcp",
                "trust": { "roots": "bundle", "bundle_path": ca_path },
                "private_cidrs": ["10.20.0.0/16"],
                "setup_timeout_milliseconds": 2000,
                "idle_read_timeout_milliseconds": 5000,
                "call_timeout_milliseconds": 10000
            }
        },
        "refresh_routes": [{
            "provider_kind": "github",
            "allowed_origins": ["https://mcp.vendor.example.test"],
            "token_endpoint": "https://oauth.vendor.example.test/token",
            "trust": { "roots": "bundle", "bundle_path": ca_path },
            "private_cidrs": ["10.20.0.0/16"],
            "client_id": "synthetic-client",
            "setup_timeout_milliseconds": 2000,
            "total_timeout_milliseconds": 5000
        }],
        "tools": [{
            "tool_id": "gh_list_issues",
            "remote_name": "list_issues",
            "version": "1",
            "description": "List issues from synthetic MCP server",
            "input_schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["repo"],
                "properties": {
                    "repo": { "type": "string", "minLength": 1, "maxLength": 64 }
                }
            },
            "connection_id": conn_id,
            "account_id": "acct-1",
            "action": "issues.read",
            "resource_field": "repo",
            "fixed_resource": "default",
            "class": "read",
            "capability": "tool.github",
            "gate": "on_by_default",
            "tool_policy": "mcp.v1",
            "destination_policy": "synth.v1",
            "endpoint_id": "gh-mcp",
            "endpoint_version": "1",
            "authoritative_lookup": false,
            "semantic_errors_are_side_effect_free": true,
            "reconcile": {
                "lookup_tool": "lookup_issue",
                "lookup_scope": "issues.read",
                "handle_argument": "handle",
                "status_field": "status"
            },
            "call_timeout_milliseconds": 5000
        }]
    });
    let loaded = fixture.load().unwrap();
    let ext = loaded
        .external_mcp
        .expect("external_mcp runtime config loaded");
    assert!(ext.transports.contains_key(conn_id));
    assert!(ext.refresh_registry.is_some());
    assert!(ext.registry.get("gh_list_issues", "1").is_some());

    // Invalid reconcile lookup_scope, unknown connection_id, or plain http MCP endpoint fail closed.
    assert_eq!(
        fixture.with(
            "/external_mcp/tools/0/reconcile/lookup_scope",
            json!("INVALID SCOPE")
        ),
        Error::ExternalMcp
    );
    assert_eq!(
        fixture.with(
            "/external_mcp/tools/0/connection_id",
            json!("00000000-0000-4000-8000-000000009999")
        ),
        Error::ExternalMcp
    );
    assert_eq!(
        fixture.with(
            &format!("/external_mcp/connections/{conn_id}/endpoint"),
            json!("http://mcp.vendor.example.test/mcp")
        ),
        Error::ExternalMcp
    );
}
