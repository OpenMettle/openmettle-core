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
    // Three previous keys are the most the ring holds besides the active one.
    let mut fixture = Fixture::new();
    fixture.document["gateway_keys"]["decrypt_only"] = json!((0..3)
        .map(|i| json!({"id": format!("old-{i}"), "path": fixture.dir.write(&format!("old-{i}"), &[i + 1; 32])}))
        .collect::<Vec<_>>());
    fixture.load().unwrap();
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
        "/gateway_keys",
        "/gateway_keys/active",
        "/gateway_keys/decrypt_only",
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
    for pointer in [
        "",
        "/gateway_keys",
        "/routes/a",
        "/routes/a/pin",
        "/routes/a/trust",
    ] {
        let mut document = fixture.document.clone();
        let target = document.pointer_mut(pointer).unwrap();
        target["unexpected"] = json!(true);
        let error = refusal(fixture.load_bytes(document.to_string().as_bytes()));
        assert_eq!(error, shape(Shape::UnknownField), "{pointer}");
    }
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

#[test]
fn routes_keep_the_transport_rules_and_bounded_timeouts() {
    let fixture = Fixture::new();
    for endpoint in [
        "http://gw.example.test:8443/v1/chat/completions",
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
fn gateway_ring_is_bounded_and_distinct() {
    let fixture = Fixture::new();
    let short = fixture.dir.write("short", &[7; 31]);
    let reused = fixture.document["gateway_keys"]["active"]["path"].clone();
    for (pointer, value) in [
        ("/gateway_keys/active/path", json!(short)),
        (
            "/gateway_keys/active/path",
            json!(fixture.dir.path("absent")),
        ),
        ("/gateway_keys/active/path", json!("gateway-key")),
        ("/gateway_keys/active/id", json!("gateway-a")),
        ("/gateway_keys/active/id", json!("not valid")),
        ("/gateway_keys/decrypt_only/0/path", reused),
    ] {
        assert_eq!(
            fixture.with(pointer, value),
            shape(Shape::GatewayKeyRing),
            "{pointer}"
        );
    }
    let four = json!((0..4)
        .map(|i| json!({"id": format!("old-{i}"), "path": fixture.dir.write(&format!("old-{i}"), &[i + 1; 32])}))
        .collect::<Vec<_>>());
    assert_eq!(
        fixture.with("/gateway_keys/decrypt_only", four),
        shape(Shape::GatewayKeyRing)
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
            "/gateway_keys/active/path",
            json!(fixture.dir.path("CANARY")),
        ),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(!text.contains(canary) && !text.contains("/"), "{text}");
        assert!(!format!("{error:?}").contains(canary));
    }
}
