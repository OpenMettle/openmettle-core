//! Loader tests with real files in a per-test temporary directory. No network or database.
use super::*;
use crate::provider_http::fixture::Ca;
use serde_json::json;
use std::{os::unix::fs::symlink, process::Command};

#[path = "../../tests/auth_config_support/mod.rs"]
mod support;
use support::Dir;

struct Fixture {
    dir: Dir,
    document: Value,
}
impl Fixture {
    fn new() -> Self {
        let dir = Dir::new();
        let document = support::document(&dir, &Ca::new().pem());
        Self { dir, document }
    }
    fn load(&self) -> Result<AuthConfig, Error> {
        self.load_bytes(self.document.to_string().as_bytes())
    }
    fn load_bytes(&self, bytes: &[u8]) -> Result<AuthConfig, Error> {
        load(Path::new(&self.dir.write("auth.json", bytes)))
    }
    /// The refusal after replacing the value at a JSON pointer.
    fn with(&self, pointer: &str, value: Value) -> Error {
        let mut document = self.document.clone();
        *document.pointer_mut(pointer).unwrap() = value;
        refusal(self.load_bytes(document.to_string().as_bytes()))
    }
    fn set(&mut self, pointer: &str, value: Value) {
        *self.document.pointer_mut(pointer).unwrap() = value;
    }
    fn fifo(&self, name: &str) -> String {
        let path = self.dir.path(name);
        assert!(
            Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        path
    }
}
fn refusal(result: Result<AuthConfig, Error>) -> Error {
    result.expect_err("configuration must be refused")
}

#[test]
fn valid_document_becomes_reusable_state_without_touching_files() {
    let fixture = Fixture::new();
    let before = std::fs::read_dir(fixture.dir.path("")).unwrap().count();
    let config = fixture.load().unwrap();
    assert_eq!(config.providers().len(), 1);
    assert_eq!(config.login_lifetime(), Duration::from_secs(300));
    assert_eq!(
        *config.token_policy(),
        auth::Policy::new(Duration::from_secs(301), Duration::from_secs(60)).unwrap()
    );
    // The loaded state and its handles show no key, endpoint or path when debug-printed.
    assert_eq!(
        format!("{config:?} {:?} {:?}", config.keys(), config.providers()[0]),
        "AuthConfig(..) KeyRing(..) ManagedProvider(..)"
    );
    // Units follow the field names: seconds for lifetimes, milliseconds for deadlines.
    assert_eq!(
        format!("{:?}", config.session_policy()),
        "Policy { lifetime_ms: 28800000, retained_limit: 16, deadline: 5.001s }"
    );
    // One more entry: the document this test wrote. Loading creates nothing.
    assert_eq!(
        std::fs::read_dir(fixture.dir.path("")).unwrap().count(),
        before + 1
    );
    assert_eq!(
        std::fs::read(fixture.dir.path("login-key-b")).unwrap(),
        [0xb1; 32]
    );
    // Limits are inclusive, and an empty decrypt-only list is a complete key ring.
    let mut fixture = fixture;
    fixture.set("/login/lifetime_seconds", json!(600));
    fixture.set("/login/keys/decrypt_only", json!([]));
    fixture.set("/providers/0/private_cidrs", json!([]));
    assert!(fixture.load().is_ok());
}

#[test]
fn projected_volume_symlinks_resolve_to_regular_files() {
    let mut fixture = Fixture::new();
    // Kubernetes layout: name -> ..data/name, ..data -> timestamped directory.
    std::fs::create_dir(fixture.dir.path("..2026_11_17")).unwrap();
    symlink("..2026_11_17", fixture.dir.path("..data")).unwrap();
    for (name, pointer) in [
        ("login-key-b", "/login/keys/active/path"),
        ("provider-ca", "/providers/0/trust/bundle_path"),
    ] {
        std::fs::rename(
            fixture.dir.path(name),
            fixture.dir.path(&format!("..2026_11_17/{name}")),
        )
        .unwrap();
        symlink(format!("..data/{name}"), fixture.dir.path(name)).unwrap();
        assert_eq!(
            fixture.document.pointer(pointer).unwrap(),
            &json!(fixture.dir.path(name))
        );
    }
    std::fs::write(
        fixture.dir.path("..2026_11_17/auth.json"),
        fixture.document.to_string(),
    )
    .unwrap();
    symlink("..data/auth.json", fixture.dir.path("linked.json")).unwrap();
    assert!(load(Path::new(&fixture.dir.path("linked.json"))).is_ok());

    // A link is only as good as its target.
    symlink("..data", fixture.dir.path("to-directory")).unwrap();
    symlink("..data/absent", fixture.dir.path("dangling")).unwrap();
    for name in ["to-directory", "dangling"] {
        assert_eq!(
            refusal(load(Path::new(&fixture.dir.path(name)))),
            Error::ConfigFile
        );
        fixture.set("/login/keys/active/path", json!(fixture.dir.path(name)));
        assert_eq!(refusal(fixture.load()), Error::KeyFile);
    }
}

#[test]
fn non_regular_relative_and_oversized_files_are_refused() {
    let fixture = Fixture::new();
    let directory = fixture.dir.path("");
    let absent = fixture.dir.path("absent");
    // A FIFO would block forever if it were opened; it is refused from its metadata.
    let fifo = fixture.fifo("fifo");
    for (path, expected) in [
        ("auth.json", Error::Path),
        (directory.as_str(), Error::ConfigFile),
        (absent.as_str(), Error::ConfigFile),
        (fifo.as_str(), Error::ConfigFile),
    ] {
        assert_eq!(refusal(load(Path::new(path))), expected);
    }
    for (pointer, expected) in [
        ("/login/keys/active/path", Error::KeyFile),
        ("/login/keys/decrypt_only/0/path", Error::KeyFile),
        ("/providers/0/trust/bundle_path", Error::TrustBundleFile),
    ] {
        assert_eq!(fixture.with(pointer, json!("relative/file")), Error::Path);
        for path in [&directory, &absent, &fifo] {
            assert_eq!(fixture.with(pointer, json!(path)), expected);
        }
    }

    // Real file lengths. The document bound is inclusive and applies before parsing.
    let mut padded = fixture.document.to_string().into_bytes();
    padded.resize(MAX_CONFIG_BYTES, b' ');
    assert!(fixture.load_bytes(&padded).is_ok());
    padded.push(b' ');
    assert_eq!(refusal(fixture.load_bytes(&padded)), Error::ConfigFile);

    // Exactly 32 raw bytes: no shorter key, trailing newline or text encoding.
    for length in [0, 31, 33, 44, 64] {
        let path = fixture.dir.write("sized-key", &vec![0xc2; length]);
        assert_eq!(
            fixture.with("/login/keys/active/path", json!(path)),
            Error::KeyFile
        );
    }
    let path = fixture.dir.write("sized-key", &[0xc2; KEY_BYTES]);
    let mut exact = fixture.document.clone();
    exact["login"]["keys"]["active"]["path"] = json!(path);
    assert!(fixture.load_bytes(exact.to_string().as_bytes()).is_ok());

    // The transport's ceiling bounds the read; its constructor still judges the contents.
    let pointer = "/providers/0/trust/bundle_path";
    let path = fixture
        .dir
        .write("large-ca", &vec![b'x'; MAX_TRUST_BUNDLE_BYTES + 1]);
    assert_eq!(fixture.with(pointer, json!(path)), Error::TrustBundleFile);
    let path = fixture
        .dir
        .write("large-ca", &vec![b'x'; MAX_TRUST_BUNDLE_BYTES]);
    assert_eq!(fixture.with(pointer, json!(path)), Error::Provider);
    let path = fixture.dir.write("empty-ca", b"");
    assert_eq!(fixture.with(pointer, json!(path)), Error::Provider);
}

/// Pointers to every object in the valid document.
const OBJECTS: [&str; 10] = [
    "",
    "/login",
    "/login/keys",
    "/login/keys/active",
    "/login/keys/decrypt_only/0",
    "/id_token",
    "/provider_refresh",
    "/session",
    "/providers/0",
    "/providers/0/trust",
];

#[test]
fn unknown_and_missing_fields_are_refused_in_every_object() {
    let fixture = Fixture::new();
    let mut fields = 0;
    for pointer in OBJECTS {
        let mut document = fixture.document.clone();
        let object = document
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap();
        object.insert("extra".into(), json!("synthetic-secret"));
        assert_eq!(
            refusal(fixture.load_bytes(document.to_string().as_bytes())),
            Error::UnknownField,
            "{pointer}"
        );
        let names: Vec<String> = fixture
            .document
            .pointer(pointer)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for name in names {
            let mut document = fixture.document.clone();
            let object = document
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap();
            object.remove(&name);
            let expected = if name == "version" {
                Error::Version
            } else {
                Error::MissingField
            };
            assert_eq!(
                refusal(fixture.load_bytes(document.to_string().as_bytes())),
                expected,
                "{pointer}/{name}"
            );
            fields += 1;
        }
    }
    // Every operational input in the version-1 shape is required: none has a default.
    assert_eq!(fields, 39);
    // Native roots take no bundle path.
    let mut native = fixture.document.clone();
    native["providers"][0]["trust"]["roots"] = json!("native");
    assert_eq!(
        refusal(fixture.load_bytes(native.to_string().as_bytes())),
        Error::UnknownField
    );
}

#[test]
fn duplicate_fields_are_refused_in_every_object() {
    let fixture = Fixture::new();
    let text = fixture.document.to_string();
    for member in [
        r#""version":1"#,
        r#""lifetime_seconds":300"#,
        r#""decrypt_only":["#,
        r#""id":"login-b""#,
        r#""id":"login-a""#,
        r#""future_skew_seconds":60"#,
        r#""cooldown_seconds":61"#,
        r#""retained_per_user":16"#,
        r#""revision":"r1""#,
        r#""roots":"bundle""#,
    ] {
        assert_eq!(text.matches(member).count(), 1, "{member}");
        // `"name":value` becomes `"name":value,"name":value`; an opened array is closed first.
        let repeated = if member.ends_with('[') {
            text.replacen(member, &format!("{member}],{member}"), 1)
        } else {
            text.replacen(member, &format!("{member},{member}"), 1)
        };
        assert_eq!(
            refusal(fixture.load_bytes(repeated.as_bytes())),
            Error::DuplicateField,
            "{member}"
        );
    }
    // A repeated unknown member is refused as well.
    let repeated = text.replacen('{', r#"{"extra":1,"extra":1,"#, 1);
    assert_eq!(
        refusal(fixture.load_bytes(repeated.as_bytes())),
        Error::DuplicateField
    );
}

#[test]
fn version_json_and_field_types_are_strict() {
    let fixture = Fixture::new();
    for version in [
        json!(0),
        json!(2),
        json!("1"),
        json!(1.0),
        json!(null),
        json!([1]),
    ] {
        assert_eq!(fixture.with("/version", version), Error::Version);
    }
    for (bytes, expected) in [
        // A later version is reported as such, not as unknown fields.
        (&br#"{"version":2,"anything":true}"#[..], Error::Version),
        (b"{}", Error::Version),
        (b"[1]", Error::Version),
        (b"1", Error::Version),
        (b"", Error::Json),
        (b"{", Error::Json),
        (br#"{"version":1}x"#, Error::Json),
        (b"\xef\xbb\xbf{}", Error::Json),
        (b"{\"version\":\"\xff\"}", Error::Json),
        (br#"{"version":1e999}"#, Error::Json),
        // Beyond serde_json's nesting limit.
        (
            format!("{}{}", "[".repeat(200), "]".repeat(200)).as_bytes(),
            Error::Json,
        ),
    ] {
        assert_eq!(refusal(fixture.load_bytes(bytes)), expected);
    }
    // Integers are plain non-negative JSON integers with the unit in the field name.
    for pointer in [
        "/login/lifetime_seconds",
        "/id_token/future_skew_seconds",
        "/provider_refresh/deadline_milliseconds",
        "/provider_refresh/max_callers",
        "/session/retained_per_user",
    ] {
        for value in [
            json!("300"),
            json!(300.0),
            json!(-1),
            json!(null),
            json!([300]),
        ] {
            assert_eq!(fixture.with(pointer, value), Error::Field, "{pointer}");
        }
    }
    for pointer in [
        "/login/keys/active/id",
        "/login/keys/active/path",
        "/providers/0/issuer",
        "/providers/0/private_cidrs/0",
        "/providers/0/trust/roots",
        "/providers/0/trust/bundle_path",
    ] {
        for value in [json!(1), json!(null), json!(["x"]), json!({})] {
            assert_eq!(fixture.with(pointer, value), Error::Field, "{pointer}");
        }
    }
    // Objects are never positional arrays, and arrays are never objects or scalars.
    for (pointer, value) in [
        ("/id_token", json!([301, 60])),
        ("/login", json!(null)),
        ("/login/keys/active", json!(["login-b", "/synthetic/path"])),
        ("/login/keys/decrypt_only", json!({})),
        ("/login/keys/decrypt_only/0", json!("login-a")),
        ("/providers", json!({})),
        ("/providers/0", json!("synthetic")),
        ("/providers/0/private_cidrs", json!("10.20.0.0/16")),
        ("/providers/0/trust", json!("native")),
        ("/providers/0/trust/roots", json!("system")),
    ] {
        assert_eq!(fixture.with(pointer, value), Error::Field, "{pointer}");
    }
}

#[test]
fn policies_are_judged_by_their_existing_constructors() {
    let fixture = Fixture::new();
    for (pointer, values, expected) in [
        (
            "/login/lifetime_seconds",
            vec![0, 601, u64::MAX],
            Error::LoginLifetime,
        ),
        (
            "/id_token/max_issued_at_age_seconds",
            vec![0, 60, 3601],
            Error::TokenPolicy,
        ),
        (
            "/id_token/future_skew_seconds",
            vec![301, u64::MAX],
            Error::TokenPolicy,
        ),
        (
            "/provider_refresh/freshness_seconds",
            vec![0, 86401],
            Error::RefreshPolicy,
        ),
        (
            "/provider_refresh/cooldown_seconds",
            vec![0, 3601],
            Error::RefreshPolicy,
        ),
        (
            "/provider_refresh/deadline_milliseconds",
            vec![9, 60001],
            Error::RefreshPolicy,
        ),
        (
            "/provider_refresh/max_providers",
            vec![0, 65, u64::MAX],
            Error::RefreshPolicy,
        ),
        (
            "/provider_refresh/max_callers",
            vec![0, 1025],
            Error::RefreshPolicy,
        ),
        (
            "/provider_refresh/max_document_gets",
            vec![0, 65],
            Error::RefreshPolicy,
        ),
        (
            "/session/lifetime_seconds",
            vec![0, 86401],
            Error::SessionPolicy,
        ),
        (
            "/session/retained_per_user",
            vec![0, 1025, u64::MAX],
            Error::SessionPolicy,
        ),
        (
            "/session/deadline_milliseconds",
            vec![9, 60001],
            Error::SessionPolicy,
        ),
    ] {
        for value in values {
            assert_eq!(
                fixture.with(pointer, json!(value)),
                expected,
                "{pointer} {value}"
            );
        }
    }
}

#[test]
fn login_keys_are_ordered_bounded_and_distinct() {
    let mut fixture = Fixture::new();
    let key = |id: &str, name: &str| KeyFile {
        id: id.into(),
        path: fixture.dir.path(name),
    };
    // Active first, then decrypt-only keys in document order, regardless of name order.
    assert_eq!(
        key_material(
            &key("login-b", "login-key-b"),
            &[key("login-a", "login-key-a")]
        )
        .unwrap(),
        [
            ("login-b".to_owned(), [0xb1; 32]),
            ("login-a".to_owned(), [0xa0; 32])
        ]
    );
    assert_eq!(
        key_material(
            &key("login-a", "login-key-a"),
            &[key("login-b", "login-key-b")]
        )
        .unwrap(),
        [
            ("login-a".to_owned(), [0xa0; 32]),
            ("login-b".to_owned(), [0xb1; 32])
        ]
    );

    let entry = |id: &str, path: &str| json!({"id": id, "path": path});
    let (active, old) = (
        fixture.dir.path("login-key-b"),
        fixture.dir.path("login-key-a"),
    );
    let more: Vec<String> = (2..=3u8)
        .map(|i| fixture.dir.write(&format!("login-key-{i}"), &[i; 32]))
        .collect();
    // One active key and three decrypt-only keys is the largest ring.
    fixture.set(
        "/login/keys/decrypt_only",
        json!([
            entry("login-a", &old),
            entry("login-2", &more[0]),
            entry("login-3", &more[1])
        ]),
    );
    assert!(fixture.load().is_ok());
    // A fourth is refused from the count alone: none of these files exists.
    let absent = fixture.dir.path("absent");
    let four: Vec<Value> = (0..4)
        .map(|i| entry(&format!("old-{i}"), &absent))
        .collect();
    assert_eq!(
        fixture.with("/login/keys/decrypt_only", json!(four)),
        Error::KeyRing
    );
    for decrypt_only in [
        // Repeated identifier, repeated material under another identifier, invalid identifier.
        json!([entry("login-b", &old)]),
        json!([entry("login-a", &active)]),
        json!([entry("bad id", &old)]),
        json!([entry("", &old)]),
    ] {
        assert_eq!(
            fixture.with("/login/keys/decrypt_only", decrypt_only),
            Error::KeyRing
        );
    }
}

#[test]
fn providers_are_bounded_unique_and_judged_by_managed_constructors() {
    let mut fixture = Fixture::new();
    let first = fixture.document["providers"][0].clone();
    let other = |id: &str| {
        let mut provider = first.clone();
        provider["id"] = json!(id);
        provider
    };
    let second = other("1c6d7a5f-3b2e-4d4c-8f9a-8b7c6d5e4f30");
    let third = other("2d7e8b60-4c3f-4e5d-9a0b-9c8d7e6f5a41");

    assert_eq!(fixture.with("/providers", json!([])), Error::ProviderCount);
    // Refuse excess providers before opening any referenced files.
    let mut over_limit = fixture.document.clone();
    over_limit["providers"] = json!([first, second, third]);
    over_limit["login"]["keys"]["active"]["path"] = json!(fixture.dir.path("absent-key"));
    assert_eq!(
        refusal(fixture.load_bytes(over_limit.to_string().as_bytes())),
        Error::ProviderCount
    );
    assert_eq!(
        fixture.with("/providers", json!([first, first])),
        Error::DuplicateProvider
    );
    // A changed definition under a repeated identifier is still a repeat, not a replacement.
    let mut changed = first.clone();
    changed["revision"] = json!("r2");
    assert_eq!(
        fixture.with("/providers", json!([first, changed])),
        Error::DuplicateProvider
    );
    fixture.set("/providers", json!([first, second]));
    assert_eq!(fixture.load().unwrap().providers().len(), 2);

    for (field, value, expected) in [
        (
            "id",
            json!("0B5C6F4E-2A1D-4C3B-9E8F-7A6B5C4D3E2F"),
            Error::ProviderIdentity,
        ),
        (
            "id",
            json!("0b5c6f4e2a1d4c3b9e8f7a6b5c4d3e2f"),
            Error::ProviderIdentity,
        ),
        (
            "issuer",
            json!("http://issuer.example.test/realm"),
            Error::ProviderIdentity,
        ),
        (
            "issuer",
            json!("https://issuer.example.test/realm?x=1"),
            Error::ProviderIdentity,
        ),
        ("client_id", json!(""), Error::ProviderIdentity),
        ("revision", json!("bad revision"), Error::Provider),
        ("destination", json!(""), Error::Provider),
        (
            "authorization_endpoint",
            json!("http://issuer.example.test/authorize"),
            Error::Provider,
        ),
        (
            "token_endpoint",
            json!("https://203.0.113.10/token"),
            Error::Provider,
        ),
        (
            "token_endpoint",
            json!("https://ISSUER.example.test/token"),
            Error::Provider,
        ),
        (
            "discovery_url",
            json!("https://issuer.example.test/discovery?x=1"),
            Error::Provider,
        ),
        ("jwks_url", json!("https://localhost/jwks"), Error::Provider),
        (
            "callback",
            json!("https://user@app.example.test/callback"),
            Error::Provider,
        ),
        ("private_cidrs", json!(["8.8.8.0/24"]), Error::Provider),
        ("private_cidrs", json!(["10.20.0.1/16"]), Error::Provider),
        (
            "private_cidrs",
            json!(vec!["10.20.0.0/16"; 33]),
            Error::Provider,
        ),
    ] {
        assert_eq!(
            fixture.with(&format!("/providers/1/{field}"), value),
            expected,
            "{field}"
        );
    }
    // The bundle is PEM certificates only; anything else in it is refused by the transport.
    let mut mixed = Ca::new().pem();
    mixed.extend_from_slice(b"-----BEGIN SYNTHETIC-----\nAAAA\n-----END SYNTHETIC-----\n");
    let path = fixture.dir.write("mixed-ca", &mixed);
    assert_eq!(
        fixture.with("/providers/1/trust/bundle_path", json!(path)),
        Error::Provider
    );
}

#[test]
fn refusals_carry_no_configuration_values() {
    let fixture = Fixture::new();
    for (pointer, value) in [
        (
            "/providers/0/issuer",
            json!("http://synthetic-secret.example.test"),
        ),
        (
            "/providers/0/token_endpoint",
            json!("https://synthetic-secret/token"),
        ),
        (
            "/login/keys/active/path",
            json!(fixture.dir.path("synthetic-secret")),
        ),
        ("/login/keys/active/id", json!("synthetic secret")),
        (
            "/providers/0/trust/bundle_path",
            json!("synthetic-secret/ca"),
        ),
    ] {
        let error = fixture.with(pointer, value);
        let text = format!("{error} {error:?}");
        assert!(!text.contains("synthetic"), "{text}");
        assert!(!text.contains('/'), "{text}");
    }
}
