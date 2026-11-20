//! Loader tests with real files in a per-test temporary directory. No network or database.
use super::*;
use crate::provider_http::fixture::Ca;
use serde_json::json;
use std::{os::unix::fs::symlink, process::Command};

// Shared with the mounting tests in `src/tests.rs`.
#[path = "../../tests/auth_config_support/mod.rs"]
pub(crate) mod support;
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
    /// The same files with a version-2 document.
    fn v2() -> Self {
        let dir = Dir::new();
        let document = support::document_v2(&dir, &Ca::new().pem());
        Self { dir, document }
    }
    /// The same files with a version-2 document that has a native profile (ADR 0029).
    fn native() -> Self {
        let dir = Dir::new();
        let document = support::document_v2_native(&dir, &Ca::new().pem());
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

/// Pointers to every object in the valid version-1 document.
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
/// The objects that version 2 adds.
const BROWSER_OBJECTS: [&str; 7] = [
    "/browser",
    "/browser/paths",
    "/browser/rates",
    "/browser/rates/initiation",
    "/browser/rates/callback",
    "/browser/rates/session_check",
    "/browser/rates/logout",
];

#[test]
fn unknown_and_missing_fields_are_refused_in_every_object() {
    // Every member of the fixture is required. The one optional member,
    // `provider_refresh.uncacheable_reuse_seconds`, is absent from it and tested separately.
    // Version 2 is version 1 plus 22 browser members, counting `browser` itself.
    assert_eq!(missing_and_unknown(&Fixture::new(), &OBJECTS), 39);
    let v2: Vec<&str> = OBJECTS.into_iter().chain(BROWSER_OBJECTS).collect();
    assert_eq!(missing_and_unknown(&Fixture::v2(), &v2), 61);
    // Native roots take no bundle path.
    let fixture = Fixture::new();
    let mut native = fixture.document.clone();
    native["providers"][0]["trust"]["roots"] = json!("native");
    assert_eq!(
        refusal(fixture.load_bytes(native.to_string().as_bytes())),
        Error::UnknownField
    );
}
/// Adds an unknown member to, and removes each member from, every object in turn. Returns
/// the number of members removed.
fn missing_and_unknown(fixture: &Fixture, objects: &[&str]) -> usize {
    let mut fields = 0;
    for &pointer in objects {
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
    fields
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
        json!(3),
        json!(u64::MAX),
        json!("1"),
        json!(1.0),
        json!(null),
        json!([1]),
    ] {
        assert_eq!(fixture.with("/version", version), Error::Version);
    }
    for (bytes, expected) in [
        // A later version is reported as such, not as unknown fields.
        (&br#"{"version":3,"anything":true}"#[..], Error::Version),
        (br#"{"version":3,"browser":{}}"#, Error::Version),
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

/// The optional reuse window for providers that refuse caching (ADR 0011 amendment, 19
/// November 2026). The fixture's cooldown is 61 s and its freshness 3600 s.
#[test]
fn uncacheable_reuse_window_is_optional_bounded_and_consistent() {
    let mut fixture = Fixture::new();
    let load = |fixture: &Fixture, reuse: Option<Value>| {
        let mut document = fixture.document.clone();
        if let Some(value) = reuse {
            document["provider_refresh"]["uncacheable_reuse_seconds"] = value;
        }
        fixture.load_bytes(document.to_string().as_bytes())
    };
    let expected = |freshness, reuse: Option<u64>| {
        let policy = RefreshPolicy::new(
            Duration::from_secs(freshness),
            Duration::from_secs(61),
            Duration::from_millis(5000),
            2,
            32,
            3,
        )
        .unwrap();
        let policy = match reuse {
            Some(seconds) => policy
                .with_uncacheable_reuse(Duration::from_secs(seconds))
                .unwrap(),
            None => policy,
        };
        format!("{policy:?}")
    };
    let loaded =
        |result: Result<AuthConfig, Error>| format!("{:?}", result.unwrap().manager().policy());
    // Absent: the 60 s default. It is not judged against the 61 s cooldown, so a document
    // written before the member existed still loads.
    assert!(expected(3600, None).contains("uncacheable_reuse: 60s"));
    assert_eq!(loaded(load(&fixture, None)), expected(3600, None));
    // Explicit: from the cooldown up to 300 s and the freshness cap.
    for seconds in [61, 120, 300] {
        assert_eq!(
            loaded(load(&fixture, Some(json!(seconds)))),
            expected(3600, Some(seconds))
        );
    }
    for seconds in [0, 1, 60, 301, u64::MAX] {
        assert_eq!(
            refusal(load(&fixture, Some(json!(seconds)))),
            Error::RefreshPolicy,
            "{seconds}"
        );
    }
    fixture.set("/provider_refresh/freshness_seconds", json!(120));
    assert_eq!(
        loaded(load(&fixture, Some(json!(120)))),
        expected(120, Some(120))
    );
    assert_eq!(
        refusal(load(&fixture, Some(json!(121)))),
        Error::RefreshPolicy
    );
    // An absent window still loads under a freshness cap below the default.
    fixture.set("/provider_refresh/freshness_seconds", json!(30));
    assert_eq!(loaded(load(&fixture, None)), expected(30, None));
    let fixture = Fixture::new();
    for value in [
        json!("61"),
        json!(61.0),
        json!(-1),
        json!(null),
        json!([61]),
    ] {
        assert_eq!(
            refusal(load(&fixture, Some(value.clone()))),
            Error::Field,
            "{value}"
        );
    }
    let text = fixture.document.to_string();
    let member = r#""cooldown_seconds":61"#;
    let repeated = text.replacen(
        member,
        &format!(r#"{member},"uncacheable_reuse_seconds":61,"uncacheable_reuse_seconds":61"#),
        1,
    );
    assert_eq!(
        refusal(fixture.load_bytes(repeated.as_bytes())),
        Error::DuplicateField
    );
    // A version-2 document takes the same member.
    let v2 = Fixture::v2();
    assert_eq!(loaded(load(&v2, Some(json!(61)))), expected(3600, Some(61)));
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
    let v2 = Fixture::v2();
    for (pointer, value) in [
        ("/browser/provider_id", "synthetic-secret"),
        ("/browser/origin", "https://synthetic-secret.example.test"),
        ("/browser/origin", "http://synthetic-secret"),
        ("/browser/landing_path", "/synthetic-secret?x"),
        ("/browser/paths/initiation", "/synthetic-secret/{x}"),
        ("/browser/paths/logout", "/synthetic-secret?x"),
    ] {
        let error = v2.with(pointer, json!(value));
        let text = format!("{error} {error:?}");
        assert!(text.starts_with("browser profile refused: "), "{text}");
        assert!(!text.contains("synthetic"), "{text}");
        assert!(!text.contains('/'), "{text}");
    }
}

// Version 2: the browser-routing profile (ADR 0020).

const PROVIDER: &str = "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f";
const OTHER_PROVIDER: &str = "1c6d7a5f-3b2e-4d4c-8f9a-8b7c6d5e4f30";
const RATES: [&str; 4] = [
    "/browser/rates/initiation",
    "/browser/rates/callback",
    "/browser/rates/session_check",
    "/browser/rates/logout",
];
const PATHS: [&str; 3] = [
    "/browser/paths/initiation",
    "/browser/paths/session_check",
    "/browser/paths/logout",
];
fn handoff_refusal(error: handoff::SettingsError) -> Error {
    Error::BrowserHandoff(error)
}
fn router_refusal(error: router::SettingsError) -> Error {
    Error::BrowserRouter(error)
}

#[test]
fn version_two_retains_the_checked_browser_profile() {
    let fixture = Fixture::v2();
    let config = fixture.load().unwrap();
    // Loading is synchronous: no async runtime exists to enter.
    assert!(tokio::runtime::Handle::try_current().is_err());
    // The version-1 settings are unchanged by the profile beside them.
    assert_eq!(config.providers().len(), 1);
    assert_eq!(config.login_lifetime(), Duration::from_secs(300));
    let profile = config.browser().expect("version 2 has a browser profile");
    let handoff = profile.handoff();
    assert_eq!(
        (handoff.origin, handoff.landing, handoff.provider),
        ("https://app.example.test", "/home", PROVIDER)
    );
    let rate = |burst, millis| Rate {
        burst,
        interval: Duration::from_millis(millis),
    };
    let routes = profile.router();
    assert_eq!(routes.initiation, "/auth/login");
    assert_eq!(
        (routes.begin, routes.callback),
        (rate(20, 500), rate(21, 501))
    );
    assert_eq!(routes.in_flight, 64);
    let sessions = profile.sessions();
    assert_eq!(
        (sessions.session, sessions.logout),
        ("/auth/session", "/auth/logout")
    );
    assert_eq!(
        (sessions.checks, sessions.logouts),
        (rate(120, 100), rate(22, 502))
    );
    // No origin, path or provider identifier when debug-printed.
    assert_eq!(
        format!("{config:?} {profile:?}"),
        "AuthConfig(..) BrowserProfile(..)"
    );

    // Version 1 keeps its accepted shape and yields no profile.
    assert!(Fixture::new().load().unwrap().browser().is_none());

    // Inclusive router ceilings, the root landing and trailing slashes are accepted.
    for (pointer, value) in [
        ("/burst", 1),
        ("/burst", u64::from(router::MAX_BURST)),
        ("/interval_milliseconds", 1),
        ("/interval_milliseconds", 3_600_000),
    ] {
        for rate in RATES {
            let mut fixture = Fixture::v2();
            fixture.set(&format!("{rate}{pointer}"), json!(value));
            assert!(fixture.load().is_ok(), "{rate}{pointer} {value}");
        }
    }
    for (pointer, value) in [
        ("/browser/max_in_flight", json!(1)),
        ("/browser/max_in_flight", json!(router::MAX_IN_FLIGHT)),
        ("/browser/landing_path", json!("/")),
        ("/browser/paths/initiation", json!("/auth/login/")),
        ("/browser/paths/logout", json!("/")),
    ] {
        let mut fixture = Fixture::v2();
        fixture.set(pointer, value);
        assert!(fixture.load().is_ok(), "{pointer}");
    }
}

#[test]
fn version_decides_whether_the_browser_profile_is_allowed() {
    let v1 = Fixture::new();
    let v2 = Fixture::v2();
    let browser = v2.document["browser"].clone();
    // Version 1 does not accept the profile; version 2 requires it.
    let mut document = v1.document.clone();
    document["browser"] = browser.clone();
    assert_eq!(
        refusal(v1.load_bytes(document.to_string().as_bytes())),
        Error::UnknownField
    );
    assert_eq!(v1.with("/version", json!(2)), Error::MissingField);
    assert_eq!(v2.with("/version", json!(1)), Error::UnknownField);
    let mut document = v2.document.clone();
    document.as_object_mut().unwrap().remove("browser");
    assert_eq!(
        refusal(v2.load_bytes(document.to_string().as_bytes())),
        Error::MissingField
    );
    // Shapes and types are strict at every depth of the profile.
    for (pointer, value) in [
        ("/browser", json!(null)),
        ("/browser", json!([PROVIDER])),
        ("/browser", json!("synthetic")),
        ("/browser/paths", json!(["/auth/login", "/a", "/b"])),
        ("/browser/rates", json!([])),
        ("/browser/rates/callback", json!([21, 501])),
        ("/browser/rates/logout", json!(null)),
        ("/browser/provider_id", json!(1)),
        ("/browser/origin", json!(null)),
        ("/browser/landing_path", json!(["/home"])),
        ("/browser/paths/session_check", json!({})),
    ] {
        assert_eq!(v2.with(pointer, value), Error::Field, "{pointer}");
    }
    for pointer in [
        "/browser/max_in_flight",
        "/browser/rates/initiation/burst",
        "/browser/rates/session_check/interval_milliseconds",
    ] {
        for value in [
            json!("64"),
            json!(64.0),
            json!(6.4e1),
            json!(-1),
            json!(null),
            json!([64]),
        ] {
            assert_eq!(v2.with(pointer, value), Error::Field, "{pointer}");
        }
    }
    // Repeated members in each new object, and in the profile itself.
    let text = v2.document.to_string();
    for member in [
        r#""provider_id":"0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f""#,
        r#""max_in_flight":64"#,
        r#""logout":"/auth/logout""#,
        r#""burst":120"#,
        r#""interval_milliseconds":502"#,
        r#""paths":{"#,
        r#""callback":{"#,
    ] {
        assert_eq!(text.matches(member).count(), 1, "{member}");
        let repeated = if member.ends_with('{') {
            text.replacen(member, &format!("{member}}},{member}"), 1)
        } else {
            text.replacen(member, &format!("{member},{member}"), 1)
        };
        assert_eq!(
            refusal(v2.load_bytes(repeated.as_bytes())),
            Error::DuplicateField,
            "{member}"
        );
    }
}

#[test]
fn browser_origin_landing_and_provider_use_the_handoff_rules() {
    use handoff::SettingsError::{Callback, Landing, Origin, Provider};
    let v2 = Fixture::v2();
    for (pointer, value, error) in [
        ("/browser/provider_id", OTHER_PROVIDER, Provider),
        (
            "/browser/provider_id",
            "0B5C6F4E-2A1D-4C3B-9E8F-7A6B5C4D3E2F",
            Provider,
        ),
        ("/browser/provider_id", "", Provider),
        ("/browser/origin", "http://app.example.test", Origin),
        ("/browser/origin", "https://app.example.test/", Origin),
        ("/browser/origin", "https://APP.example.test", Origin),
        ("/browser/origin", "https://app.example.test:443", Origin),
        ("/browser/origin", "https://user@app.example.test", Origin),
        ("/browser/origin", "app.example.test", Origin),
        ("/browser/origin", "", Origin),
        // Canonical, but the selected provider's callback is not on it.
        ("/browser/origin", "https://other.example.test", Callback),
        ("/browser/origin", "https://app.example.test:8443", Callback),
        ("/browser/landing_path", "", Landing),
        ("/browser/landing_path", "home", Landing),
        ("/browser/landing_path", "//evil.example.test", Landing),
        ("/browser/landing_path", "/a/../home", Landing),
        ("/browser/landing_path", "/./home", Landing),
        ("/browser/landing_path", "/home?next=x", Landing),
        ("/browser/landing_path", "/home#x", Landing),
        ("/browser/landing_path", "/h%6fme", Landing),
        ("/browser/landing_path", "/h me", Landing),
        ("/browser/landing_path", "/hömé", Landing),
    ] {
        assert_eq!(
            v2.with(pointer, json!(value)),
            handoff_refusal(error),
            "{pointer} {value}"
        );
    }
    // The profile selects one provider by exact UUID; only that provider's callback counts.
    let mut fixture = Fixture::v2();
    let mut other = fixture.document["providers"][0].clone();
    other["id"] = json!(OTHER_PROVIDER);
    other["callback"] = json!("https://other.example.test/return");
    let first = fixture.document["providers"][0].clone();
    fixture.set("/providers", json!([first, other]));
    assert!(fixture.load().is_ok());
    fixture.set("/browser/provider_id", json!(OTHER_PROVIDER));
    assert_eq!(refusal(fixture.load()), handoff_refusal(Callback));
    fixture.set("/browser/origin", json!("https://other.example.test"));
    let config = fixture.load().unwrap();
    assert_eq!(config.browser().unwrap().handoff().provider, OTHER_PROVIDER);
    // The other provider's callback path is now the one the router checks against.
    fixture.set("/browser/paths/logout", json!("/return"));
    assert_eq!(
        refusal(fixture.load()),
        router_refusal(router::SettingsError::Collision)
    );
}

#[test]
fn browser_paths_and_admission_use_the_router_rules() {
    use router::SettingsError::{Collision, InFlight, Path, Pattern, Rate as RateRange};
    let v2 = Fixture::v2();
    let long = format!("/{}", "a".repeat(router::MAX_PATH_BYTES));
    for pointer in PATHS {
        for (value, error) in [
            ("/{id}", Pattern),
            ("/auth/{*rest}", Pattern),
            ("/auth:x", Pattern),
            ("", Path),
            ("auth", Path),
            ("//auth", Path),
            ("/a//b", Path),
            ("/a/../b", Path),
            ("/auth?x=1", Path),
            ("/auth#x", Path),
            ("/%61uth", Path),
            (long.as_str(), Path),
            // The selected provider's registered callback path, the operational routes and
            // the application API prefix (ADR 0027 PR4b).
            ("/callback", Collision),
            ("/healthz", Collision),
            ("/readyz", Collision),
            ("/v1", Collision),
            ("/v1/", Collision),
            ("/v1/projects", Collision),
        ] {
            assert_eq!(
                v2.with(pointer, json!(value)),
                router_refusal(error),
                "{pointer} {value}"
            );
        }
    }
    for (first, second) in [(0, 1), (1, 2), (0, 2)] {
        let mut fixture = Fixture::v2();
        fixture.set(PATHS[first], json!("/same"));
        fixture.set(PATHS[second], json!("/same"));
        assert_eq!(refusal(fixture.load()), router_refusal(Collision));
    }
    // Every budget is independent and judged by the router's ranges. Values too large for
    // the router's types still report the router's category.
    for rate in RATES {
        for (member, value) in [
            ("burst", 0),
            ("burst", u64::from(router::MAX_BURST) + 1),
            ("burst", u64::from(u32::MAX) + 1),
            ("burst", u64::MAX),
            ("interval_milliseconds", 0),
            ("interval_milliseconds", 3_600_001),
            ("interval_milliseconds", u64::MAX),
        ] {
            assert_eq!(
                v2.with(&format!("{rate}/{member}"), json!(value)),
                router_refusal(RateRange),
                "{rate}/{member} {value}"
            );
        }
    }
    for value in [
        0,
        u64::from(router::MAX_IN_FLIGHT) + 1,
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        assert_eq!(
            v2.with("/browser/max_in_flight", json!(value)),
            router_refusal(InFlight),
            "{value}"
        );
    }
    // The handoff's settings are judged before the router's, and paths before budgets.
    let mut fixture = Fixture::v2();
    fixture.set("/browser/max_in_flight", json!(0));
    fixture.set("/browser/rates/logout/burst", json!(0));
    assert_eq!(refusal(fixture.load()), router_refusal(RateRange));
    fixture.set("/browser/paths/logout", json!("/healthz"));
    assert_eq!(refusal(fixture.load()), router_refusal(Collision));
    fixture.set("/browser/landing_path", json!("home"));
    assert_eq!(
        refusal(fixture.load()),
        handoff_refusal(handoff::SettingsError::Landing)
    );
    // Earlier version-1 refusals still come first.
    fixture.set("/session/retained_per_user", json!(0));
    assert_eq!(refusal(fixture.load()), Error::SessionPolicy);
}

/// A native app link (ADR 0023) never lands on a configured browser route, the landing path
/// or an operational route of the browser origin, whether or not the native deployment
/// shares that origin. The lazy pool is never used, so nothing connects.
#[tokio::test]
async fn native_app_links_cannot_target_configured_browser_routes() {
    use crate::browser_auth::{BrowserAuth, native::NativeAuth};
    use std::sync::Arc;
    let config = Fixture::v2().load().unwrap();
    let provider = config.browser().unwrap().handoff().provider.to_owned();
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy_with(
        sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(9),
    );
    let auth = Arc::new(BrowserAuth::new(config, pool.clone(), pool));
    for origin in ["https://app.example.test", "https://broker.example.test"] {
        let register = |link: &str| {
            NativeAuth::new(
                auth.clone(),
                &provider,
                origin,
                &format!("{origin}/native/callback"),
                "synthetic.mobile",
                link,
                8,
            )
        };
        for path in [
            "/auth/login",
            "/auth/session",
            "/auth/logout",
            "/home",
            "/healthz",
            "/readyz",
        ] {
            let link = format!("https://app.example.test{path}");
            assert!(register(&link).is_err(), "{origin} {path}");
        }
        // Controls: another path on the browser origin, and a browser path on another origin.
        assert!(register("https://app.example.test/app-link").is_ok());
        assert!(register("https://links.example.test/auth/session").is_ok());
    }
}

/// One implementation: each profile the offline check accepts or refuses gets the same outcome
/// from `LoginHandoff::new` and `router_with_sessions`, built over the same providers. The
/// lazy pool is never used, so nothing connects.
#[tokio::test]
async fn offline_outcomes_match_the_handoff_and_router_constructors() {
    use crate::browser_auth::{BrowserAuth, handoff::LoginHandoff, router::router_with_sessions};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;
    let fixture = Fixture::v2();
    let pool = PgPoolOptions::new().connect_lazy_with(
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(9)
            .username("fixture"),
    );
    let build_routes = |config, profile: &BrowserProfile| -> Result<(), Error> {
        let auth = Arc::new(BrowserAuth::new(config, pool.clone(), pool.clone()));
        let handoff = LoginHandoff::new(auth, profile.handoff()).map_err(Error::BrowserHandoff)?;
        router_with_sessions(handoff, profile.router(), profile.sessions())
            .map(drop)
            .map_err(Error::BrowserRouter)
    };

    // Compose the router from the profile the loader returned. Keep the checked
    // settings while BrowserAuth takes ownership of the rest of the configuration.
    let config = fixture.load().unwrap();
    let profile = config.browser().unwrap().clone();
    assert_eq!(build_routes(config, &profile), Ok(()));

    let constructors = |document: &Value| -> Result<(), Error> {
        let profile = BrowserProfile::parse(document["browser"].clone()).unwrap();
        let mut v1 = document.clone();
        v1["version"] = json!(1);
        v1.as_object_mut().unwrap().remove("browser");
        let config = fixture.load_bytes(v1.to_string().as_bytes()).unwrap();
        build_routes(config, &profile)
    };
    let mut outcomes = HashSet::new();
    for (pointer, value) in [
        ("/browser/max_in_flight", json!(64)),
        ("/browser/provider_id", json!(OTHER_PROVIDER)),
        ("/browser/origin", json!("https://app.example.test/")),
        ("/browser/origin", json!("https://other.example.test")),
        ("/browser/landing_path", json!("/a/../b")),
        ("/browser/paths/initiation", json!("/{id}")),
        ("/browser/paths/session_check", json!("/a//b")),
        ("/browser/paths/logout", json!("/callback")),
        ("/browser/rates/callback/burst", json!(0)),
        (
            "/browser/rates/session_check/interval_milliseconds",
            json!(3_600_001),
        ),
        ("/browser/max_in_flight", json!(4097)),
    ] {
        let mut document = fixture.document.clone();
        *document.pointer_mut(pointer).unwrap() = value;
        let offline = fixture
            .load_bytes(document.to_string().as_bytes())
            .map(drop);
        assert_eq!(offline, constructors(&document), "{pointer}");
        outcomes.insert(format!("{offline:?}"));
    }
    // Success and the nine handoff and router categories above were all reached.
    assert_eq!(outcomes.len(), 10);
}

/// Serving (ADR 0025) takes the same loader and additionally requires the profile. Version 1
/// stays valid for the offline check, and every loader refusal passes through unchanged.
#[test]
fn serving_load_requires_the_version_2_profile() {
    let v2 = Fixture::v2();
    let path = v2
        .dir
        .write("auth.json", v2.document.to_string().as_bytes());
    let (config, profile) = load_browser(Path::new(&path)).unwrap();
    assert_eq!(profile.handoff().origin, "https://app.example.test");
    assert_eq!(
        profile.router().initiation,
        config.browser().unwrap().router().initiation
    );

    let v1 = Fixture::new();
    let path = v1
        .dir
        .write("auth.json", v1.document.to_string().as_bytes());
    assert!(load(Path::new(&path)).is_ok());
    let refused = |path: &str| load_browser(Path::new(path)).map(drop);
    assert_eq!(refused(&path), Err(Error::BrowserProfileRequired));
    assert_eq!(
        Error::BrowserProfileRequired.to_string(),
        "serving requires a version 2 browser profile"
    );
    assert_eq!(refused("auth.json"), Err(Error::Path));
    assert_eq!(refused(&v1.dir.path("absent")), Err(Error::ConfigFile));
    assert_eq!(refused(&v1.dir.write("auth.json", b"{")), Err(Error::Json));
}

// Version 2: the optional native sign-in profile (ADR 0029).

const NATIVE_OBJECTS: [&str; 2] = ["/native", "/native/rate"];
fn native_refusal(error: native::SettingsError) -> Error {
    Error::Native(error)
}

#[test]
fn native_profile_is_optional_in_version_two_and_retained_when_present() {
    // Every existing version-2 document, which has no native member, is unchanged.
    let config = Fixture::v2().load().unwrap();
    assert!(config.browser().is_some() && config.native().is_none());

    let config = Fixture::native().load().unwrap();
    assert!(tokio::runtime::Handle::try_current().is_err());
    let profile = config.native().expect("the native profile is retained");
    let settings = profile.settings();
    assert_eq!(
        (
            settings.provider,
            settings.issuer,
            settings.callback,
            settings.client,
            settings.redirect,
            settings.max_in_flight,
        ),
        (
            PROVIDER,
            "https://app.example.test",
            "https://app.example.test/auth/native/callback",
            "openmettle-desktop",
            "https://app.example.test/native/complete",
            65,
        )
    );
    assert_eq!(
        profile.rate(),
        Rate {
            burst: 23,
            interval: Duration::from_millis(503)
        }
    );
    // The browser profile beside it is unchanged.
    assert_eq!(config.browser().unwrap().router().initiation, "/auth/login");
    // No origin, link, client or provider identifier when debug-printed.
    assert_eq!(
        format!("{config:?} {profile:?} {settings:?}"),
        "AuthConfig(..) NativeProfile(..) NativeSettings(..)"
    );

    // Inclusive bounds.
    for (pointer, value) in [
        ("/native/rate/burst", json!(1)),
        ("/native/rate/burst", json!(router::MAX_BURST)),
        ("/native/rate/interval_milliseconds", json!(1)),
        ("/native/rate/interval_milliseconds", json!(3_600_000)),
        ("/native/max_in_flight", json!(1)),
        ("/native/max_in_flight", json!(native::MAX_IN_FLIGHT)),
        ("/native/client_id", json!("a".repeat(128))),
        ("/native/client_id", json!("A-z.0_9")),
    ] {
        let mut fixture = Fixture::native();
        fixture.set(pointer, value);
        assert!(fixture.load().is_ok(), "{pointer}");
    }
}

#[test]
fn native_profile_shape_is_strict() {
    let v1 = Fixture::new();
    let fixture = Fixture::native();
    let profile = fixture.document["native"].clone();
    // Version 1 keeps its exact shape: the member is unknown there.
    let mut document = v1.document.clone();
    document["native"] = profile.clone();
    assert_eq!(
        refusal(v1.load_bytes(document.to_string().as_bytes())),
        Error::UnknownField
    );
    let mut document = fixture.document.clone();
    document["version"] = json!(1);
    document.as_object_mut().unwrap().remove("browser");
    assert_eq!(
        refusal(fixture.load_bytes(document.to_string().as_bytes())),
        Error::UnknownField
    );
    // Present means an object: `null` is not absence.
    for value in [
        json!(null),
        json!([]),
        json!(PROVIDER),
        json!(1),
        json!(true),
    ] {
        assert_eq!(fixture.with("/native", value), Error::Field);
    }
    // Seven members and two rate members, each required; unknown members are refused.
    assert_eq!(missing_and_unknown(&fixture, &NATIVE_OBJECTS), 9);
    for pointer in [
        "/native/provider_id",
        "/native/issuer",
        "/native/callback",
        "/native/client_id",
        "/native/redirect_uri",
    ] {
        for value in [json!(1), json!(null), json!(["x"]), json!({})] {
            assert_eq!(fixture.with(pointer, value), Error::Field, "{pointer}");
        }
    }
    for pointer in [
        "/native/max_in_flight",
        "/native/rate/burst",
        "/native/rate/interval_milliseconds",
    ] {
        for value in [
            json!("64"),
            json!(64.0),
            json!(6.4e1),
            json!(-1),
            json!(null),
            json!([64]),
        ] {
            assert_eq!(fixture.with(pointer, value), Error::Field, "{pointer}");
        }
    }
    for value in [json!([23, 503]), json!(null), json!("23/503")] {
        assert_eq!(fixture.with("/native/rate", value), Error::Field);
    }
    // Repeated members, in the profile and its rate, and a repeated profile.
    let text = fixture.document.to_string();
    for member in [
        r#""client_id":"openmettle-desktop""#,
        r#""redirect_uri":"https://app.example.test/native/complete""#,
        r#""max_in_flight":65"#,
        r#""burst":23"#,
        r#""interval_milliseconds":503"#,
        r#""rate":{"#,
        r#""native":{"#,
    ] {
        assert_eq!(text.matches(member).count(), 1, "{member}");
        let repeated = if member.ends_with('{') {
            text.replacen(member, &format!("{member}}},{member}"), 1)
        } else {
            text.replacen(member, &format!("{member},{member}"), 1)
        };
        assert_eq!(
            refusal(fixture.load_bytes(repeated.as_bytes())),
            Error::DuplicateField,
            "{member}"
        );
    }
}

/// Every refusal of the native settings check, by category, in the order it decides them.
/// Each case is a set of JSON pointer replacements in the native fixture.
type NativeCase = (
    Vec<(&'static str, Value)>,
    Result<(), native::SettingsError>,
);
fn native_cases() -> Vec<NativeCase> {
    use native::SettingsError::*;
    let app = |path: &str| json!(format!("https://app.example.test{path}"));
    let broker = |path: &str| json!(format!("https://broker.example.test{path}"));
    let on_broker = |link: Value| {
        vec![
            ("/native/issuer", json!("https://broker.example.test")),
            ("/native/callback", broker("/auth/native/callback")),
            ("/native/redirect_uri", link),
        ]
    };
    let long_path = format!("/{}", "a".repeat(router::MAX_PATH_BYTES));
    let long_host = format!(
        "https://{}.example.test",
        vec!["a".repeat(60); 34].join(".")
    );
    let one = |pointer: &'static str, value: Value| vec![(pointer, value)];
    let mut cases = vec![
        (vec![], Ok(())),
        (
            one("/native/provider_id", json!(OTHER_PROVIDER)),
            Err(Provider),
        ),
        (
            one("/native/provider_id", json!(PROVIDER.to_ascii_uppercase())),
            Err(Provider),
        ),
        (one("/native/provider_id", json!("")), Err(Provider)),
        (
            one("/native/issuer", json!("http://app.example.test")),
            Err(Issuer),
        ),
        (
            one("/native/issuer", json!("https://app.example.test/")),
            Err(Issuer),
        ),
        (
            one("/native/issuer", json!("https://APP.example.test")),
            Err(Issuer),
        ),
        (
            one("/native/issuer", json!("https://app.example.test:443")),
            Err(Issuer),
        ),
        (
            one("/native/issuer", json!("app.example.test")),
            Err(Issuer),
        ),
        (one("/native/issuer", json!(long_host)), Err(Issuer)),
        // Canonical, but the callback is not on it.
        (
            one("/native/issuer", json!("https://other.example.test")),
            Err(Callback),
        ),
        (
            one(
                "/native/callback",
                json!("http://app.example.test/auth/native/callback"),
            ),
            Err(Callback),
        ),
        (
            one("/native/callback", app("/auth/native/callback?x=1")),
            Err(Callback),
        ),
        (
            one("/native/callback", app("/auth/native/callback#x")),
            Err(Callback),
        ),
        (one("/native/callback", app("/")), Err(Callback)),
        (one("/native/callback", app("//auth")), Err(Callback)),
        (one("/native/callback", app("/a%20b")), Err(Callback)),
        (one("/native/callback", app("/a/../b")), Err(Callback)),
        (
            one(
                "/native/callback",
                json!("https://user@app.example.test/auth/native/callback"),
            ),
            Err(Callback),
        ),
        (
            one("/native/callback", broker("/auth/native/callback")),
            Err(Callback),
        ),
        (one("/native/client_id", json!("")), Err(Client)),
        (
            one("/native/client_id", json!("a".repeat(129))),
            Err(Client),
        ),
        (
            one("/native/client_id", json!("openmettle desktop")),
            Err(Client),
        ),
        (
            one("/native/client_id", json!("openmettle~desktop")),
            Err(Client),
        ),
        (one("/native/client_id", json!("désktop")), Err(Client)),
        (
            one(
                "/native/redirect_uri",
                json!("http://app.example.test/native/complete"),
            ),
            Err(Redirect),
        ),
        (
            one("/native/redirect_uri", app("/native/complete?x=1")),
            Err(Redirect),
        ),
        (
            one("/native/redirect_uri", json!("https://app.example.test")),
            Err(Redirect),
        ),
        (
            one("/native/redirect_uri", json!("com.example.app:/complete")),
            Err(Redirect),
        ),
        (one("/native/redirect_uri", json!("")), Err(Redirect)),
        // An exact link whose path is no plain route path.
        (one("/native/callback", app("/a//b")), Err(Route)),
        (one("/native/callback", app(&long_path)), Err(Route)),
        // The callback against operational, native, browser and provider callback routes.
        (one("/native/callback", app("/healthz")), Err(Collision)),
        (one("/native/callback", app("/readyz")), Err(Collision)),
        (
            one("/native/callback", app("/auth/native/token")),
            Err(Collision),
        ),
        (
            one("/native/callback", app("/auth/native/authorize")),
            Err(Collision),
        ),
        (one("/native/callback", app("/auth/login")), Err(Collision)),
        (
            one("/native/callback", app("/auth/session")),
            Err(Collision),
        ),
        (one("/native/callback", app("/home")), Err(Collision)),
        (one("/native/callback", app("/callback")), Err(Collision)),
        // The application API prefix, on any origin: one router serves it (ADR 0027 PR4b).
        (one("/native/callback", app("/v1/callback")), Err(Collision)),
        (
            vec![
                ("/native/issuer", json!("https://broker.example.test")),
                ("/native/callback", broker("/v1/native/callback")),
            ],
            Err(Collision),
        ),
        (one("/native/redirect_uri", app("/v1")), Err(Collision)),
        (
            one("/native/redirect_uri", app("/v1/projects")),
            Err(Collision),
        ),
        (on_broker(app("/v1/capabilities")), Err(Collision)),
        (
            one(
                "/native/redirect_uri",
                json!("https://links.example.test/v1/complete"),
            ),
            Ok(()),
        ),
        // The app link against the provider callback, native and operational routes of
        // the issuer, and browser and operational routes of the browser origin.
        (
            one("/native/redirect_uri", app("/callback")),
            Err(Collision),
        ),
        (
            one("/native/redirect_uri", app("/auth/native/session")),
            Err(Collision),
        ),
        (
            one("/native/redirect_uri", app("/auth/native/callback")),
            Err(Collision),
        ),
        (one("/native/redirect_uri", app("/healthz")), Err(Collision)),
        (
            one("/native/redirect_uri", app("/auth/logout")),
            Err(Collision),
        ),
        (on_broker(app("/auth/session")), Err(Collision)),
        (on_broker(app("/home")), Err(Collision)),
        (on_broker(app("/readyz")), Err(Collision)),
        (on_broker(app("/callback")), Err(Collision)),
        (on_broker(broker("/auth/native/token")), Err(Collision)),
        (on_broker(broker("/readyz")), Err(Collision)),
        // Controls: browser paths as an app link on another origin, and native paths for a
        // link elsewhere.
        (on_broker(app("/app-link")), Ok(())),
        (on_broker(broker("/auth/session")), Ok(())),
        (on_broker(broker("/callback")), Ok(())),
        // One router serves both route sets and ignores the host, so a native route never
        // repeats a mounted browser route on another origin either. The landing is not a
        // route, so only a shared origin protects it.
        (
            vec![
                ("/native/issuer", json!("https://broker.example.test")),
                ("/native/callback", broker("/auth/login")),
            ],
            Err(Collision),
        ),
        (
            vec![
                ("/native/issuer", json!("https://broker.example.test")),
                ("/native/callback", broker("/callback")),
            ],
            Err(Collision),
        ),
        (
            vec![
                ("/native/issuer", json!("https://broker.example.test")),
                ("/native/callback", broker("/auth/logout")),
            ],
            Err(Collision),
        ),
        (
            vec![
                ("/native/issuer", json!("https://broker.example.test")),
                ("/native/callback", broker("/home")),
            ],
            Ok(()),
        ),
        (
            one(
                "/native/redirect_uri",
                json!("https://links.example.test/auth/native/token"),
            ),
            Ok(()),
        ),
    ];
    for (member, value) in [
        ("burst", json!(0)),
        ("burst", json!(u64::from(router::MAX_BURST) + 1)),
        ("burst", json!(u64::from(u32::MAX) + 1)),
        ("burst", json!(u64::MAX)),
        ("interval_milliseconds", json!(0)),
        ("interval_milliseconds", json!(3_600_001)),
        ("interval_milliseconds", json!(u64::MAX)),
    ] {
        let pointer = if member == "burst" {
            "/native/rate/burst"
        } else {
            "/native/rate/interval_milliseconds"
        };
        cases.push((one(pointer, value), Err(Rate)));
    }
    for value in [
        json!(0),
        json!(native::MAX_IN_FLIGHT + 1),
        json!(u64::from(u32::MAX) + 1),
        json!(u64::MAX),
    ] {
        cases.push((one("/native/max_in_flight", value), Err(InFlight)));
    }
    // Earlier categories are decided first.
    cases.push((
        vec![
            ("/native/max_in_flight", json!(0)),
            ("/native/rate/burst", json!(0)),
        ],
        Err(Rate),
    ));
    cases.push((
        vec![
            ("/native/rate/burst", json!(0)),
            ("/native/callback", app("/healthz")),
        ],
        Err(Collision),
    ));
    cases.push((
        vec![
            ("/native/redirect_uri", json!("http://x")),
            ("/native/client_id", json!("")),
        ],
        Err(Client),
    ));
    cases.push((
        vec![
            ("/native/provider_id", json!(OTHER_PROVIDER)),
            ("/native/issuer", json!("http://x")),
        ],
        Err(Provider),
    ));
    cases
}
fn with_all(document: &Value, changes: &[(&str, Value)]) -> Value {
    let mut document = document.clone();
    for (pointer, value) in changes {
        *document.pointer_mut(pointer).unwrap() = value.clone();
    }
    document
}

#[test]
fn native_settings_refusals_have_fixed_categories() {
    let fixture = Fixture::native();
    let mut categories = HashSet::new();
    for (changes, expected) in native_cases() {
        let document = with_all(&fixture.document, &changes);
        let outcome = fixture
            .load_bytes(document.to_string().as_bytes())
            .map(drop);
        assert_eq!(outcome, expected.map_err(native_refusal), "{changes:?}");
        categories.insert(format!("{expected:?}"));
    }
    // Success and all nine categories were reached.
    assert_eq!(categories.len(), 10);
    // The browser profile is judged first, and version-1 refusals before both.
    let mut fixture = Fixture::native();
    fixture.set("/native/max_in_flight", json!(0));
    fixture.set("/browser/max_in_flight", json!(0));
    assert_eq!(
        refusal(fixture.load()),
        router_refusal(router::SettingsError::InFlight)
    );
    fixture.set("/session/retained_per_user", json!(0));
    assert_eq!(refusal(fixture.load()), Error::SessionPolicy);
    // A native route never shadows a browser path even if the browser profile moves.
    let mut fixture = Fixture::native();
    fixture.set(
        "/browser/paths/session_check",
        json!("/auth/native/session"),
    );
    assert_eq!(
        refusal(fixture.load()),
        native_refusal(native::SettingsError::Collision)
    );
}

#[test]
fn native_refusals_carry_no_configuration_values() {
    use native::SettingsError::*;
    for error in [
        Provider, Issuer, Callback, Client, Redirect, Route, Collision, Rate, InFlight,
    ] {
        let text = format!("{error} {error:?} {}", native_refusal(error));
        assert!(!text.contains('/') && !text.contains("http"), "{text}");
    }
    assert_eq!(
        native_refusal(Collision).to_string(),
        "native profile refused: native routes or app link collide with another route"
    );
    let fixture = Fixture::native();
    for (pointer, value) in [
        ("/native/provider_id", "synthetic-secret"),
        ("/native/issuer", "https://synthetic-secret.example.test"),
        ("/native/issuer", "http://synthetic-secret"),
        (
            "/native/callback",
            "https://app.example.test/synthetic-secret?x",
        ),
        (
            "/native/callback",
            "https://app.example.test/synthetic-secret//x",
        ),
        ("/native/client_id", "synthetic secret"),
        (
            "/native/redirect_uri",
            "https://synthetic-secret.example.test/healthz?x",
        ),
        ("/native/redirect_uri", "https://app.example.test/healthz"),
    ] {
        let error = fixture.with(pointer, json!(value));
        let text = format!("{error} {error:?}");
        assert!(text.starts_with("native profile refused: "), "{text}");
        for canary in [
            "synthetic",
            "/",
            "app.example",
            "desktop",
            PROVIDER,
            "healthz",
        ] {
            assert!(!text.contains(canary), "{canary}: {text}");
        }
    }
}

/// One implementation: each native profile the offline check accepts or refuses gets the
/// same outcome from the native service built over the same providers and browser profile.
/// `NativeAuth::new` has no rate and reports `Configuration`; a refused rate is then refused
/// by `router_shared`. The lazy pool is never used, so nothing connects.
#[tokio::test]
async fn offline_native_outcomes_match_the_native_constructors() {
    use crate::{
        browser_auth::{BrowserAuth, native::NativeAuth},
        sessions,
    };
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;
    let fixture = Fixture::native();
    let pool = PgPoolOptions::new().connect_lazy_with(
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(9)
            .username("fixture"),
    );
    for (changes, expected) in native_cases() {
        let document = with_all(&fixture.document, &changes);
        let offline = fixture
            .load_bytes(document.to_string().as_bytes())
            .map(drop);
        assert_eq!(offline, expected.map_err(native_refusal), "{changes:?}");
        let mut root = Object::new(document.clone()).unwrap();
        let profile = NativeProfile::parse(root.object("native").unwrap()).unwrap();
        // The same settings without the profile, so only the constructors judge it.
        let mut without = document.clone();
        without.as_object_mut().unwrap().remove("native");
        let config = fixture.load_bytes(without.to_string().as_bytes()).unwrap();
        let auth = Arc::new(BrowserAuth::new(config, pool.clone(), pool.clone()));
        let checked = NativeAuth::checked(auth.clone(), profile.settings(), profile.rate());
        assert_eq!(
            checked.as_ref().map(drop).map_err(|e| *e),
            expected,
            "{changes:?}"
        );
        let settings = profile.settings();
        let built = NativeAuth::new(
            auth,
            settings.provider,
            settings.issuer,
            settings.callback,
            settings.client,
            settings.redirect,
            settings.max_in_flight,
        );
        // Without a rate, `new` refuses what the check refuses before the rate, and a
        // rate refused by the check is refused when the routes are built.
        match (expected, built) {
            (Ok(()), Ok(auth)) => assert!(Arc::new(auth).router_shared(profile.rate()).is_ok()),
            (Err(native::SettingsError::Rate), Ok(auth)) => assert_eq!(
                Arc::new(auth).router_shared(profile.rate()).err(),
                Some(sessions::Error::Configuration),
                "{changes:?}"
            ),
            (Err(_), Err(error)) => assert_eq!(error, sessions::Error::Configuration),
            (expected, built) => panic!("{changes:?}: {expected:?} {:?}", built.map(drop)),
        }
    }
}

/// Serving takes the same loader: the native profile is retained beside the browser one.
#[test]
fn serving_load_retains_the_native_profile() {
    let fixture = Fixture::native();
    let path = fixture
        .dir
        .write("auth.json", fixture.document.to_string().as_bytes());
    let (config, browser) = load_browser(Path::new(&path)).unwrap();
    assert_eq!(browser.handoff().origin, "https://app.example.test");
    assert_eq!(config.native().unwrap().rate().burst, 23);
    let mut document = fixture.document.clone();
    document["native"]["max_in_flight"] = json!(0);
    let path = fixture
        .dir
        .write("auth.json", document.to_string().as_bytes());
    assert_eq!(
        load_browser(Path::new(&path)).map(drop),
        Err(native_refusal(native::SettingsError::InFlight))
    );
}
