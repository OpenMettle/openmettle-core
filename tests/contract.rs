//! Application API contract checks (ADR 0007). Offline: every reference resolves from
//! vendored files and network or file retrieval is refused. These tests validate the
//! canonical contract and its generated fixtures, and the problems a mounted API returns
//! without a database. Successful `/v1` responses are checked against PostgreSQL in
//! `tests/schema/authz_http.rs`.
#[path = "auth_config_support/mod.rs"]
mod auth_config_support;
// The transport fixture's synthetic CA; its leaf certificates are not needed here.
#[allow(dead_code)]
#[path = "provider_http_support/ca.rs"]
mod ca;
#[path = "contract/consumer.rs"]
mod consumer;
#[path = "support/env.rs"]
mod env_support;

use env_support::scrub_env;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::OnceLock,
};

const CONTRACT_URI: &str = "https://openmettle.invalid/contracts/openapi/openmettle-v1.json";
const OAS_SCHEMA_BASE: &str = "https://spec.openapis.org/oas/3.2/schema-base/2026-11-12";
const OAS_DIALECT: &str = "https://spec.openapis.org/oas/3.2/dialect/2026-02-26";
/// Official OpenAPI 3.2 schema files, vendored unmodified with their pinned SHA-256.
const VENDORED: [(&str, &str, &str); 4] = [
    (
        OAS_SCHEMA_BASE,
        "schema-base-2026-11-12.json",
        "8e432f0f148597960daa3aafa0c0030d8aae7538d32c217854a1e3aada595216",
    ),
    (
        "https://spec.openapis.org/oas/3.2/schema/2026-11-12",
        "schema-2026-11-12.json",
        "f1f7ee38d431a7bb1082e4df2288dbe1d4d3f49081b497af249c07b77737fb43",
    ),
    (
        OAS_DIALECT,
        "dialect-2026-02-26.json",
        "9375b7042aa0b01848403f0a9ebf12a3425e01a9e24337ce12624f10fea73833",
    ),
    (
        "https://spec.openapis.org/oas/3.2/meta/2026-02-26",
        "meta-2026-02-26.json",
        "f444d02ef7d36f30293983fad8118c823a3c70a49a8e5aa6f1afe21215e35417",
    ),
];
const SENSITIVE_NAMES: [&str; 13] = [
    "url",
    "endpoint",
    "secret",
    "token",
    "password",
    "credential",
    "api_key",
    "email",
    "issuer",
    "subject",
    "owner",
    "user_id",
    "digest",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&read(path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn contract() -> &'static Value {
    static CONTRACT: OnceLock<Value> = OnceLock::new();
    CONTRACT.get_or_init(|| read_json(&root().join("contracts/openapi/openmettle-v1.json")))
}

/// Serves only the vendored OAS files and the canonical contract; refuses everything else.
struct Offline(HashMap<&'static str, Value>);

impl Offline {
    fn new() -> Self {
        let mut map = HashMap::new();
        for (uri, file, _) in VENDORED {
            map.insert(
                uri,
                read_json(&root().join("contracts/vendor/oas-3.2").join(file)),
            );
        }
        map.insert(CONTRACT_URI, contract().clone());
        Self(map)
    }
}

impl jsonschema::Retrieve for Offline {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.0
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("refused unvendored reference {}", uri.as_str()).into())
    }
}

fn build(schema: &Value) -> Result<jsonschema::Validator, String> {
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .with_retriever(Offline::new())
        .should_validate_formats(true)
        .build(schema)
        .map_err(|e| e.to_string())
}

fn validator_for(pointer: &str) -> jsonschema::Validator {
    assert!(pointer.starts_with("#/"), "{pointer}");
    build(&json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("{CONTRACT_URI}{pointer}"),
    }))
    .unwrap_or_else(|e| panic!("{pointer}: {e}"))
}

/// (instance path, keyword) for every error, keyword being the last schema-path segment.
fn errors(validator: &jsonschema::Validator, instance: &Value) -> Vec<(String, String)> {
    validator
        .iter_errors(instance)
        .map(|e| {
            let schema_path = e.schema_path().to_string();
            let keyword = schema_path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned();
            (e.instance_path().to_string(), keyword)
        })
        .collect()
}

fn pointer_get<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value
        .pointer(pointer.trim_start_matches('#'))
        .unwrap_or_else(|| panic!("{pointer} does not resolve"))
}

/// Follows local $ref chains at the root of a schema.
fn resolve_schema<'a>(document: &'a Value, pointer: &str) -> (&'a Value, String) {
    let mut pointer = pointer.to_owned();
    let mut node = pointer_get(document, &pointer);
    while let Some(next) = node.get("$ref").and_then(Value::as_str) {
        assert!(next.starts_with("#/"), "non-local reference {next}");
        pointer = next.to_owned();
        node = pointer_get(document, &pointer);
    }
    (node, pointer)
}

fn walk<'a>(value: &'a Value, path: String, visit: &mut impl FnMut(&str, &'a Value)) {
    visit(&path, value);
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                walk(
                    child,
                    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    visit,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(child, format!("{path}/{index}"), visit);
            }
        }
        _ => {}
    }
}

#[test]
fn vendored_oas_schemas_match_pinned_digests() {
    for (_, file, digest) in VENDORED {
        let bytes = read(&root().join("contracts/vendor/oas-3.2").join(file));
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            actual, digest,
            "{file} differs from the pinned official copy"
        );
    }
    assert!(
        String::from_utf8(read(&root().join("contracts/vendor/oas-3.2/LICENSE")))
            .unwrap()
            .contains("Apache License")
    );
}

#[test]
fn document_conforms_to_official_oas_3_2_schema() {
    let validator = build(&json!({"$ref": OAS_SCHEMA_BASE})).unwrap();
    let failures: Vec<String> = validator
        .iter_errors(contract())
        .map(|e| format!("{} ({}): {e}", e.instance_path(), e.schema_path()))
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
    // The official schema also rejects a malformed Schema Object inside the document.
    let mut broken = contract().clone();
    broken["components"]["schemas"]["Uuid"]["type"] = json!("strng");
    assert!(!validator.is_valid(&broken));
}

#[test]
fn document_pins_versions_and_dialect() {
    let document = contract();
    assert_eq!(document["openapi"], "3.2.1");
    assert_eq!(document["jsonSchemaDialect"], OAS_DIALECT);
    assert!(
        document["info"]["version"]
            .as_str()
            .unwrap()
            .starts_with("1.")
    );
    let pattern = document["components"]["schemas"]["ApiVersion"]["pattern"]
        .as_str()
        .unwrap();
    assert!(pattern.starts_with("^1\\."), "{pattern}");
    for path in document["paths"].as_object().unwrap().keys() {
        assert!(path.starts_with("/v1/"), "{path} is outside the v1 prefix");
    }
}

#[test]
fn resolution_is_offline_and_refuses_remote_and_file_references() {
    for reference in [
        "https://example.invalid/schema.json",
        "http://json-schema.org/not-vendored",
        "file:///etc/hosts",
    ] {
        let error = build(&json!({"$ref": reference}))
            .err()
            .unwrap_or_else(|| panic!("{reference} resolved"));
        assert!(error.contains("refused unvendored reference"), "{error}");
    }
    let mut external = Vec::new();
    walk(contract(), String::new(), &mut |path, value| {
        if let Some(reference) = value.get("$ref").and_then(Value::as_str)
            && !reference.starts_with("#/")
        {
            external.push(format!("{path}: {reference}"));
        }
    });
    assert!(external.is_empty(), "{external:?}");
}

#[test]
fn every_component_schema_compiles() {
    let schemas = contract()["components"]["schemas"].as_object().unwrap();
    assert!(schemas.len() >= 10);
    for name in schemas.keys() {
        validator_for(&format!("#/components/schemas/{name}"));
    }
    validator_for("#/components/mediaTypes/RunEventStream/itemSchema");
}

/// JSON content properties (contentMediaType application/json) of a schema's root.
fn content_schemas(schema_pointer: &str) -> BTreeMap<String, String> {
    let (schema, pointer) = resolve_schema(contract(), schema_pointer);
    let mut out = BTreeMap::new();
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            if property.get("contentMediaType") == Some(&json!("application/json")) {
                assert!(property.get("contentSchema").is_some(), "{pointer}/{name}");
                out.insert(
                    format!("/{name}"),
                    format!("{pointer}/properties/{name}/contentSchema"),
                );
            }
        }
    }
    out
}

struct Fixture {
    path: String,
    class: String,
    schema: String,
    expect: Value,
    instance: Value,
}

fn fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    for class in ["valid", "compat", "invalid"] {
        let dir = root().join("contracts/fixtures").join(class);
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            let fixture = read_json(&path);
            assert_eq!(fixture["class"], class, "{}", path.display());
            assert_eq!(fixture["generated_by"], "scripts/contract_fixtures.py");
            out.push(Fixture {
                path: format!("{class}/{}", path.file_name().unwrap().to_string_lossy()),
                class: class.to_owned(),
                schema: fixture["schema"].as_str().unwrap().to_owned(),
                expect: fixture["expect"].clone(),
                instance: fixture["instance"].clone(),
            });
        }
    }
    out
}

#[test]
fn generated_fixtures_validate_as_declared() {
    let all = fixtures();
    for class in ["valid", "compat", "invalid"] {
        assert!(all.iter().any(|f| f.class == class), "no {class} fixtures");
    }
    let mut validators: HashMap<String, jsonschema::Validator> = HashMap::new();
    let mut check = |pointer: &str, instance: &Value| -> Vec<(String, String)> {
        let validator = validators
            .entry(pointer.to_owned())
            .or_insert_with(|| validator_for(pointer));
        errors(validator, instance)
    };
    for fixture in &all {
        let outer = check(&fixture.schema, &fixture.instance);
        let contents = content_schemas(&fixture.schema);
        let expected_content = fixture.expect.get("content").and_then(Value::as_str);
        if fixture.class != "invalid" || expected_content.is_some() {
            assert!(outer.is_empty(), "{}: {outer:?}", fixture.path);
        }
        // contentSchema is not asserted by JSON Schema; decode and validate it explicitly.
        let mut content_errors = BTreeMap::new();
        for (property, pointer) in &contents {
            let encoded = fixture.instance.pointer(property).and_then(Value::as_str);
            let Some(encoded) = encoded else { continue };
            let result = match serde_json::from_str::<Value>(encoded) {
                Ok(decoded) => Ok(check(pointer, &decoded)),
                Err(e) => Err(e.to_string()),
            };
            content_errors.insert(property.clone(), result);
        }
        if fixture.class != "invalid" {
            for (property, result) in &content_errors {
                assert!(
                    matches!(result, Ok(e) if e.is_empty()),
                    "{} {property}: {result:?}",
                    fixture.path
                );
            }
            continue;
        }
        assert_eq!(fixture.expect["valid"], false, "{}", fixture.path);
        let found = match expected_content {
            Some(property) => content_errors
                .get(property)
                .unwrap_or_else(|| panic!("{}: no content at {property}", fixture.path)),
            None => &Ok(outer),
        };
        if fixture.expect.get("decode") == Some(&json!(true)) {
            assert!(found.is_err(), "{}: content decoded", fixture.path);
            continue;
        }
        let wanted = (
            fixture.expect["instancePath"].as_str().unwrap().to_owned(),
            fixture.expect["keyword"].as_str().unwrap().to_owned(),
        );
        let found = found
            .as_ref()
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.path));
        assert!(
            found.contains(&wanted),
            "{}: expected {wanted:?}, got {found:?}",
            fixture.path
        );
    }
}

#[test]
fn every_fixture_example_has_a_generated_fixture() {
    let generated: Vec<String> = fixtures()
        .into_iter()
        .filter(|f| f.class == "valid")
        .map(|f| f.path)
        .collect();
    for (name, example) in contract()["components"]["examples"].as_object().unwrap() {
        if example.get("x-openmettle-fixture").is_some() {
            assert!(
                generated.contains(&format!("valid/{name}.json")),
                "{name} has no generated fixture; run scripts/contract_fixtures.py"
            );
        }
    }
}

fn operation_problems(document: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let schemes = document["components"]["securitySchemes"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    // V1-04 settled both session transports (ADRs 0019 and 0029).
    for (name, scheme) in &schemes {
        if scheme.get("x-openmettle-provisional").is_some() {
            problems.push(format!(
                "security scheme {name} is still marked provisional"
            ));
        }
    }
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let at = format!("{method} {path}");
            let status = operation.get("x-openmettle-implementation");
            if ![json!("implemented"), json!("not-implemented")]
                .iter()
                .any(|allowed| status == Some(allowed))
            {
                problems.push(format!(
                    "{at}: implementation status must be implemented or not-implemented"
                ));
            }
            let security = operation
                .get("security")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if security.is_empty()
                || security.iter().any(|requirement| {
                    let requirement = requirement.as_object().unwrap();
                    requirement.is_empty() || requirement.keys().any(|k| !schemes.contains_key(k))
                })
            {
                problems.push(format!(
                    "{at}: must require a declared authentication scheme"
                ));
            }
            for (status, response) in operation["responses"].as_object().unwrap() {
                let (response, _) = match response.get("$ref").and_then(Value::as_str) {
                    Some(reference) => resolve_schema(document, reference),
                    None => (response, String::new()),
                };
                if response
                    .pointer("/headers/OpenMettle-API-Version/$ref")
                    .is_none()
                {
                    problems.push(format!("{at} {status}: missing OpenMettle-API-Version"));
                }
                if status.starts_with('4') || status.starts_with('5') {
                    let content = response["content"].as_object().cloned().unwrap_or_default();
                    let schema = content
                        .get("application/problem+json")
                        .and_then(|c| c.pointer("/schema/$ref"));
                    if content.len() != 1 || schema != Some(&json!("#/components/schemas/Problem"))
                    {
                        problems.push(format!("{at} {status}: must be problem+json only"));
                    }
                }
            }
        }
    }
    problems
}

#[test]
fn operations_are_authenticated_declare_their_status_and_use_problem_details() {
    let problems = operation_problems(contract());
    assert!(problems.is_empty(), "{problems:#?}");
    // The lint detects an anonymous operation, a non-problem error response, a missing or
    // unknown implementation status and a provisional security scheme.
    let mut weakened = contract().clone();
    let operation = &mut weakened["paths"]["/v1/capabilities"]["get"];
    operation["security"] = json!([{}]);
    operation["responses"]["418"] = json!({
        "description": "x",
        "headers": {"OpenMettle-API-Version": {"$ref": "#/components/headers/ApiVersion"}},
        "content": {"text/plain": {"schema": {"type": "string", "maxLength": 1}}}
    });
    weakened["paths"]["/v1/projects"]["post"]["x-openmettle-implementation"] = json!("partial");
    weakened["paths"]["/v1/projects/{project_id}"]["get"]
        .as_object_mut()
        .unwrap()
        .remove("x-openmettle-implementation");
    weakened["components"]["securitySchemes"]["nativeSession"]["x-openmettle-provisional"] =
        json!(true);
    let found = operation_problems(&weakened);
    for needle in [
        "get /v1/capabilities: must require a declared authentication scheme",
        "get /v1/capabilities 418: must be problem+json only",
        "post /v1/projects: implementation status",
        "get /v1/projects/{project_id}: implementation status",
        "security scheme nativeSession is still marked provisional",
    ] {
        assert!(
            found.iter().any(|p| p.contains(needle)),
            "{needle}: {found:?}"
        );
    }
}

/// The settled session transports match the server: the browser cookie is the one the sign-in
/// callback sets, the native credential is a bearer, and every implemented operation accepts
/// either.
#[test]
fn security_schemes_match_the_served_session_transports() {
    let schemes = &contract()["components"]["securitySchemes"];
    assert_eq!(
        (
            &schemes["browserSession"]["type"],
            &schemes["browserSession"]["in"],
            &schemes["browserSession"]["name"],
        ),
        (
            &json!("apiKey"),
            &json!("cookie"),
            &json!(openmettle_core::browser_auth::handoff::SESSION_COOKIE),
        )
    );
    assert_eq!(
        (
            &schemes["nativeSession"]["type"],
            &schemes["nativeSession"]["scheme"]
        ),
        (&json!("http"), &json!("bearer"))
    );
    for item in contract()["paths"].as_object().unwrap().values() {
        for operation in item.as_object().unwrap().values() {
            assert_eq!(
                operation["security"],
                json!([{"browserSession": []}, {"nativeSession": []}]),
                "{}",
                operation["operationId"]
            );
        }
    }
}

/// Every schema under components bounds strings, arrays and integers; object property
/// names avoid sensitive data; request bodies are closed objects.
fn schema_problems(document: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    walk(
        &document["components"]["schemas"],
        "#/components/schemas".into(),
        &mut |path, node| {
            let Some(object) = node.as_object() else {
                return;
            };
            // Skip example payloads and annotation-only arrays.
            if path.contains("/examples") || path.contains("/required") || path.contains("/enum") {
                return;
            }
            let types: Vec<&str> = match object.get("type") {
                Some(Value::String(t)) => vec![t.as_str()],
                Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            let fixed = object.contains_key("const") || object.contains_key("enum");
            if types.contains(&"string") && !fixed && !object.contains_key("maxLength") {
                problems.push(format!("{path}: string without maxLength"));
            }
            if types.contains(&"array") && !object.contains_key("maxItems") {
                problems.push(format!("{path}: array without maxItems"));
            }
            if types.contains(&"integer")
                && !fixed
                && !(object.contains_key("minimum") && object.contains_key("maximum"))
            {
                problems.push(format!("{path}: integer without minimum and maximum"));
            }
            if let Some(Value::Object(properties)) = object.get("properties")
                && !path.ends_with("/properties")
            {
                for name in properties.keys() {
                    // ADR 0035 exposes only the SHA-256 binding on the actor's private operations.
                    if name == "binding_digest"
                        && matches!(
                            path,
                            "#/components/schemas/PendingApproval"
                                | "#/components/schemas/ApprovalDecisionRequest"
                                | "#/components/schemas/ApprovalReceipt"
                        )
                        && properties[name] == json!({"$ref":"#/components/schemas/Sha256Digest"})
                    {
                        continue;
                    }
                    // ADR 0045: AuthorizeConnectionRequest is strictly a write-only input body
                    // accepting access_token and optional refresh_token; it is never returned in
                    // any response schema (verified below).
                    if path == "#/components/schemas/AuthorizeConnectionRequest"
                        && matches!(name.as_str(), "access_token" | "refresh_token")
                    {
                        continue;
                    }
                    if SENSITIVE_NAMES.iter().any(|s| name.contains(s)) {
                        problems.push(format!("{path}: sensitive property name {name}"));
                    }
                }
            }
        },
    );
    walk(&document["paths"], "#/paths".into(), &mut |path, node| {
        if !path.ends_with("/requestBody") {
            return;
        }
        for (media, content) in node["content"].as_object().into_iter().flatten() {
            let (schema, at) = match content.pointer("/schema/$ref").and_then(Value::as_str) {
                Some(reference) => resolve_schema(document, reference),
                None => (&content["schema"], format!("{path}/content/{media}/schema")),
            };
            if schema.get("additionalProperties") != Some(&json!(false))
                && schema.get("unevaluatedProperties") != Some(&json!(false))
            {
                problems.push(format!("{at}: request object must reject unknown fields"));
            }
        }
    });
    walk(&document["paths"], "#/paths".into(), &mut |path, node| {
        if path.contains("/responses/")
            && node.as_str() == Some("#/components/schemas/AuthorizeConnectionRequest")
        {
            problems.push(format!(
                "{path}: write-only AuthorizeConnectionRequest referenced in response"
            ));
        }
    });
    problems
}

#[test]
fn schemas_are_bounded_private_and_requests_strict() {
    let problems = schema_problems(contract());
    assert!(problems.is_empty(), "{problems:#?}");
    // Mutations prove each rule fires, including request strictness on an injected open body.
    let mut weakened = contract().clone();
    let schemas = &mut weakened["components"]["schemas"];
    schemas["Cursor"]
        .as_object_mut()
        .unwrap()
        .remove("maxLength");
    schemas["CapabilityList"]["properties"]["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("maxItems");
    schemas["Capability"]["properties"]["endpoint_url"] = json!({"type": "string", "maxLength": 9});
    schemas["OpenRequest"] = json!({"type": "object", "properties": {}});
    schemas["ClosedRequest"] =
        json!({"type": "object", "properties": {}, "additionalProperties": false});
    weakened["paths"]["/v1/capabilities"]["post"] = json!({"requestBody": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/OpenRequest"}}}}});
    weakened["paths"]["/v1/capabilities"]["put"] = json!({"requestBody": {"content": {
        "application/json": {"schema": {"$ref": "#/components/schemas/ClosedRequest"}}}}});
    let found = schema_problems(&weakened);
    for needle in [
        "Cursor: string without maxLength",
        "capabilities: array without maxItems",
        "sensitive property name endpoint_url",
        "OpenRequest: request object must reject unknown fields",
    ] {
        assert!(
            found.iter().any(|p| p.contains(needle)),
            "{needle}: {found:#?}"
        );
    }
    assert!(
        !found.iter().any(|p| p.contains("ClosedRequest")),
        "{found:#?}"
    );
}

fn fixtures_for(schema: &str, classes: &[&str]) -> Vec<Fixture> {
    let selected: Vec<Fixture> = fixtures()
        .into_iter()
        .filter(|f| f.schema == schema && classes.contains(&f.class.as_str()))
        .collect();
    assert!(!selected.is_empty(), "no fixtures for {schema}");
    selected
}

fn fixture(name: &str) -> Value {
    let found = fixtures()
        .into_iter()
        .find(|f| f.path.ends_with(&format!("/{name}.json")))
        .unwrap_or_else(|| panic!("missing fixture {name}"));
    found.instance
}

#[test]
fn consumer_decodes_every_valid_and_newer_compatible_response() {
    for f in fixtures_for("#/components/schemas/CapabilityList", &["valid", "compat"]) {
        consumer::decode_capabilities(&f.instance).unwrap_or_else(|e| panic!("{}: {e}", f.path));
    }
    for f in fixtures_for("#/components/schemas/Problem", &["valid", "compat"]) {
        consumer::decode_problem(&f.instance).unwrap_or_else(|e| panic!("{}: {e}", f.path));
    }
    for f in fixtures_for("#/components/schemas/PageInfo", &["valid", "compat"]) {
        consumer::decode_page(&f.instance).unwrap_or_else(|e| panic!("{}: {e}", f.path));
    }
    for f in fixtures_for("#/components/schemas/RunEventItem", &["valid", "compat"]) {
        consumer::EventCursor::default()
            .apply(&f.instance)
            .unwrap_or_else(|e| panic!("{}: {e}", f.path));
    }
    for f in fixtures_for("#/components/schemas/ApiVersion", &["valid", "compat"]) {
        consumer::check_api_version(f.instance.as_str().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e:?}", f.path));
    }
    for f in fixtures_for("#/components/schemas/NonNegativeDecimal", &["valid"]) {
        consumer::parse_decimal(f.instance.as_str().unwrap(), true)
            .unwrap_or_else(|e| panic!("{}: {e}", f.path));
    }
    for f in fixtures_for("#/components/schemas/WideNonNegativeDecimal", &["valid"]) {
        consumer::parse_wide_decimal(f.instance.as_str().unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", f.path));
    }
    for (schema, decode) in v1_decoders() {
        for f in fixtures_for(schema, &["valid", "compat"]) {
            decode(&f.instance).unwrap_or_else(|e| panic!("{}: {e}", f.path));
        }
    }
}

type Decode = fn(&Value) -> Result<(), String>;

/// The consumer's decoders of the V1-05 project, conversation, artifact, V1-17 quota and V1-18
/// capacity responses.
fn v1_decoders() -> [(&'static str, Decode); 16] {
    [
        ("#/components/schemas/Run", |v| {
            consumer::decode_run(v).map(drop)
        }),
        ("#/components/schemas/MessagePage", |v| {
            consumer::decode_conversation_operation("listMessages", v)
        }),
        ("#/components/schemas/Project", |v| {
            consumer::decode_project(v).map(drop)
        }),
        ("#/components/schemas/ProjectMemberGrant", |v| {
            consumer::decode_member_grant(v).map(drop)
        }),
        ("#/components/schemas/ResourceShare", |v| {
            consumer::decode_share(v).map(drop)
        }),
        ("#/components/schemas/ConversationAccess", |v| {
            consumer::decode_item_access(v, false).map(drop)
        }),
        ("#/components/schemas/ArtifactAccess", |v| {
            consumer::decode_item_access(v, true).map(drop)
        }),
        ("#/components/schemas/ArtifactRevision", |v| {
            consumer::decode_revision(v).map(drop)
        }),
        ("#/components/schemas/QuotaSummary", |v| {
            consumer::decode_quota_summary(v).map(drop)
        }),
        ("#/components/schemas/QuotaOverride", |v| {
            consumer::decode_quota_override(v).map(drop)
        }),
        ("#/components/schemas/CapacitySummary", |v| {
            consumer::decode_capacity_summary(v).map(drop)
        }),
        ("#/components/schemas/AdminCapacityGroupList", |v| {
            consumer::decode_admin_capacity_groups(v).map(drop)
        }),
        ("#/components/schemas/RetentionPolicy", |v| {
            consumer::decode_retention_policy(v).map(drop)
        }),
        ("#/components/schemas/AdminRetentionStatus", |v| {
            consumer::decode_admin_retention_status(v).map(drop)
        }),
        ("#/components/schemas/RetentionDeadlinesPreview", |v| {
            consumer::decode_retention_deadlines_preview(v).map(drop)
        }),
        ("#/components/schemas/RetentionDeadlinesApplyResult", |v| {
            consumer::decode_retention_deadlines_apply_result(v).map(drop)
        }),
    ]
}

/// What a client may infer from the V1-05 responses, and what it must not.
#[test]
fn consumer_reads_projects_and_items_without_inferring_access() {
    use consumer::{Access, Grantee, Role};
    let project = consumer::decode_project(&fixture("ProjectOwned")).unwrap();
    assert_eq!((project.revision, project.archived), (1, false));
    assert!(project.role.manages_project() && project.defaults.contains_key("model"));
    assert!(!project.id.is_empty() && !project.name.is_empty());
    // A project created before settings existed has an empty name, and is still decoded.
    let legacy = consumer::decode_project(&fixture("ProjectOwned--pre-settings-project")).unwrap();
    assert!(legacy.name.is_empty());
    // A newer role is surfaced but grants no management.
    let newer = consumer::decode_project(&fixture("ProjectOwned--unrecognized-role")).unwrap();
    assert_eq!(newer.role, Role::Unrecognized("steward".into()));
    assert!(!newer.role.manages_project());

    let grant = consumer::decode_member_grant(&fixture("ProjectMemberGrantEditor")).unwrap();
    assert!(matches!(grant.grantee, Grantee::User(_)) && grant.role == Role::Editor);
    assert!(!grant.project_id.is_empty());
    let other = fixture("ProjectMemberGrantEditor--unrecognized-grantee-kind");
    let other = consumer::decode_member_grant(&other).unwrap();
    assert_eq!(other.grantee, Grantee::Unrecognized("service".into()));

    let share = consumer::decode_share(&fixture("ResourceShareRead--whole-project")).unwrap();
    assert_eq!(
        (share.grantee, share.access),
        (Grantee::WholeProject, Access::Read)
    );
    assert_eq!(share.resource_kind, "conversation");
    assert!(!share.resource_id.is_empty());
    // A whole-project grantee never carries an identifier, and a user grantee always does.
    for malformed in [
        json!({"kind": "project", "grantee_id": "x"}),
        json!({"kind": "user"}),
    ] {
        let mut value = fixture("ResourceShareRead");
        value["grantee"] = malformed;
        assert!(consumer::decode_share(&value).is_err());
    }

    let item = consumer::decode_item_access(&fixture("ConversationAccessProject"), false).unwrap();
    assert!(item.project_id.is_some() && item.access == Access::Write && item.can_manage_shares);
    assert!(!item.id.is_empty() && item.last_revision.is_none());
    let personal = fixture("ConversationAccessProject--personal-scope");
    assert!(
        consumer::decode_item_access(&personal, false)
            .unwrap()
            .project_id
            .is_none()
    );
    let newer = fixture("ConversationAccessProject--unrecognized-access");
    let newer = consumer::decode_item_access(&newer, false).unwrap();
    assert_eq!(newer.access, Access::Unrecognized("comment".into()));
    let artifact = consumer::decode_item_access(&fixture("ArtifactAccessShared"), true).unwrap();
    assert_eq!(
        (artifact.last_revision, artifact.access),
        (Some(3), Access::Read)
    );
    // A conversation is not an artifact, and an artifact needs its revision.
    assert!(consumer::decode_item_access(&fixture("ConversationAccessProject"), true).is_err());
    let mut unrevised = fixture("ArtifactAccessShared");
    unrevised.as_object_mut().unwrap().remove("last_revision");
    assert!(consumer::decode_item_access(&unrevised, true).is_err());

    use consumer::RevisionState;
    let revision = consumer::decode_revision(&fixture("ArtifactRevisionActive")).unwrap();
    assert_eq!((revision.revision, revision.size_bytes), (1, 12));
    assert_eq!(revision.display_name.as_deref(), Some("notes.txt"));
    assert!(revision.state.downloadable() && revision.project_id.is_none());
    assert!(!revision.artifact_id.is_empty() && !revision.revision_id.is_empty());
    assert!(revision.media_type.starts_with("text/plain") && revision.sha256.len() == 64);
    let unnamed = consumer::decode_revision(&fixture("ArtifactRevisionActive--unnamed")).unwrap();
    assert!(unnamed.display_name.is_none());
    // Backward compatibility: pre-PR3 / pre-#154 servers omit optional `retained_at`,
    // `purge_after`, and `lost_at`.
    let mut legacy_revision = fixture("ArtifactRevisionActive");
    let obj = legacy_revision.as_object_mut().unwrap();
    obj.remove("retained_at");
    obj.remove("purge_after");
    obj.remove("lost_at");
    let revision_validator = validator_for("#/components/schemas/ArtifactRevision");
    assert!(revision_validator.is_valid(&legacy_revision));
    let decoded_legacy = consumer::decode_revision(&legacy_revision).unwrap();
    assert_eq!(
        (
            decoded_legacy.retained_at,
            decoded_legacy.purge_after,
            decoded_legacy.lost_at,
        ),
        (None, None, None)
    );
    let lost = consumer::decode_revision(&fixture("ArtifactRevisionLost")).unwrap();
    assert_eq!(lost.state, RevisionState::Lost);
    assert!(!lost.state.downloadable());
    assert_eq!(lost.lost_at.as_deref(), Some("2026-11-22T10:15:00.000000Z"));
    // A newer state is surfaced and never offered for download.
    let newer = fixture("ArtifactRevisionActive--unrecognized-state");
    let newer = consumer::decode_revision(&newer).unwrap();
    assert_eq!(
        newer.state,
        RevisionState::Unrecognized("archived_cold".into())
    );
    assert!(!newer.state.downloadable());
    // A revision is numbered from 1, and its digest is exact.
    for (member, value) in [("revision", json!("0")), ("sha256", json!("AB".repeat(32)))] {
        let mut bad = fixture("ArtifactRevisionActive");
        bad[member] = value;
        assert!(consumer::decode_revision(&bad).is_err(), "{member}");
    }

    // MessagePage fixtures cover normal null stop_reason, assistant limit stop, open-vocabulary
    // forward compatibility, legacy omitted stop_reason, and rejection of non-string or user
    // non-null stop_reason.
    for name in [
        "VisibleMessagePage",
        "VisibleMessagePage--assistant-limit-stop",
        "VisibleMessagePage--unrecognized-stop-reason",
    ] {
        consumer::decode_conversation_operation("listMessages", &fixture(name)).unwrap();
    }
    let mut legacy_user = fixture("VisibleMessagePage");
    legacy_user["items"][0]
        .as_object_mut()
        .unwrap()
        .remove("stop_reason");
    let message_page_validator = build(&json!({
        "$ref": format!("{CONTRACT_URI}#/components/schemas/MessagePage")
    }))
    .unwrap();
    assert!(message_page_validator.is_valid(&legacy_user));
    consumer::decode_conversation_operation("listMessages", &legacy_user).unwrap();
    let mut bad_user = fixture("VisibleMessagePage");
    bad_user["items"][0]["stop_reason"] = json!("limit");
    assert!(
        !message_page_validator.is_valid(&bad_user),
        "user message with non-null stop_reason must fail MessagePage schema"
    );
    assert!(
        consumer::decode_conversation_operation("listMessages", &bad_user).is_err(),
        "user message with non-null stop_reason must fail consumer decode"
    );
    for name in [
        "VisibleMessagePage--invalid-stop-reason",
        "VisibleMessagePage--user-non-null-stop-reason",
    ] {
        assert!(
            consumer::decode_conversation_operation("listMessages", &fixture(name)).is_err(),
            "{name} must fail consumer decode"
        );
    }
}

/// The contract's multipart examples of `createArtifact`, as a client sends them: the boundary
/// on their first line.
fn multipart_example(name: &str) -> (String, Vec<u8>) {
    let content = &contract()["paths"]["/v1/artifacts"]["post"]["requestBody"]["content"];
    let wire = content["multipart/form-data"]["examples"][name]["serializedValue"]
        .as_str()
        .unwrap();
    let boundary = wire.lines().next().unwrap().strip_prefix("--").unwrap();
    (
        format!("multipart/form-data; boundary={boundary}"),
        wire.as_bytes().to_vec(),
    )
}

/// The file bytes and form of one body fed in `chunk`-byte pieces, or the parser's refusal.
fn parse_upload(
    content_type: &str,
    body: &[u8],
    chunk: usize,
) -> Result<(Vec<u8>, openmettle_core::multipart::Form), openmettle_core::multipart::Error> {
    let mut parser = openmettle_core::multipart::Parser::new(content_type)?;
    let mut file = Vec::new();
    for piece in body.chunks(chunk) {
        file.extend(parser.feed(piece)?);
    }
    Ok((file, parser.finish()?))
}

/// ADR 0031 wire fixtures: both documented part orders, under different boundaries, yield the
/// same file, media type, display name and metadata, which is why the boundary and part order
/// are not part of the upload's idempotency identity. The bytes match the documented revision;
/// a truncated or repeated part is refused.
#[test]
fn multipart_examples_parse_to_one_upload_in_either_order() {
    use openmettle_core::multipart::Error;
    let metadata = validator_for("#/components/schemas/ArtifactUploadMetadata");
    let (file_first, file_first_body) = multipart_example("fileFirst");
    let (metadata_first, metadata_first_body) = multipart_example("metadataFirst");
    assert_ne!(file_first, metadata_first);
    let expected = parse_upload(&file_first, &file_first_body, usize::MAX).unwrap();
    for (content_type, body) in [
        (&file_first, &file_first_body),
        (&metadata_first, &metadata_first_body),
    ] {
        for chunk in [1, 7, usize::MAX] {
            assert_eq!(parse_upload(content_type, body, chunk).unwrap(), expected);
        }
    }
    let (file, form) = expected;
    let revision = fixture("ArtifactRevisionActive");
    assert_eq!(form.media_type, revision["media_type"]);
    assert_eq!(
        form.display_name.as_deref(),
        revision["display_name"].as_str()
    );
    assert_eq!(file.len().to_string(), revision["size_bytes"]);
    let digest = format!("{:x}", Sha256::digest(&file));
    assert_eq!(digest, revision["sha256"]);
    assert!(metadata.is_valid(&serde_json::from_slice(&form.metadata).unwrap()));

    // An interrupted body: before the closing delimiter, and in the middle of the file.
    let close = b"--openmettle-example-retry--\r\n".len();
    let truncated = &metadata_first_body[..metadata_first_body.len() - close];
    assert_eq!(
        parse_upload(&metadata_first, truncated, 5),
        Err(Error::Truncated)
    );
    let cut = file_first_body
        .windows(5)
        .position(|w| w == b"hello")
        .unwrap()
        + 3;
    assert_eq!(
        parse_upload(&file_first, &file_first_body[..cut], usize::MAX),
        Err(Error::Truncated)
    );
    // The file part again before the whole form: a repeated part.
    let text = std::str::from_utf8(&file_first_body).unwrap();
    let second = text[1..].find("--openmettle-example-a").unwrap() + 1;
    let repeated = format!("{}{text}", &text[..second]);
    assert_eq!(
        parse_upload(&file_first, repeated.as_bytes(), usize::MAX),
        Err(Error::DuplicatePart)
    );
}

#[test]
fn consumer_rejects_invalid_structure_it_depends_on() {
    // Missing required members and wrong JSON types must not decode into defaults.
    let decoders: [(&str, Decode); 4] = [
        ("#/components/schemas/CapabilityList", |v| {
            consumer::decode_capabilities(v).map(drop)
        }),
        ("#/components/schemas/Problem", |v| {
            consumer::decode_problem(v).map(drop)
        }),
        ("#/components/schemas/PageInfo", |v| {
            consumer::decode_page(v).map(drop)
        }),
        ("#/components/schemas/RunEventItem", |v| {
            consumer::EventCursor::default().apply(v).map(drop)
        }),
    ];
    let mut checked = 0;
    for (schema, decode) in decoders.into_iter().chain(v1_decoders()) {
        for f in fixtures_for(schema, &["invalid"]) {
            let keyword = f.expect["keyword"].as_str().unwrap_or("decode");
            let structural = ["type", "required", "not", "decode"].contains(&keyword)
                || (keyword == "const" && f.expect["instancePath"] == "/status")
                || (keyword == "pattern" && f.expect["instancePath"] == "/sequence");
            if structural {
                assert!(decode(&f.instance).is_err(), "{} decoded", f.path);
                checked += 1;
            }
        }
    }
    assert!(checked >= 20, "only {checked} structural fixtures checked");
}

#[test]
fn consumer_keeps_capability_dimensions_independent() {
    let capabilities = consumer::decode_capabilities(&fixture("CapabilitiesMixed")).unwrap();
    let by_id = |id: &str| capabilities.iter().find(|c| c.id == id).unwrap();
    use consumer::{Authorization::*, ReadinessState};
    let chat = by_id("chat.completions");
    assert!(chat.offerable());
    // Installed and observed unavailable, and also denied: neither dimension implies the other.
    let search = by_id("search.web");
    assert!(search.installed && search.authorization == Denied);
    let readiness = search.readiness.as_ref().unwrap();
    assert!(readiness.observed && readiness.state == ReadinessState::Unavailable);
    // Absent: no readiness at all, authorization unknown rather than denied.
    let media = by_id("media.image");
    assert!(!media.installed && media.readiness.is_none() && media.authorization == Unknown);
    // Installed but unobserved: unknown is neither unavailable nor ready.
    let memory = by_id("memory.graph");
    let readiness = memory.readiness.as_ref().unwrap();
    assert!(!readiness.observed && readiness.state == ReadinessState::Unknown);
    assert!(!memory.offerable());
    assert!(by_id("retrieval.rerank").offerable());
    // A newer readiness state is not inferred to be ready.
    let newer =
        consumer::decode_capabilities(&fixture("CapabilitiesMixed--unrecognized-readiness-state"))
            .unwrap();
    assert_eq!(
        newer[0].readiness.as_ref().unwrap().state,
        ReadinessState::Unrecognized("warming".into())
    );
    assert!(!newer[0].offerable());
    let kinds =
        consumer::decode_capabilities(&fixture("CapabilitiesMixed--unrecognized-kind")).unwrap();
    assert_eq!(
        kinds[0].kind,
        consumer::CapabilityKind::Unrecognized("hologram".into())
    );
    assert_eq!(kinds[0].id, "chat.completions");
    assert!(kinds[0].installed && kinds[0].authorization == Allowed);
    assert_eq!(
        kinds[0].readiness.as_ref().unwrap().state,
        ReadinessState::Ready
    );
    assert!(!kinds[0].offerable());
    // A core-only installation decodes to no capabilities and nothing else.
    assert!(
        consumer::decode_capabilities(&fixture("CapabilitiesCoreOnly"))
            .unwrap()
            .is_empty()
    );
    let mut duplicate = fixture("CapabilitiesMixed");
    let first = duplicate["capabilities"][0].clone();
    duplicate["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(first);
    assert!(consumer::decode_capabilities(&duplicate).is_err());
}

#[test]
fn consumer_classifies_problems_without_trusting_unknown_codes() {
    use consumer::Category;
    let expected = [
        ("ProblemValidation", Category::Validation),
        ("ProblemInvalidCursor", Category::InvalidCursor),
        ("ProblemUnauthenticated", Category::Unauthenticated),
        ("ProblemPolicy", Category::Policy),
        ("ProblemNotFound", Category::NotFound),
        ("ProblemConflict", Category::Conflict),
        ("ProblemIdempotencyConflict", Category::IdempotencyConflict),
        ("ProblemPayloadLost", Category::PayloadLost),
        ("ProblemRangeNotSatisfiable", Category::RangeNotSatisfiable),
        ("ProblemQuota", Category::Quota),
        ("ProblemRateLimited", Category::RateLimited),
        ("ProblemInternal", Category::Internal),
        ("ProblemProviderFailure", Category::ProviderFailure),
        ("ProblemUnavailable", Category::Unavailable),
        ("ProblemProvisioning", Category::Provisioning),
        ("ProblemTimeout", Category::Timeout),
    ];
    for (name, category) in expected {
        let problem = consumer::decode_problem(&fixture(name)).unwrap();
        assert_eq!(problem.category, category, "{name}");
        assert!(problem.detail.as_ref().is_none_or(|d| d.len() <= 512));
    }
    let unknown =
        consumer::decode_problem(&fixture("ProblemValidation--unrecognized-code")).unwrap();
    assert_eq!(
        unknown.category,
        Category::OtherClient("schema_epoch_mismatch".into())
    );
    assert_eq!(unknown.status, 400);
}

#[test]
fn consumer_advances_cursor_over_unrecognized_events_and_drops_duplicates() {
    let mut cursor = consumer::EventCursor::default();
    let first = fixture("RunEventItemNote");
    let consumer::Applied::New(event) = cursor.apply(&first).unwrap() else {
        panic!("first event reported as duplicate");
    };
    assert_eq!(event.sequence, 42);
    assert_eq!(
        event.kind,
        consumer::EventKind::Unknown("example.note".into())
    );
    assert_eq!(event.run_id, "0f0e0d0c-0b0a-4908-8706-050403020100");
    assert!(event.data.is_empty());
    assert_eq!(
        cursor.last_id.as_deref(),
        Some("cnVuLWV2ZW50LWN1cnNvci00Mg")
    );
    // Replaying the same item after reconnect has no second effect.
    assert!(matches!(
        cursor.apply(&first).unwrap(),
        consumer::Applied::Duplicate
    ));
    let mut later = fixture("RunEventItemNote--sequence-signed-64-maximum");
    later["id"] = json!("bGF0ZXItY3Vyc29y");
    let consumer::Applied::New(event) = cursor.apply(&later).unwrap() else {
        panic!("later event reported as duplicate");
    };
    assert_eq!(event.sequence, i64::MAX);
    assert_eq!(cursor.last_id.as_deref(), Some("bGF0ZXItY3Vyc29y"));
    assert!(matches!(
        cursor.apply(&first).unwrap(),
        consumer::Applied::Duplicate
    ));
    assert_eq!(cursor.last_id.as_deref(), Some("bGF0ZXItY3Vyc29y"));
    // Undecodable items do not advance the cursor.
    for name in [
        "RunEventItemNote--sequence-above-signed-64",
        "RunEventItemNote--data-not-json",
        "RunEventItemNote--sequence-zero",
        "RunEventItemNote--sequence-json-number",
    ] {
        assert!(cursor.apply(&fixture(name)).is_err(), "{name}");
        assert_eq!(cursor.last_id.as_deref(), Some("bGF0ZXItY3Vyc29y"));
    }
}

#[test]
fn configured_run_reads_reach_primary_session_validation() {
    let dir = auth_config_support::Dir::new();
    let mut document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    document["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let path = dir.write("auth.json", document.to_string().as_bytes());
    let (api, _database) = Api::start(Some(&path));
    let token = format!("{}.{}", "A".repeat(43), "A".repeat(43));
    for suffix in ["", "/events"] {
        let request = format!(
            "GET /v1/runs/00000000-0000-0000-0000-000000000001{suffix} HTTP/1.1\r\nauthorization: Bearer {token}\r\n\r\n"
        );
        let (status, _, _) = api.exchange(&request).unwrap();
        assert!(matches!(status, 503 | 504));
    }
}

#[test]
fn serialized_lifecycle_replays_to_the_snapshot() {
    let example = pointer_get(
        contract(),
        "#/components/mediaTypes/RunEventStream/examples/lifecycle",
    );
    let frames: Vec<_> = example["serializedValue"]
        .as_str()
        .unwrap()
        .split("\n\n")
        .filter_map(consumer::sse_item)
        .collect();
    assert_eq!(json!(frames), example["dataValue"]);
    let mut position = consumer::EventCursor::default();
    let snapshot = consumer::decode_run(&fixture("RunSnapshot")).unwrap();
    let mut kinds = vec![];
    for frame in frames {
        assert!(validator_for("#/components/schemas/RunEventItem").is_valid(&frame));
        let consumer::Applied::New(event) = position.apply(&frame).unwrap() else {
            panic!("duplicate sequence")
        };
        assert_eq!(event.run_id, snapshot.run_id);
        kinds.push(event.kind);
    }
    use consumer::{EventKind, Reason};
    assert_eq!(
        kinds,
        [
            EventKind::Created,
            EventKind::Started,
            EventKind::Cancelled(Reason::Requested)
        ]
    );
    assert_eq!(snapshot.terminal.unwrap().kind, kinds.pop().unwrap());
    assert_eq!(snapshot.state, "cancelled");
    assert_eq!(position.last_id.unwrap(), snapshot.resume_cursor);
    assert_eq!(position.last_sequence.unwrap(), snapshot.last_sequence);
    assert_ne!(snapshot.conversation_id, snapshot.run_id);
    assert_eq!(snapshot.created_at, "2026-11-20T09:00:01.000000Z");
}

#[test]
fn consumer_rejects_unsupported_versions_and_imprecise_numbers() {
    use consumer::VersionError;
    assert_eq!(consumer::check_api_version("1.0"), Ok(0));
    assert_eq!(consumer::check_api_version("1.12"), Ok(12));
    assert_eq!(
        consumer::check_api_version("2.0"),
        Err(VersionError::UnsupportedMajor("2".into()))
    );
    for malformed in ["1", "1.01", "01.0", "v1.0", "1.0.0", ""] {
        assert!(
            matches!(
                consumer::check_api_version(malformed),
                Err(VersionError::Malformed(_))
            ),
            "{malformed}"
        );
    }
    assert_eq!(
        consumer::parse_decimal("9223372036854775807", true),
        Ok(i64::MAX)
    );
    for rejected in ["9223372036854775808", "007", "-1", "1e3", "", " 1"] {
        assert!(
            consumer::parse_decimal(rejected, true).is_err(),
            "{rejected}"
        );
    }
    assert!(consumer::parse_decimal("0", false).is_err());
    // 2^53 + 1 survives exactly as a string where a JSON number decoded as f64 would not.
    assert_eq!(
        consumer::parse_decimal("9007199254740993", true),
        Ok(9_007_199_254_740_993)
    );
}

/// Every contract path with a synthetic identifier in each path parameter.
fn concrete_paths() -> Vec<String> {
    contract()["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(|template| {
            template
                .split('/')
                .map(|segment| match segment.starts_with('{') {
                    true => "0f0e0d0c-0b0a-4908-8706-050403020100",
                    false => segment,
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

/// The API binary over a database address that accepts and never answers, optionally with an
/// auth settings document. Killed on drop.
struct Api(std::process::Child, String);
impl Api {
    fn start(auth: Option<&str>) -> (Self, std::net::TcpListener) {
        use std::{
            net::TcpListener,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let bind = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_openmettle-api"));
        scrub_env(&mut command);
        command
            .env("OPENMETTLE_API_BIND", &bind)
            .env(
                "OPENMETTLE_API_DATABASE_URL",
                format!(
                    "postgres://fixture@{}/fixture?sslmode=disable",
                    unavailable.local_addr().unwrap()
                ),
            )
            .env("OPENMETTLE_API_DB_TIMEOUT_MS", "150")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(path) = auth {
            // ADR 0030: sign-in needs the issuance pool, under its own user; never contacted.
            command.env("OPENMETTLE_API_AUTH_CONFIG", path).env(
                "OPENMETTLE_API_ISSUANCE_DATABASE_URL",
                format!(
                    "postgres://fixture-issuance@{}/fixture?sslmode=disable",
                    unavailable.local_addr().unwrap()
                ),
            );
        }
        let mut api = Self(command.spawn().unwrap(), bind);
        let deadline = Instant::now() + Duration::from_secs(15);
        while api
            .exchange("GET /healthz HTTP/1.1\r\n\r\n")
            .is_none_or(|(status, _, _)| status != 200)
        {
            assert!(api.0.try_wait().unwrap().is_none(), "API exited");
            assert!(Instant::now() < deadline, "API did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        (api, unavailable)
    }

    /// One request on a new connection: the status, the lowercase head and the body. `request`
    /// is the request line and any header lines, ending with a blank line and an optional body.
    fn exchange(&self, request: &str) -> Option<(u16, String, String)> {
        use std::{
            io::{Read, Write},
            net::TcpStream,
            time::Duration,
        };
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        let request = format!("{head}\r\nhost: localhost\r\nconnection: close\r\n\r\n{body}");
        let address = self.1.parse().unwrap();
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(300)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream.write_all(request.as_bytes()).ok()?;
        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;
        let (head, body) = response.split_once("\r\n\r\n")?;
        let status = head.get(9..12)?.parse().ok()?;
        Some((status, head.to_ascii_lowercase(), body.to_owned()))
    }
}
impl Drop for Api {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn api_does_not_serve_contract_routes() {
    // The `/v1` routes are mounted only with OPENMETTLE_API_AUTH_CONFIG (ADR 0027 PR4b). An
    // API started without it must return 404 for every contract path, implemented or not.
    let (api, _database) = Api::start(None);
    for path in concrete_paths() {
        let (status, head, _) = api
            .exchange(&format!("GET {path} HTTP/1.1\r\n\r\n"))
            .unwrap();
        assert_eq!(status, 404, "{path}");
        assert!(!head.contains("openmettle-api-version"), "{path}: {head}");
    }
}

/// ADR 0007 through the real API binary, mounted with a version-2 document and its native
/// profile, without PostgreSQL. Every refusal decided before the database, and the
/// `unavailable` answer of a well-formed credential the primary cannot check, is a versioned,
/// uncacheable problem that conforms to the canonical `Problem` schema, is classified by the
/// independent consumer and echoes no request value.
#[test]
fn mounted_api_problems_conform_to_the_contract() {
    let dir = auth_config_support::Dir::new();
    let document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    let path = dir.write("auth.json", document.to_string().as_bytes());
    let (api, _database) = Api::start(Some(&path));
    let validator = validator_for("#/components/schemas/Problem");
    // Well-formed credentials: the shape check passes and validation needs the primary.
    let credential = format!("{}.{}", "A".repeat(43), "A".repeat(43));
    let bearer = format!("authorization: Bearer {credential}\r\n");
    let cookie = format!("cookie: __Host-openmettle-session={credential}\r\n");
    let key = "idempotency-key: CANARY-key\r\n";
    let json = "content-type: application/json\r\n";
    let id = "0f0e0d0c-0b0a-4908-8706-050403020100";
    let unknown = r#"{"name":"CANARY-name","folder_id":"CANARY-folder"}"#;
    use consumer::Category::{NotFound, Provisioning, Unauthenticated, Unavailable, Validation};
    let multipart = "content-type: multipart/form-data; boundary=CANARY\r\n";
    let revision = format!("/v1/artifacts/{id}/revisions/{id}");
    let mut cases: Vec<(String, consumer::Category)> = Vec::new();
    // Every implemented operation refuses an anonymous request before any other check.
    for (template, item) in contract()["paths"].as_object().unwrap() {
        let target = template.replace(['{', '}'], "").replace("project_id", id);
        let target = target
            .replace("conversation_id", id)
            .replace("artifact_id", id)
            .replace("revision_id", id)
            .replace("run_id", id)
            .replace("approval_id", id)
            .replace("scope_id", id)
            .replace("resource_kind", "storage_bytes");
        for method in item.as_object().unwrap().keys() {
            let method = method.to_ascii_uppercase();
            cases.push((
                format!("{method} {target} HTTP/1.1\r\ncontent-length: 0\r\n\r\n"),
                Unauthenticated,
            ));
        }
    }
    cases.extend([
        // Both channels, a repeated bearer and a cookie write without the configured Origin.
        (format!("GET /v1/capabilities HTTP/1.1\r\n{cookie}{bearer}\r\n"), Unauthenticated),
        (format!("GET /v1/capabilities HTTP/1.1\r\n{bearer}{bearer}\r\n"), Unauthenticated),
        (
            format!("POST /v1/projects HTTP/1.1\r\n{cookie}{key}{json}content-length: 2\r\n\r\n{{}}"),
            Unauthenticated,
        ),
        // Request shape, decided before the primary is asked.
        (
            format!("POST /v1/projects HTTP/1.1\r\n{bearer}{json}content-length: 2\r\n\r\n{{}}"),
            Validation,
        ),
        (
            format!(
                "POST /v1/projects HTTP/1.1\r\n{bearer}{key}{json}content-length: {}\r\n\r\n{unknown}",
                unknown.len()
            ),
            Validation,
        ),
        (format!("GET /v1/projects/CANARY-id HTTP/1.1\r\n{bearer}\r\n"), Validation),
        (format!("GET /v1/artifacts/{id}/revisions/CANARY-id HTTP/1.1\r\n{bearer}\r\n"), Validation),
        (format!("GET /v1/runs/{id} HTTP/1.1\r\n{bearer}\r\n"), Provisioning),
        (format!("GET /v1/runs/{id}/events HTTP/1.1\r\n{cookie}\r\n"), Provisioning),
        (format!("GET /v1/runs/{id}/events?cursor=x HTTP/1.1\r\n{cookie}\r\n"), Validation),
        // Artifact uploads: the key, the query and the multipart type precede the store check.
        (format!("POST /v1/artifacts HTTP/1.1\r\n{bearer}{multipart}\r\n"), Validation),
        (
            format!("POST /v1/artifacts?scope_id=CANARY-scope HTTP/1.1\r\n{bearer}{key}{multipart}\r\n"),
            Validation,
        ),
        (
            format!("POST /v1/artifacts?max_bytes=0 HTTP/1.1\r\n{bearer}{key}{multipart}\r\n"),
            Validation,
        ),
        (format!("POST /v1/artifacts HTTP/1.1\r\n{bearer}{key}{json}\r\n"), Validation),
        (
            format!("GET {revision}/content HTTP/1.1\r\n{bearer}range: bytes=0-1,CANARY\r\n\r\n"),
            Validation,
        ),
        // Without ARTIFACTS_DIR, payload operations are refused before the session is checked;
        // revision metadata still needs the primary.
        (format!("POST /v1/artifacts HTTP/1.1\r\n{bearer}{key}{multipart}\r\n"), Provisioning),
        (
            format!("POST /v1/artifacts/{id}/revisions HTTP/1.1\r\n{cookie}origin: https://app.example.test\r\n{key}{multipart}\r\n"),
            Provisioning,
        ),
        (format!("GET {revision}/content HTTP/1.1\r\n{bearer}\r\n"), Provisioning),
        (format!("GET {revision} HTTP/1.1\r\n{bearer}\r\n"), Unavailable),
        // Quota routes: pre-DB path, query, idempotency-key and body validation.
        (format!("GET /v1/quotas/personal?extra=1 HTTP/1.1\r\n{bearer}\r\n"), Validation),
        (format!("GET /v1/projects/CANARY-id/quotas HTTP/1.1\r\n{bearer}\r\n"), Validation),
        (
            format!("PUT /v1/admin/scopes/CANARY-id/quotas/usage_tokens HTTP/1.1\r\n{bearer}{key}{json}content-length: 40\r\n\r\n{{\"hard_limit\":\"10\",\"reason\":\"CANARY-r\"}}"),
            Validation,
        ),
        (
            format!("PUT /v1/admin/scopes/{id}/quotas/CANARY_res HTTP/1.1\r\n{bearer}{key}{json}content-length: 40\r\n\r\n{{\"hard_limit\":\"10\",\"reason\":\"CANARY-r\"}}"),
            Validation,
        ),
        (
            format!("PUT /v1/admin/scopes/{id}/quotas/round_cap HTTP/1.1\r\n{bearer}{key}{json}content-length: 42\r\n\r\n{{\"hard_limit\":\"1001\",\"reason\":\"CANARY-r\"}}"),
            Validation,
        ),
        (
            format!("PUT /v1/admin/scopes/{id}/quotas/usage_tokens HTTP/1.1\r\n{bearer}{json}content-length: 40\r\n\r\n{{\"hard_limit\":\"10\",\"reason\":\"CANARY-r\"}}"),
            Validation,
        ),
        (
            format!("POST /v1/admin/scopes/{id}/quotas/usage_tokens/revoke HTTP/1.1\r\n{bearer}{key}{json}content-length: 13\r\n\r\n{{\"reason\":\"\"}}"),
            Validation,
        ),
        (format!("GET /v1/quotas/personal HTTP/1.1\r\n{bearer}\r\n"), Unavailable),
        // Capacity routes: query rejection before DB, wrong method 404, unreachable primary 503.
        (format!("GET /v1/capacity?extra=1 HTTP/1.1\r\n{bearer}\r\n"), Validation),
        (
            format!("GET /v1/admin/capacity/groups?extra=1 HTTP/1.1\r\n{bearer}\r\n"),
            Validation,
        ),
        (format!("GET /v1/capacity HTTP/1.1\r\n{bearer}\r\n"), Unavailable),
        (
            format!("GET /v1/admin/capacity/groups HTTP/1.1\r\n{bearer}\r\n"),
            Unavailable,
        ),
        ("POST /v1/capacity HTTP/1.1\r\n\r\n".into(), NotFound),
        // Paths and methods the contract does not define.
        ("GET /v1/CANARY-path HTTP/1.1\r\n\r\n".into(), NotFound),
        ("DELETE /v1/capabilities HTTP/1.1\r\n\r\n".into(), NotFound),
        // Well-formed credentials on each channel; the primary never answers.
        (format!("GET /v1/capabilities HTTP/1.1\r\n{bearer}\r\n"), Unavailable),
        (format!("GET /v1/capabilities HTTP/1.1\r\n{cookie}\r\n"), Unavailable),
    ]);
    for (request, category) in cases {
        let line = request.lines().next().unwrap().to_owned();
        let (status, head, body) = api.exchange(&request).unwrap();
        let problem: Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert!(validator.is_valid(&problem), "{line}: {problem}");
        let decoded = consumer::decode_problem(&problem).unwrap();
        assert_eq!(
            (decoded.status, decoded.category),
            (status, category),
            "{line}"
        );
        assert_eq!(problem["type"], "about:blank", "{line}");
        for header in [
            "content-type: application/problem+json",
            "openmettle-api-version: 1.0",
            "cache-control: no-store",
        ] {
            assert!(head.contains(header), "{line}: {head}");
        }
        let version = head
            .lines()
            .find_map(|l| l.strip_prefix("openmettle-api-version: "))
            .unwrap();
        assert_eq!(consumer::check_api_version(version), Ok(0), "{line}");
        assert!(!head.contains("set-cookie"), "{line}: {head}");
        for planted in ["CANARY", "AAAAAAAAAA", id] {
            assert!(!body.contains(planted), "{line}: {body}");
        }
    }
    // HEAD answers the GET's status and headers without a body.
    let (status, head, body) = api
        .exchange(&format!("HEAD {revision}/content HTTP/1.1\r\n{bearer}\r\n"))
        .unwrap();
    assert_eq!((status, body.as_str()), (503, ""));
    assert!(
        head.contains("openmettle-api-version: 1.0") && head.contains("cache-control: no-store")
    );
}

#[tokio::test]
async fn evaluated_capabilities_match_canonical_schema() {
    use openmettle_core::capabilities::*;
    use std::time::Duration;
    let validator = validator_for("#/components/schemas/Capability");
    for installed in [false, true] {
        for enabled in [false, true] {
            for authorization in [
                Authorization::Allowed,
                Authorization::Denied,
                Authorization::Unknown,
            ] {
                for outcome in [
                    Some(Observation::Status(Status::Ready)),
                    Some(Observation::Status(Status::Degraded)),
                    Some(Observation::Status(Status::Unavailable)),
                    Some(Observation::Status(Status::Unknown)),
                    Some(Observation::ProviderFailure),
                    None, // A yielding observer that never completes.
                ] {
                    let result = evaluate(
                        Input {
                            installed,
                            enabled,
                            caller: Caller::Visible(authorization),
                        },
                        Duration::from_millis(1),
                        || async {
                            match outcome {
                                Some(value) => value,
                                None => std::future::pending().await,
                            }
                        },
                    )
                    .await
                    .unwrap();
                    // Test projection only: production has no HTTP serializer. A fixed
                    // canonical timestamp stands in for the actual SystemTime metadata.
                    let mut wire = json!({"id":"synthetic.tool", "kind":"tool", "installed":result.installed, "authorization":match result.authorization { Authorization::Allowed => Some(true), Authorization::Denied => Some(false), Authorization::Unknown => None }});
                    if let Some(r) = result.readiness {
                        let mut readiness = json!({"state":match r.status { Status::Ready => "ready", Status::Degraded => "degraded", Status::Unavailable => "unavailable", Status::Unknown => "unknown" }});
                        if r.observed_at.is_some() {
                            readiness["observed_at"] = json!("2026-11-17T09:00:00.000000Z");
                        }
                        if let Some(reason) = r.reason {
                            readiness["reason"] = json!(match reason {
                                Reason::Disabled => "disabled",
                                Reason::Timeout => "timeout",
                                Reason::ProviderFailure => "provider_failure",
                            });
                        }
                        wire["readiness"] = readiness;
                    }
                    assert!(validator.is_valid(&wire), "{:?}", errors(&validator, &wire));
                    let decoded = consumer::decode_capabilities(&json!({
                        "generated_at": "2026-11-17T09:00:00.000000Z",
                        "capabilities": [wire],
                    }))
                    .unwrap();
                    assert_eq!(decoded[0].offerable(), result.offered());
                }
            }
        }
    }
}

#[test]
fn consumer_reads_each_managed_conversation_operation() {
    let operations = [
        "createConversation",
        "listConversations",
        "createBranch",
        "listBranches",
        "getBranch",
        "listMessages",
        "listModels",
        "listPresets",
        "getPreset",
        "previewConfiguration",
        "createRun",
        "cancelRun",
        "listRunApprovals",
        "decideRunApproval",
    ];
    let mut found = BTreeSet::new();
    for path in contract()["paths"].as_object().unwrap().values() {
        for op in path.as_object().unwrap().values() {
            let id = op["operationId"].as_str().unwrap();
            if !operations.contains(&id) {
                continue;
            }
            for (status, r) in op["responses"].as_object().unwrap() {
                if !status.starts_with('2') {
                    continue;
                }
                let schema = r
                    .pointer("/content/application~1json/schema/$ref")
                    .unwrap()
                    .as_str()
                    .unwrap();
                let all = fixtures_for(schema, &["valid", "compat"]);
                assert!(!all.is_empty(), "{id} {status}");
                for f in all {
                    consumer::decode_conversation_operation(id, &f.instance)
                        .unwrap_or_else(|e| panic!("{id} {}: {e}", f.path));
                }
            }
            found.insert(id);
        }
    }
    assert_eq!(found, operations.into_iter().collect());
    let run = consumer::decode_run(&fixture("RunWithBranch")).unwrap();
    assert!(run.branch_id.is_some() && run.input_message_id.is_some());
    let legacy = consumer::decode_run(&fixture("RunSnapshot")).unwrap();
    assert!(legacy.branch_id.is_none() && legacy.input_message_id.is_none());
}

#[test]
fn auth_settings_validate_optional_catalog_and_admission_limits_offline() {
    use openmettle_core::auth_config::{Error, load};
    let dir = auth_config_support::Dir::new();
    let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    let check = |doc: &Value| {
        load(Path::new(
            &dir.write("auth.json", &serde_json::to_vec(doc).unwrap()),
        ))
        .map(drop)
    };
    assert!(check(&doc).is_ok());
    doc["catalog_file"] = json!(dir.write(
        "catalog.json",
        br#"{"version":1,"revision":"empty","models":{},"presets":{}}"#
    ));
    doc["admission_limits"] = json!({"live_per_actor":1,"live_per_scope":2,"queued_in_instance":3,"queue_timeout_seconds":4,"round_cap":5});
    assert!(check(&doc).is_ok());
    for key in [
        "live_per_actor",
        "live_per_scope",
        "queued_in_instance",
        "queue_timeout_seconds",
        "round_cap",
    ] {
        let mut invalid = doc.clone();
        invalid["admission_limits"][key] = json!(0);
        assert_eq!(check(&invalid), Err(Error::AdmissionLimits));
        invalid["admission_limits"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert_eq!(check(&invalid), Err(Error::MissingField));
    }
    doc["catalog_file"] = json!(dir.write("catalog.json", b"invalid"));
    assert_eq!(check(&doc), Err(Error::Catalog));
}

#[test]
fn consumer_recognizes_the_approval_lifecycle() {
    use consumer::{Applied, EventKind, Reason};
    for (example, kind) in [
        ("RunEventApprovalRequested", EventKind::ApprovalRequested),
        ("RunEventWaiting", EventKind::Waiting(Reason::Approval)),
        ("RunEventApprovalDecided", EventKind::ApprovalDecided),
        ("RunEventResumed", EventKind::Resumed),
        (
            "RunEventApprovalExpired",
            EventKind::Failed(Reason::ApprovalExpired),
        ),
        (
            "RunEventInvalidWait",
            EventKind::Failed(Reason::InvalidWait),
        ),
    ] {
        let Applied::New(event) = consumer::EventCursor::default()
            .apply(&fixture(example))
            .unwrap()
        else {
            panic!("missing event")
        };
        assert_eq!(event.kind, kind);
    }
}

#[test]
fn consumer_decodes_wide_quota_counters_overrides_and_closed_problem_quota() {
    use consumer::{Category, ProblemQuota, QuotaStatus};

    // WideNonNegativeDecimal accepts 3-column > i64::MAX sums while NonNegativeDecimal refuses them.
    let wide_validator = validator_for("#/components/schemas/WideNonNegativeDecimal");
    let narrow_validator = validator_for("#/components/schemas/NonNegativeDecimal");
    let three_col = json!("27670116110564327421");
    assert!(wide_validator.is_valid(&three_col));
    assert!(!narrow_validator.is_valid(&three_col));
    assert_eq!(
        consumer::parse_wide_decimal("27670116110564327421"),
        Ok(27_670_116_110_564_327_421u128)
    );
    assert_eq!(
        consumer::parse_wide_decimal(&"9".repeat(38)),
        Ok(99_999_999_999_999_999_999_999_999_999_999_999_999u128)
    );
    for bad in ["100000000000000000000000000000000000000", "01", "-1", ""] {
        assert!(consumer::parse_wide_decimal(bad).is_err(), "{bad}");
    }

    let personal = consumer::decode_quota_summary(&fixture("QuotaSummaryPersonal")).unwrap();
    assert_eq!(personal.scope_id, "10111213-1415-4617-8819-1a1b1c1d1e1f");
    assert_eq!(personal.scope_kind, "personal");
    assert!(personal.has_actor_execution);
    assert_eq!(personal.round_cap_limit, Some(25));
    assert_eq!(personal.storage.limit_bytes, Some(1_073_741_824));
    assert_eq!(personal.storage.limit_source, "default");
    assert_eq!(
        (
            personal.storage.active_bytes,
            personal.storage.retained_bytes,
            personal.storage.reserved_bytes,
            personal.storage.charged_bytes,
            personal.storage.remaining_bytes,
        ),
        (4096, 1024, 0, 5120, Some(1_073_736_704))
    );
    assert_eq!(personal.storage.status, QuotaStatus::Ok);
    assert_eq!(personal.usage[0].resource_kind, "usage_tokens");
    assert_eq!(personal.usage[0].window_kind, "windowed");
    assert_eq!(personal.usage[0].limit, Some(1_000_000));
    assert_eq!(personal.usage[0].limit_source, "override");
    assert_eq!(
        personal.usage[0].active_used,
        27_670_116_110_564_327_421u128
    );
    assert_eq!(personal.usage[0].reserved_held, 0);
    assert_eq!(personal.usage[0].remaining, Some(0));
    assert_eq!(personal.usage[0].status, QuotaStatus::HardLimit);
    assert_eq!(personal.usage[1].unit.as_deref(), Some("usd_micros"));
    assert_eq!(personal.device_reservations.reserved_held, 1);
    assert_eq!(personal.device_reservations.limit, Some(2));
    assert_eq!(personal.device_reservations.status, QuotaStatus::Ok);
    assert_eq!(personal.warnings.len(), 1);
    assert_eq!(personal.warnings[0].resource_kind, "usage_cost_micros");
    assert_eq!(personal.warnings[0].threshold_pct, 80);
    assert_eq!(
        personal.warnings[0].dedupe_bucket,
        "2026-11-20T00:00:00.000000Z"
    );
    assert_eq!(
        personal.warnings[0].triggered_at,
        "2026-11-20T11:59:00.000000Z"
    );

    let project = consumer::decode_quota_summary(&fixture("QuotaSummaryProject")).unwrap();
    assert_eq!(project.scope_kind, "project");
    assert!(!project.has_actor_execution);
    assert_eq!(project.storage.status, QuotaStatus::Unconfigured);
    assert!(project.warnings.is_empty());

    for invalid_summary in [
        "QuotaSummaryPersonal--missing-live-per-actor",
        "QuotaSummaryPersonal--missing-executing-per-actor",
        "QuotaSummaryProject--with-live-per-actor",
        "QuotaSummaryProject--with-executing-per-actor",
        "QuotaSummaryProject--with-null-live-per-actor",
        "QuotaSummaryProject--with-null-executing-per-actor",
    ] {
        assert!(
            consumer::decode_quota_summary(&fixture(invalid_summary)).is_err(),
            "{invalid_summary}"
        );
    }

    let max_utf8_reason = "é".repeat(128);
    let over_utf8_reason = "é".repeat(129);
    assert_eq!(max_utf8_reason.len(), 256);
    assert_eq!(over_utf8_reason.len(), 258);
    assert!(consumer::encode_quota_override_set_request(100, None, &max_utf8_reason).is_ok());
    assert!(consumer::encode_quota_override_revoke_request(&max_utf8_reason).is_ok());
    for bad in ["", over_utf8_reason.as_str(), "nul\0byte"] {
        assert!(
            consumer::encode_quota_override_set_request(100, None, bad).is_err(),
            "{bad:?}"
        );
        assert!(
            consumer::encode_quota_override_revoke_request(bad).is_err(),
            "{bad:?}"
        );
    }

    let compat =
        consumer::decode_quota_summary(&fixture("QuotaSummaryPersonal--unrecognized-status"))
            .unwrap();
    assert_eq!(
        compat.storage.status,
        QuotaStatus::Unrecognized("soft_grace".into())
    );

    let active = consumer::decode_quota_override(&fixture("QuotaOverrideActive")).unwrap();
    assert_eq!(active.scope_id, "10111213-1415-4617-8819-1a1b1c1d1e1f");
    assert_eq!(active.scope_kind, "personal");
    assert_eq!(active.resource_kind, "usage_tokens");
    assert_eq!((active.hard_limit, active.revision), (500_000, 1));
    assert_eq!(
        active.expires_at.as_deref(),
        Some("2026-12-31T23:59:59.000000Z")
    );
    assert!(active.revoked_at.is_none());
    assert_eq!(active.updated_at, "2026-11-20T12:00:00.000000Z");

    let revoked = consumer::decode_quota_override(&fixture("QuotaOverrideRevoked")).unwrap();
    assert_eq!(revoked.revision, 2);
    assert!(revoked.revoked_at.is_some());

    let with_quota =
        consumer::decode_problem(&fixture("ProblemQuota--with-quota-extension")).unwrap();
    assert_eq!(with_quota.category, Category::Quota);
    assert_eq!(
        with_quota.quota,
        Some(ProblemQuota {
            resource_kind: "usage_tokens".into(),
            scope_kind: "personal".into(),
        })
    );
    assert!(consumer::decode_problem(&fixture("ProblemQuota--quota-unknown-field")).is_err());
    assert!(consumer::decode_problem(&fixture("ProblemQuota--quota-bad-scope-kind")).is_err());
}

#[test]
fn consumer_decodes_capacity_visibility_and_admin_group_observations() {
    use consumer::CapacityAvailability as A;

    let mixed = consumer::decode_capacity_summary(&fixture("CapacitySummaryMixed")).unwrap();
    assert_eq!(mixed.len(), 4);
    assert_eq!(
        (
            mixed[0].profile.as_str(),
            &mixed[0].availability,
            mixed[0].estimated_wait_seconds
        ),
        ("chat.base", &A::Ready, None)
    );
    assert!(mixed[0].availability.ready_now());
    assert_eq!(
        (
            mixed[1].profile.as_str(),
            &mixed[1].availability,
            mixed[1].estimated_wait_seconds
        ),
        ("media.image", &A::Busy, None)
    );
    assert_eq!(
        (
            mixed[2].profile.as_str(),
            &mixed[2].availability,
            mixed[2].estimated_wait_seconds
        ),
        ("media.video", &A::QueuedEstimate, Some(30))
    );
    assert_eq!(
        (
            mixed[3].profile.as_str(),
            &mixed[3].availability,
            mixed[3].estimated_wait_seconds
        ),
        ("eval.large", &A::Unavailable, None)
    );

    assert!(
        consumer::decode_capacity_summary(&fixture("CapacitySummaryEmpty"))
            .unwrap()
            .is_empty()
    );
    let compat = consumer::decode_capacity_summary(&fixture(
        "CapacitySummaryMixed--unrecognized-availability",
    ))
    .unwrap();
    assert_eq!(compat[0].availability, A::Unrecognized("warming".into()));
    assert!(!compat[0].availability.ready_now());

    for invalid in [
        "CapacitySummaryMixed--queued-estimate-missing-wait",
        "CapacitySummaryMixed--ready-with-wait",
        "CapacitySummaryMixed--zero-wait",
    ] {
        assert!(
            consumer::decode_capacity_summary(&fixture(invalid)).is_err(),
            "{invalid}"
        );
    }

    let groups =
        consumer::decode_admin_capacity_groups(&fixture("AdminCapacityGroupListTypical")).unwrap();
    assert_eq!(groups.len(), 2);
    assert!(groups[0].admits_bursts);
    assert_eq!(
        (groups[0].controller_epoch, groups[0].observation_revision),
        (3, 12)
    );
    assert_eq!(
        groups[0].observed_at.as_deref(),
        Some("2026-11-25T12:00:00.123456Z")
    );
    assert_eq!(groups[0].totals.effective_grantable_bytes, 8_589_934_592);
    assert_eq!(groups[0].devices.len(), 2);
    assert_eq!(
        groups[0].devices[0].effective_grantable_bytes,
        1_073_741_824
    );
    assert!(!groups[1].admits_bursts);
    assert!(groups[1].observed_at.is_none());
    assert!(groups[1].devices.is_empty());

    let wide = consumer::decode_admin_capacity_groups(&fixture(
        "AdminCapacityGroupListTypical--wide-group-totals",
    ))
    .unwrap();
    assert_eq!(wide[0].totals.total_bytes, 27_670_116_110_564_327_421u128);
    assert!(
        consumer::decode_admin_capacity_groups(&fixture(
            "AdminCapacityGroupListTypical--device-bytes-above-signed-64"
        ))
        .is_err()
    );
}

#[test]
fn consumer_reads_retention_status_policy_and_deadlines() {
    let retained = consumer::decode_revision(&fixture("ArtifactRevisionRetained")).unwrap();
    assert_eq!(retained.state, consumer::RevisionState::Retained);
    assert_eq!(
        retained.retained_at.as_deref(),
        Some("2026-11-21T09:00:00.000000Z")
    );
    assert_eq!(
        retained.purge_after.as_deref(),
        Some("2026-12-21T09:00:00.000000Z")
    );

    let status =
        consumer::decode_admin_retention_status(&fixture("AdminRetentionStatusOpen")).unwrap();
    assert!(status.restore_gate.open);
    assert_eq!(status.policy.revision, 1);
    assert_eq!(status.deletion_journal.journal_seq, 4);

    let closed =
        consumer::decode_admin_retention_status(&fixture("AdminRetentionStatusOpen--closed-gate"))
            .unwrap();
    assert!(!closed.restore_gate.open);
    assert_eq!(closed.restore_gate.snapshot_journal_seq, Some(2));
    assert_eq!(closed.restore_gate.required_journal_seq, Some(4));
    assert!(!closed.restore_gate.coverage_complete);

    let policy = consumer::decode_retention_policy(&fixture("RetentionPolicyTypical")).unwrap();
    assert_eq!((policy.revision, policy.grace_seconds), (2, 604_800));

    let preview =
        consumer::decode_retention_deadlines_preview(&fixture("RetentionDeadlinesPreviewTypical"))
            .unwrap();
    assert_eq!(
        (
            preview.policy_revision,
            preview.affected_revisions,
            preview.affected_bytes
        ),
        (2, 3, 4096)
    );

    let applied = consumer::decode_retention_deadlines_apply_result(&fixture(
        "RetentionDeadlinesApplyResultTypical",
    ))
    .unwrap();
    assert_eq!(applied, preview);
}

#[test]
fn consumer_reads_external_connections_pages_and_shares() {
    let pending = consumer::decode_connection(&fixture("ConnectionPendingAuth")).unwrap();
    assert_eq!(pending.state, consumer::ConnectionState::PendingAuth);
    assert!(!pending.has_refresh);
    assert_eq!(pending.generation, 0);
    assert!(pending.granted_scopes.is_empty());

    let authorized = consumer::decode_connection(&fixture("ConnectionAuthorized")).unwrap();
    assert_eq!(authorized.state, consumer::ConnectionState::Authorized);
    assert!(authorized.has_refresh);
    assert_eq!(authorized.generation, 1);
    assert_eq!(authorized.granted_scopes, vec!["issues.read"]);
    assert_eq!(authorized.origin, "https://api.example.test");

    let disconnected = consumer::decode_connection(&fixture("ConnectionDisconnected")).unwrap();
    assert_eq!(disconnected.state, consumer::ConnectionState::Disconnected);
    assert!(!disconnected.has_refresh);
    assert_eq!(disconnected.revocation_generation, 1);
    assert!(disconnected.disconnected_at.is_some());

    let page = consumer::decode_connection_page(&fixture("ConnectionPageTypical")).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0], authorized);
    assert!(page.next_cursor.is_none());

    let share = consumer::decode_connection_share(&fixture("ConnectionShareUse")).unwrap();
    assert_eq!(share.access, "use");
    assert_eq!(share.grantee_kind, "user");
    assert!(share.grantee_id.is_some());
}
