//! Application API contract checks (ADR 0007). Offline: every reference resolves from
//! vendored files and network or file retrieval is refused. These tests validate the
//! canonical contract and its generated fixtures; no /v1 route is implemented.
#[path = "contract/consumer.rs"]
mod consumer;
#[path = "support/env.rs"]
mod env_support;

use env_support::scrub_env;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
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
        let actual: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
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
    for (name, scheme) in &schemes {
        if scheme.get("x-openmettle-provisional") != Some(&json!(true)) {
            problems.push(format!("security scheme {name} is not marked provisional"));
        }
    }
    for (path, item) in document["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let at = format!("{method} {path}");
            if operation.get("x-openmettle-implementation") != Some(&json!("not-implemented")) {
                problems.push(format!(
                    "{at}: implementation status must be not-implemented"
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
fn operations_are_authenticated_unimplemented_and_use_problem_details() {
    let problems = operation_problems(contract());
    assert!(problems.is_empty(), "{problems:#?}");
    // The lint detects an anonymous operation and a non-problem error response.
    let mut weakened = contract().clone();
    let operation = &mut weakened["paths"]["/v1/capabilities"]["get"];
    operation["security"] = json!([{}]);
    operation["responses"]["418"] = json!({
        "description": "x",
        "headers": {"OpenMettle-API-Version": {"$ref": "#/components/headers/ApiVersion"}},
        "content": {"text/plain": {"schema": {"type": "string", "maxLength": 1}}}
    });
    let found = operation_problems(&weakened);
    assert!(
        found.iter().any(|p| p.contains("authentication")),
        "{found:?}"
    );
    assert!(found.iter().any(|p| p.contains("418")), "{found:?}");
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
    problems
}

#[test]
fn schemas_are_bounded_private_and_requests_strict() {
    let problems = schema_problems(contract());
    assert!(problems.is_empty(), "{problems:#?}");
    // Mutations prove each rule fires. No operation has a request body yet, so strictness
    // is only exercised through this injected body.
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
}

#[test]
fn consumer_rejects_invalid_structure_it_depends_on() {
    // Missing required members and wrong JSON types must not decode into defaults.
    type Decode = fn(&Value) -> Result<(), String>;
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
    for (schema, decode) in decoders {
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
    assert_eq!(event.unrecognized_type, "example.note");
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

#[test]
fn api_does_not_serve_contract_routes() {
    // The contract is unimplemented: the running API must return 404 for every path.
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
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
    let mut child = command
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
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let get = |path: &str| -> Option<String> {
        let mut stream =
            TcpStream::connect_timeout(&bind.parse().unwrap(), Duration::from_millis(300)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .ok()?;
        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;
        Some(response)
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    while get("/healthz").is_none_or(|r| !r.starts_with("HTTP/1.1 200")) {
        assert!(child.try_wait().unwrap().is_none(), "API exited");
        assert!(Instant::now() < deadline, "API did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let paths: Vec<String> = contract()["paths"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    for path in &paths {
        let response = get(path).unwrap();
        assert!(response.starts_with("HTTP/1.1 404"), "{path}: {response}");
    }
    let _ = child.kill();
    let _ = child.wait();
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
