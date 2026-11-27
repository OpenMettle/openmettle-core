//! Server-owned reviewed external MCP tool contracts and closed-object argument validation (ADR 0039).

use super::ToolFault;
use crate::{
    authz::{
        CapabilityGate,
        approvals::{self, Destination, EffectClass, EffectPolicy, EndpointKey, Proposal, Review},
        projects,
        store::StoreError,
    },
    provider_http::{
        inference::Tool,
        mcp::{MAX_CALL_TIMEOUT, RemoteToolDeclaration, is_allowed_idempotency_header_name},
    },
    provider_keys::documents::unique,
    runs,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

const MAX_SCHEMA_BYTES: usize = 65_536;
const MAX_ARG_BYTES: usize = 65_536;
const MAX_DEPTH: usize = 16;
const MAX_OBJECT_PROPERTIES: usize = 64;
const MAX_ARRAY_ITEMS: usize = 256;
const MAX_STRING_BYTES: usize = 16_384;

/// Recursively detect any MCP `2026-07-28` `x-mcp-header` annotation in a schema or value.
pub fn contains_x_mcp_header(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-mcp-header") || contains_x_mcp_header(v)),
        Value::Array(items) => items.iter().any(contains_x_mcp_header),
        _ => false,
    }
}

/// Canonical SHA-256 digest of a JSON schema object after key sorting.
pub fn canonical_schema_digest(schema: &Value) -> [u8; 32] {
    let mut sorted = schema.clone();
    sorted.sort_all_objects();
    Sha256::digest(sorted.to_string().as_bytes()).into()
}

/// Where a contract-pinned idempotency key travels on the MCP wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyCarrier {
    None,
    /// HTTP header name (e.g. `Idempotency-Key`); never `Mcp-Session-Id` or `Mcp-Param-*`.
    Header(String),
    /// `params._meta` key (never `io.modelcontextprotocol/*`).
    Meta(String),
}

/// Reviewed idempotency key window for `EndpointKey::Supported` contracts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyWindow {
    pub namespace: String,
    pub carrier: IdempotencyCarrier,
    pub valid_from_us: i64,
    pub expires_us: i64,
}

/// Contract-defined read-only status lookup used by `Executor::reconcile`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileSpec {
    /// Remote MCP tool name for the read-only lookup (on the same pinned transport).
    pub lookup_tool: String,
    /// Canonical lowercase ASCII scope token required for this read-only reconciliation lookup.
    pub lookup_scope: String,
    /// Argument name populated with `operations.downstream_handle` when present.
    pub handle_argument: Option<String>,
    /// Argument name populated with the deterministic key (`endpoint_key` or `logical_key`)
    /// when `downstream_handle` is absent (e.g. `idempotent` or deterministic `lookup`).
    pub deterministic_key_argument: Option<String>,
    /// JSON field name in `structuredContent` (or parsed JSON text) reporting `"succeeded"`,
    /// `"failed"` / `"not_found"`, or `"pending"`.
    pub status_field: String,
}

/// One server-reviewed external MCP tool contract. Upstream `tools/list` can only verify it.
#[derive(Clone)]
pub struct ExternalToolContract {
    pub tool_id: String,
    pub remote_name: String,
    pub version: String,
    pub description: String,
    pub input_schema: Value,
    pub schema_digest: [u8; 32],
    pub connection_id: String,
    pub account_id: String,
    pub action: String,
    /// Optional argument property name that selects `Destination.resource`; otherwise `fixed_resource`.
    pub resource_field: Option<String>,
    pub fixed_resource: String,
    pub class: EffectClass,
    pub capability: String,
    pub gate: CapabilityGate,
    pub tool_policy: String,
    pub destination_policy: String,
    pub endpoint_id: String,
    pub endpoint_version: String,
    pub idempotency: Option<IdempotencyWindow>,
    pub authoritative_lookup: bool,
    pub semantic_errors_are_side_effect_free: bool,
    /// Optional `structuredContent` string field captured as redacted `downstream_handle`.
    pub handle_field: Option<String>,
    pub reconcile: Option<ReconcileSpec>,
    pub call_timeout: Duration,
}

impl ExternalToolContract {
    /// Validate the contract schema at registration time, rejecting `x-mcp-header`, open objects,
    /// unsupported idempotency headers, or oversized schemas fail-closed.
    pub fn validate(&mut self) -> Result<(), ToolFault> {
        if self.tool_id.is_empty()
            || self.tool_id.len() > 128
            || self.remote_name.is_empty()
            || self.remote_name.len() > 256
            || self.version.is_empty()
            || self.version.len() > 128
            || self.connection_id.is_empty()
            || self.account_id.is_empty()
            || self.action.is_empty()
            || self.fixed_resource.is_empty()
            || self.call_timeout.is_zero()
            || self.call_timeout > MAX_CALL_TIMEOUT
        {
            return Err(ToolFault::TerminalRefusal);
        }
        if self.input_schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(ToolFault::TerminalRefusal);
        }
        validate_schema(&self.input_schema, 0)?;
        let mut sorted = self.input_schema.clone();
        sorted.sort_all_objects();
        if sorted.to_string().len() > MAX_SCHEMA_BYTES {
            return Err(ToolFault::TerminalRefusal);
        }
        if let Some(idem) = &self.idempotency {
            if idem.namespace.is_empty() || idem.expires_us <= idem.valid_from_us {
                return Err(ToolFault::TerminalRefusal);
            }
            match &idem.carrier {
                IdempotencyCarrier::None => return Err(ToolFault::TerminalRefusal),
                IdempotencyCarrier::Header(name) if !is_allowed_idempotency_header_name(name) => {
                    return Err(ToolFault::TerminalRefusal);
                }
                IdempotencyCarrier::Meta(field)
                    if field.is_empty() || field.starts_with("io.modelcontextprotocol/") =>
                {
                    return Err(ToolFault::TerminalRefusal);
                }
                _ => {}
            }
        }
        if let Some(reconcile) = &self.reconcile
            && (reconcile.lookup_tool.is_empty()
                || reconcile.lookup_tool.len() > 256
                || reconcile.status_field.is_empty()
                || reconcile.status_field.len() > 128
                || !crate::vault::is_valid_scope_token(&reconcile.lookup_scope))
        {
            return Err(ToolFault::TerminalRefusal);
        }
        self.input_schema = sorted;
        self.schema_digest = canonical_schema_digest(&self.input_schema);
        Ok(())
    }

    /// Build the model-facing `Tool` declaration projected to the `provider_http::inference`
    /// function-schema subset while retaining full contract constraint enforcement in `proposal`.
    pub fn declaration(&self) -> Tool {
        Tool {
            name: self.tool_id.clone(),
            description: self.description.clone(),
            parameters: project_model_schema(&self.input_schema),
        }
    }

    /// Build a [`crate::worker::DeclaredTool`] carrying this contract's pinned version for
    /// [`crate::worker::ApprovedAdapter::filter_turn_tools`].
    pub fn declared_tool(&self) -> crate::worker::DeclaredTool {
        crate::worker::DeclaredTool::external(self.declaration(), self.version.clone())
    }

    /// Validate raw JSON arguments against this closed-object contract and expand defaults.
    pub fn validate_arguments(&self, raw: &[u8]) -> Result<Value, ToolFault> {
        if raw.len() > MAX_ARG_BYTES {
            return Err(ToolFault::TerminalRefusal);
        }
        let parsed = approvals::canonical_arguments(raw).map_err(|_| ToolFault::TerminalRefusal)?;
        if contains_x_mcp_header(&parsed) {
            return Err(ToolFault::TerminalRefusal);
        }
        let mut normalized = validate_value_against_schema(&parsed, &self.input_schema, 0)?;
        normalized.sort_all_objects();
        if normalized.to_string().len() > MAX_ARG_BYTES {
            return Err(ToolFault::TerminalRefusal);
        }
        Ok(normalized)
    }

    /// Build a server-bound `Proposal` from validated arguments and pinned destination fields.
    pub fn proposal(&self, key: &str, raw_args: &[u8]) -> Result<Proposal, ToolFault> {
        if key.is_empty()
            || key.len() > 128
            || key.contains('*')
            || key.chars().any(char::is_control)
        {
            return Err(ToolFault::TerminalRefusal);
        }
        let normalized = self.validate_arguments(raw_args)?;
        let resource = match &self.resource_field {
            Some(field) => normalized
                .as_object()
                .and_then(|m| m.get(field))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && !s.contains('*') && !s.chars().any(char::is_control))
                .ok_or(ToolFault::TerminalRefusal)?,
            None => self.fixed_resource.as_str(),
        };
        Proposal::new(
            key,
            &self.tool_id,
            &self.version,
            normalized.to_string().as_bytes(),
            Destination {
                connection: &self.connection_id,
                account: &self.account_id,
                action: &self.action,
                resource,
            },
        )
        .map_err(|_| ToolFault::TerminalRefusal)
    }

    /// Derive the deterministic endpoint idempotency key for `(scope, run, proposal)`.
    pub fn endpoint_key(&self, scope: &str, run: &str, proposal: &Proposal) -> EndpointKey {
        let Some(idem) = &self.idempotency else {
            return EndpointKey::Unsupported;
        };
        let field = match &idem.carrier {
            IdempotencyCarrier::Header(_) => "Idempotency-Key".to_owned(),
            IdempotencyCarrier::Meta(field) => field.clone(),
            IdempotencyCarrier::None => return EndpointKey::Unsupported,
        };
        let mut hasher = Sha256::new();
        hasher.update(b"openmettle/mcp-idempotency/1\0");
        for part in [
            scope.as_bytes(),
            run.as_bytes(),
            proposal.logical_key.as_bytes(),
            proposal.tool.as_bytes(),
            proposal.version.as_bytes(),
            proposal.destination().as_bytes(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        let key = projects::hex(&hasher.finalize());
        EndpointKey::Supported {
            namespace: idem.namespace.clone(),
            field,
            valid_from_us: idem.valid_from_us,
            key,
            expires_us: idem.expires_us,
        }
    }
}

/// Registry of reviewed external MCP tool contracts implementing `approvals::EffectPolicy`.
#[derive(Clone, Default)]
pub struct ExternalRegistry {
    contracts: BTreeMap<(String, String), ExternalToolContract>,
}

impl ExternalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one reviewed contract after strict schema validation.
    pub fn register(&mut self, mut contract: ExternalToolContract) -> Result<(), ToolFault> {
        contract.validate()?;
        let key = (contract.tool_id.clone(), contract.version.clone());
        if self.contracts.contains_key(&key) {
            return Err(ToolFault::TerminalRefusal);
        }
        self.contracts.insert(key, contract);
        Ok(())
    }

    pub fn get(&self, tool_id: &str, version: &str) -> Option<&ExternalToolContract> {
        self.contracts
            .get(&(tool_id.to_owned(), version.to_owned()))
    }

    pub fn find_by_tool_id(&self, tool_id: &str) -> Vec<&ExternalToolContract> {
        self.contracts
            .values()
            .filter(|c| c.tool_id == tool_id)
            .collect()
    }

    pub fn contracts(&self) -> impl Iterator<Item = &ExternalToolContract> {
        self.contracts.values()
    }

    pub fn proposal(
        &self,
        key: &str,
        tool_id: &str,
        version: &str,
        raw_args: &[u8],
    ) -> Result<Proposal, ToolFault> {
        self.get(tool_id, version)
            .ok_or(ToolFault::TerminalRefusal)?
            .proposal(key, raw_args)
    }

    /// Deterministic SHA-256 fingerprint of every contract pinned to `connection_id`.
    /// Returns `None` when no contracts are registered for `connection_id`.
    pub fn connection_fingerprint(&self, connection_id: &str) -> Option<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(b"openmettle/mcp-connection-catalog/1\0");
        let mut matched_any = false;
        for contract in self.contracts.values() {
            if contract.connection_id != connection_id {
                continue;
            }
            matched_any = true;
            for part in [
                contract.tool_id.as_bytes(),
                contract.version.as_bytes(),
                contract.remote_name.as_bytes(),
                &contract.schema_digest,
            ] {
                hasher.update((part.len() as u64).to_be_bytes());
                hasher.update(part);
            }
        }
        matched_any.then(|| hasher.finalize().into())
    }

    /// Verify upstream `tools/list` declarations for `connection_id`.
    ///
    /// Ignores undeclared remote tools, rejects duplicate remote tool names, rejects any
    /// `x-mcp-header` annotation, and requires every contract pinned to `connection_id` to
    /// exist remotely with an exact canonical schema digest match.
    pub fn verify_tools_list(
        &self,
        connection_id: &str,
        remote: &[RemoteToolDeclaration],
    ) -> Result<(), ToolFault> {
        let mut by_name: BTreeMap<&str, &Value> = BTreeMap::new();
        for tool in remote {
            if by_name
                .insert(tool.name.as_str(), &tool.input_schema)
                .is_some()
            {
                return Err(ToolFault::TerminalRefusal);
            }
        }
        let mut matched_any = false;
        for contract in self.contracts.values() {
            if contract.connection_id != connection_id {
                continue;
            }
            matched_any = true;
            let Some(remote_schema) = by_name.get(contract.remote_name.as_str()) else {
                return Err(ToolFault::TerminalRefusal);
            };
            if contains_x_mcp_header(remote_schema) {
                return Err(ToolFault::TerminalRefusal);
            }
            // Reject duplicate keys in remote schema serialization as well as schema drift.
            let raw = remote_schema.to_string();
            if raw.len() > MAX_SCHEMA_BYTES || unique(raw.as_bytes()).is_err() {
                return Err(ToolFault::TerminalRefusal);
            }
            if canonical_schema_digest(remote_schema) != contract.schema_digest {
                return Err(ToolFault::TerminalRefusal);
            }
        }
        if !matched_any {
            return Err(ToolFault::TerminalRefusal);
        }
        Ok(())
    }
}

impl EffectPolicy for ExternalRegistry {
    fn review(&self, scope: &str, run: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        let Some(contract) = self.get(&p.tool, &p.version) else {
            return Ok(None);
        };
        let Ok(expected) = contract.proposal(&p.logical_key, p.arguments().to_string().as_bytes())
        else {
            return Ok(None);
        };
        if expected.arguments() != p.arguments() || expected.destination() != p.destination() {
            return Ok(None);
        }
        Ok(Some(Review {
            class: contract.class,
            capability: contract.capability.clone(),
            gate: contract.gate,
            tool_policy: contract.tool_policy.clone(),
            destination_policy: contract.destination_policy.clone(),
            endpoint_id: contract.endpoint_id.clone(),
            endpoint_version: contract.endpoint_version.clone(),
            endpoint_key: contract.endpoint_key(scope, run, p),
            authoritative_lookup: contract.authoritative_lookup,
            artifact: None,
            reservation: None,
        }))
    }

    fn requires_two_phase_writes(&self) -> bool {
        true
    }
}

fn project_model_schema(schema: &Value) -> Value {
    let Some(obj) = schema.as_object() else {
        return schema.clone();
    };
    let mut out = Map::new();
    for (k, v) in obj {
        match k.as_str() {
            "type" | "description" | "required" | "additionalProperties" => {
                out.insert(k.clone(), v.clone());
            }
            "properties" => {
                if let Some(props) = v.as_object() {
                    let projected: Map<String, Value> = props
                        .iter()
                        .map(|(pk, pv)| (pk.clone(), project_model_schema(pv)))
                        .collect();
                    out.insert(k.clone(), Value::Object(projected));
                }
            }
            "items" => {
                out.insert(k.clone(), project_model_schema(v));
            }
            _ => {}
        }
    }
    Value::Object(out)
}

fn validate_schema_metadata(obj: &Map<String, Value>) -> Result<(), ToolFault> {
    for key in ["description", "title"] {
        if let Some(val) = obj.get(key)
            && !val.is_string()
        {
            return Err(ToolFault::TerminalRefusal);
        }
    }
    Ok(())
}

fn check_allowed_schema_keys(obj: &Map<String, Value>, allowed: &[&str]) -> Result<(), ToolFault> {
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(ToolFault::TerminalRefusal);
    }
    validate_schema_metadata(obj)
}

fn validate_schema(schema: &Value, depth: usize) -> Result<(), ToolFault> {
    if depth > MAX_DEPTH || contains_x_mcp_header(schema) {
        return Err(ToolFault::TerminalRefusal);
    }
    let obj = schema.as_object().ok_or(ToolFault::TerminalRefusal)?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ToolFault::TerminalRefusal)?;
    match kind {
        "object" => {
            check_allowed_schema_keys(
                obj,
                &[
                    "type",
                    "properties",
                    "required",
                    "additionalProperties",
                    "description",
                    "title",
                ],
            )?;
            if obj.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Err(ToolFault::TerminalRefusal);
            }
            let props = obj
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(ToolFault::TerminalRefusal)?;
            if props.len() > MAX_OBJECT_PROPERTIES {
                return Err(ToolFault::TerminalRefusal);
            }
            for (name, prop) in props {
                if name.is_empty() {
                    return Err(ToolFault::TerminalRefusal);
                }
                validate_schema(prop, depth + 1)?;
            }
            if let Some(required) = obj.get("required") {
                let reqs = required.as_array().ok_or(ToolFault::TerminalRefusal)?;
                let mut seen = BTreeSet::new();
                for req in reqs {
                    let name = req.as_str().ok_or(ToolFault::TerminalRefusal)?;
                    if !props.contains_key(name) || !seen.insert(name) {
                        return Err(ToolFault::TerminalRefusal);
                    }
                }
            }
            Ok(())
        }
        "string" => {
            check_allowed_schema_keys(
                obj,
                &[
                    "type",
                    "description",
                    "title",
                    "default",
                    "minLength",
                    "maxLength",
                    "enum",
                    "format",
                ],
            )?;
            let min = match obj.get("minLength") {
                Some(v) => {
                    let n = v.as_u64().ok_or(ToolFault::TerminalRefusal)?;
                    if n > MAX_STRING_BYTES as u64 {
                        return Err(ToolFault::TerminalRefusal);
                    }
                    Some(n)
                }
                None => None,
            };
            let max = match obj.get("maxLength") {
                Some(v) => {
                    let n = v.as_u64().ok_or(ToolFault::TerminalRefusal)?;
                    if n > MAX_STRING_BYTES as u64 {
                        return Err(ToolFault::TerminalRefusal);
                    }
                    Some(n)
                }
                None => None,
            };
            if let (Some(lo), Some(hi)) = (min, max)
                && lo > hi
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(fmt) = obj.get("format")
                && fmt.as_str() != Some("uuid")
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(allowed) = obj.get("enum") {
                let items = allowed.as_array().ok_or(ToolFault::TerminalRefusal)?;
                if items.is_empty() {
                    return Err(ToolFault::TerminalRefusal);
                }
                for item in items {
                    if !item.is_string() {
                        return Err(ToolFault::TerminalRefusal);
                    }
                    validate_value_against_schema(item, schema, depth)?;
                }
            }
            if let Some(default) = obj.get("default") {
                validate_value_against_schema(default, schema, depth)?;
            }
            Ok(())
        }
        "integer" => {
            check_allowed_schema_keys(
                obj,
                &[
                    "type",
                    "description",
                    "title",
                    "default",
                    "minimum",
                    "maximum",
                    "enum",
                ],
            )?;
            let min = match obj.get("minimum") {
                Some(v) => Some(v.as_i64().ok_or(ToolFault::TerminalRefusal)?),
                None => None,
            };
            let max = match obj.get("maximum") {
                Some(v) => Some(v.as_i64().ok_or(ToolFault::TerminalRefusal)?),
                None => None,
            };
            if let (Some(lo), Some(hi)) = (min, max)
                && lo > hi
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(allowed) = obj.get("enum") {
                let items = allowed.as_array().ok_or(ToolFault::TerminalRefusal)?;
                if items.is_empty() {
                    return Err(ToolFault::TerminalRefusal);
                }
                for item in items {
                    if item.as_i64().is_none() {
                        return Err(ToolFault::TerminalRefusal);
                    }
                    validate_value_against_schema(item, schema, depth)?;
                }
            }
            if let Some(default) = obj.get("default") {
                validate_value_against_schema(default, schema, depth)?;
            }
            Ok(())
        }
        "boolean" => {
            check_allowed_schema_keys(obj, &["type", "description", "title", "default", "enum"])?;
            if let Some(allowed) = obj.get("enum") {
                let items = allowed.as_array().ok_or(ToolFault::TerminalRefusal)?;
                if items.is_empty() {
                    return Err(ToolFault::TerminalRefusal);
                }
                for item in items {
                    if item.as_bool().is_none() {
                        return Err(ToolFault::TerminalRefusal);
                    }
                }
            }
            if let Some(default) = obj.get("default") {
                validate_value_against_schema(default, schema, depth)?;
            }
            Ok(())
        }
        "array" => {
            check_allowed_schema_keys(
                obj,
                &[
                    "type",
                    "description",
                    "title",
                    "default",
                    "items",
                    "minItems",
                    "maxItems",
                ],
            )?;
            let min = match obj.get("minItems") {
                Some(v) => {
                    let n = v.as_u64().ok_or(ToolFault::TerminalRefusal)?;
                    if n > MAX_ARRAY_ITEMS as u64 {
                        return Err(ToolFault::TerminalRefusal);
                    }
                    Some(n)
                }
                None => None,
            };
            let max = match obj.get("maxItems") {
                Some(v) => {
                    let n = v.as_u64().ok_or(ToolFault::TerminalRefusal)?;
                    if n > MAX_ARRAY_ITEMS as u64 {
                        return Err(ToolFault::TerminalRefusal);
                    }
                    Some(n)
                }
                None => None,
            };
            if let (Some(lo), Some(hi)) = (min, max)
                && lo > hi
            {
                return Err(ToolFault::TerminalRefusal);
            }
            let items = obj.get("items").ok_or(ToolFault::TerminalRefusal)?;
            validate_schema(items, depth + 1)?;
            if let Some(default) = obj.get("default") {
                validate_value_against_schema(default, schema, depth)?;
            }
            Ok(())
        }
        _ => Err(ToolFault::TerminalRefusal),
    }
}

fn validate_value_against_schema(
    value: &Value,
    schema: &Value,
    depth: usize,
) -> Result<Value, ToolFault> {
    if depth > MAX_DEPTH {
        return Err(ToolFault::TerminalRefusal);
    }
    let obj = schema.as_object().ok_or(ToolFault::TerminalRefusal)?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ToolFault::TerminalRefusal)?;
    match kind {
        "object" => {
            let input = value.as_object().ok_or(ToolFault::TerminalRefusal)?;
            if input.len() > MAX_OBJECT_PROPERTIES {
                return Err(ToolFault::TerminalRefusal);
            }
            let props = obj
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(ToolFault::TerminalRefusal)?;
            for k in input.keys() {
                if !props.contains_key(k) {
                    return Err(ToolFault::TerminalRefusal);
                }
            }
            let mut out = Map::new();
            for (k, prop_schema) in props {
                if let Some(v) = input.get(k) {
                    out.insert(
                        k.clone(),
                        validate_value_against_schema(v, prop_schema, depth + 1)?,
                    );
                } else if let Some(default) = prop_schema.get("default") {
                    out.insert(
                        k.clone(),
                        validate_value_against_schema(default, prop_schema, depth + 1)?,
                    );
                }
            }
            if let Some(required) = obj.get("required").and_then(Value::as_array) {
                for req in required {
                    let name = req.as_str().ok_or(ToolFault::TerminalRefusal)?;
                    if !out.contains_key(name) {
                        return Err(ToolFault::TerminalRefusal);
                    }
                }
            }
            Ok(Value::Object(out))
        }
        "string" => {
            let s = value.as_str().ok_or(ToolFault::TerminalRefusal)?;
            if s.len() > MAX_STRING_BYTES {
                return Err(ToolFault::TerminalRefusal);
            }
            let char_len = s.chars().count() as u64;
            if let Some(min) = obj.get("minLength").and_then(Value::as_u64)
                && char_len < min
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(max) = obj.get("maxLength").and_then(Value::as_u64)
                && char_len > max
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if obj.get("format").and_then(Value::as_str) == Some("uuid")
                && !runs::is_canonical_uuid(s)
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(allowed) = obj.get("enum").and_then(Value::as_array)
                && !allowed.iter().any(|v| v == value)
            {
                return Err(ToolFault::TerminalRefusal);
            }
            Ok(Value::String(s.to_owned()))
        }
        "integer" => {
            let n = value.as_i64().ok_or(ToolFault::TerminalRefusal)?;
            if let Some(min) = obj.get("minimum").and_then(Value::as_i64)
                && n < min
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(max) = obj.get("maximum").and_then(Value::as_i64)
                && n > max
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(allowed) = obj.get("enum").and_then(Value::as_array)
                && !allowed.iter().any(|v| v.as_i64() == Some(n))
            {
                return Err(ToolFault::TerminalRefusal);
            }
            Ok(Value::Number(n.into()))
        }
        "boolean" => {
            let b = value.as_bool().ok_or(ToolFault::TerminalRefusal)?;
            if let Some(allowed) = obj.get("enum").and_then(Value::as_array)
                && !allowed.iter().any(|v| v.as_bool() == Some(b))
            {
                return Err(ToolFault::TerminalRefusal);
            }
            Ok(Value::Bool(b))
        }
        "array" => {
            let items = value.as_array().ok_or(ToolFault::TerminalRefusal)?;
            if items.len() > MAX_ARRAY_ITEMS {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(min) = obj.get("minItems").and_then(Value::as_u64)
                && (items.len() as u64) < min
            {
                return Err(ToolFault::TerminalRefusal);
            }
            if let Some(max) = obj.get("maxItems").and_then(Value::as_u64)
                && (items.len() as u64) > max
            {
                return Err(ToolFault::TerminalRefusal);
            }
            let item_schema = obj.get("items").ok_or(ToolFault::TerminalRefusal)?;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(validate_value_against_schema(item, item_schema, depth + 1)?);
            }
            Ok(Value::Array(out))
        }
        _ => Err(ToolFault::TerminalRefusal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_contract() -> ExternalToolContract {
        ExternalToolContract {
            tool_id: "docs.append".into(),
            remote_name: "docs.append".into(),
            version: "1".into(),
            description: "Append one bounded note".into(),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["doc_id", "body"],
                "properties": {
                    "doc_id": {"type": "string", "minLength": 1, "maxLength": 64},
                    "body": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "retries": {"type": "integer", "minimum": 0, "maximum": 3, "default": 1}
                }
            }),
            schema_digest: [0; 32],
            connection_id: "docs-mcp".into(),
            account_id: "acct-1".into(),
            action: "append".into(),
            resource_field: Some("doc_id".into()),
            fixed_resource: "default".into(),
            class: EffectClass::EligibleWrite,
            capability: "tools.docs.write".into(),
            gate: CapabilityGate::OptIn,
            tool_policy: "docs.append.v1".into(),
            destination_policy: "docs.v1".into(),
            endpoint_id: "docs-mcp".into(),
            endpoint_version: "1".into(),
            idempotency: Some(IdempotencyWindow {
                namespace: "docs".into(),
                carrier: IdempotencyCarrier::Header("Idempotency-Key".into()),
                valid_from_us: 1_000,
                expires_us: 9_000_000_000_000_000,
            }),
            authoritative_lookup: false,
            semantic_errors_are_side_effect_free: true,
            handle_field: Some("handle".into()),
            reconcile: None,
            call_timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn x_mcp_header_and_open_objects_and_tools_list_drift_fail_closed() {
        let mut with_header = sample_contract();
        with_header.input_schema["properties"]["doc_id"]["x-mcp-header"] = json!("X-Doc");
        assert_eq!(with_header.validate(), Err(ToolFault::TerminalRefusal));

        let mut open = sample_contract();
        open.input_schema["additionalProperties"] = json!(true);
        assert_eq!(open.validate(), Err(ToolFault::TerminalRefusal));

        let mut bad_idem = sample_contract();
        bad_idem.idempotency.as_mut().unwrap().carrier =
            IdempotencyCarrier::Header("Mcp-Param-Id".into());
        assert_eq!(bad_idem.validate(), Err(ToolFault::TerminalRefusal));

        let mut registry = ExternalRegistry::new();
        registry.register(sample_contract()).unwrap();

        // Undeclared remote tools are ignored while pinned tool must match exactly.
        let matching_schema = registry
            .get("docs.append", "1")
            .unwrap()
            .input_schema
            .clone();
        assert!(
            registry
                .verify_tools_list(
                    "docs-mcp",
                    &[
                        RemoteToolDeclaration {
                            name: "undeclared.tool".into(),
                            input_schema: json!({"type": "object"}),
                        },
                        RemoteToolDeclaration {
                            name: "docs.append".into(),
                            input_schema: matching_schema.clone(),
                        },
                    ],
                )
                .is_ok()
        );

        // Missing pinned tool -> refused.
        assert_eq!(
            registry.verify_tools_list("docs-mcp", &[]),
            Err(ToolFault::TerminalRefusal)
        );

        // Schema drift or remote `x-mcp-header` -> refused.
        let mut drifted = matching_schema.clone();
        drifted["properties"]["body"]["maxLength"] = json!(8192);
        assert_eq!(
            registry.verify_tools_list(
                "docs-mcp",
                &[RemoteToolDeclaration {
                    name: "docs.append".into(),
                    input_schema: drifted,
                }],
            ),
            Err(ToolFault::TerminalRefusal)
        );

        let mut remote_header = matching_schema;
        remote_header["properties"]["doc_id"]["x-mcp-header"] = json!("X-Custom");
        assert_eq!(
            registry.verify_tools_list(
                "docs-mcp",
                &[RemoteToolDeclaration {
                    name: "docs.append".into(),
                    input_schema: remote_header,
                }],
            ),
            Err(ToolFault::TerminalRefusal)
        );
    }

    #[test]
    fn argument_validation_expands_defaults_and_rejects_extra_or_out_of_bounds_values() {
        let mut registry = ExternalRegistry::new();
        registry.register(sample_contract()).unwrap();
        let proposal = registry
            .proposal("k1", "docs.append", "1", br#"{"doc_id":"d1","body":"hi"}"#)
            .unwrap();
        assert_eq!(proposal.arguments()["retries"], 1);
        assert_eq!(
            proposal.destination(),
            r#"["v1","docs-mcp","acct-1","append","d1"]"#
        );
        for bad in [
            br#"{"doc_id":"d1","body":"hi","extra":1}"#.as_slice(),
            br#"{"doc_id":"d1","body":"hi","retries":4}"#,
            br#"{"doc_id":"d1","body":"hi","retries":1.0}"#,
            br#"{"doc_id":"*","body":"hi"}"#,
            br#"{"doc_id":"d1","body":"hi","body":"dup"}"#,
        ] {
            assert_eq!(
                registry.proposal("k1", "docs.append", "1", bad).err(),
                Some(ToolFault::TerminalRefusal)
            );
        }
    }

    #[test]
    fn closed_schema_subset_enforces_enum_min_items_timeout_and_idempotency_header_allowlist() {
        // Supported integer/boolean enums and array minItems are enforced at runtime.
        let mut strict = sample_contract();
        strict.input_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["doc_id", "mode", "tags"],
            "properties": {
                "doc_id": {"type": "string", "minLength": 1, "maxLength": 32},
                "mode": {"type": "integer", "enum": [1, 3]},
                "confirm": {"type": "boolean", "enum": [true], "default": true},
                "tags": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 0},
                    "minItems": 2,
                    "maxItems": 4
                }
            }
        });
        let mut registry = ExternalRegistry::new();
        registry.register(strict).unwrap();
        assert!(
            registry
                .proposal(
                    "ok-1",
                    "docs.append",
                    "1",
                    br#"{"doc_id":"d1","mode":3,"tags":[0,1]}"#
                )
                .is_ok()
        );
        for bad in [
            br#"{"doc_id":"d1","mode":2,"tags":[0,1]}"#.as_slice(),
            br#"{"doc_id":"d1","mode":1,"confirm":false,"tags":[0,1]}"#,
            br#"{"doc_id":"d1","mode":1,"tags":[0]}"#,
            br#"{"doc_id":"d1","mode":1,"tags":[0,1,2,3,4]}"#,
        ] {
            assert_eq!(
                registry.proposal("bad", "docs.append", "1", bad).err(),
                Some(ToolFault::TerminalRefusal)
            );
        }

        // Unsupported JSON Schema keywords or malformed bounds fail closed at registration.
        for bad_schema in [
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"doc_id": {"type": "string", "pattern": "^[a-z]+$"}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "oneOf": [{"required": ["doc_id"]}],
                "properties": {"doc_id": {"type": "string"}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"n": {"type": "integer", "multipleOf": 2}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"a": {"type": "array", "items": {"type": "string"}, "additionalItems": false}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"doc_id": {"$ref": "#/$defs/id"}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"doc_id": {"type": "string", "const": "fixed"}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"n": {"type": "integer", "minimum": 1.5}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"n": {"type": "integer", "enum": [1, 3], "default": 2}}
            }),
            json!({
                "type": "object", "additionalProperties": false,
                "properties": {"a": {"type": "array", "items": {"type": "integer"}, "minItems": 3, "maxItems": 2}}
            }),
        ] {
            let mut c = sample_contract();
            c.input_schema = bad_schema;
            assert_eq!(c.validate(), Err(ToolFault::TerminalRefusal));
        }

        // `call_timeout` above 300s is rejected at registration.
        let mut slow = sample_contract();
        slow.call_timeout = Duration::from_secs(301);
        assert_eq!(slow.validate(), Err(ToolFault::TerminalRefusal));

        // Only `Idempotency-Key` (case-insensitive) is accepted as an idempotency HTTP header.
        let mut lower_idem = sample_contract();
        lower_idem.idempotency.as_mut().unwrap().carrier =
            IdempotencyCarrier::Header("idempotency-key".into());
        assert!(lower_idem.validate().is_ok());
        for forbidden in [
            "Expect",
            "Content-Encoding",
            "X-Custom-Key",
            "Mcp-Session-Id",
        ] {
            let mut c = sample_contract();
            c.idempotency.as_mut().unwrap().carrier = IdempotencyCarrier::Header(forbidden.into());
            assert_eq!(
                c.validate(),
                Err(ToolFault::TerminalRefusal),
                "header {forbidden} must fail closed"
            );
        }
    }

    #[test]
    fn declaration_projects_to_inference_schema_subset_while_proposal_enforces_full_constraints() {
        let mut rich = sample_contract();
        rich.tool_id = "docs_append".into();
        rich.input_schema = json!({
            "type": "object",
            "title": "AppendInput",
            "description": "Append arguments",
            "additionalProperties": false,
            "required": ["doc_id", "mode"],
            "properties": {
                "doc_id": {
                    "type": "string",
                    "title": "Document ID",
                    "description": "Canonical document UUID",
                    "format": "uuid",
                    "minLength": 36,
                    "maxLength": 36
                },
                "mode": {
                    "type": "string",
                    "enum": ["append", "replace"],
                    "minLength": 1,
                    "maxLength": 16
                },
                "retries": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 3,
                    "default": 2
                },
                "tags": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "default": ["v1"],
                    "items": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 8,
                        "enum": ["v1", "v2"]
                    }
                }
            }
        });
        let mut registry = ExternalRegistry::new();
        registry.register(rich).unwrap();
        let contract = registry.get("docs_append", "1").unwrap();
        let decl = contract.declaration();

        // Every schema node in `declaration().parameters` must only contain inference-allowed keys.
        fn assert_projected_only(node: &Value) {
            let obj = node.as_object().expect("schema node must be object");
            for (k, v) in obj {
                assert!(
                    matches!(
                        k.as_str(),
                        "type"
                            | "description"
                            | "properties"
                            | "required"
                            | "additionalProperties"
                            | "items"
                    ),
                    "unexpected non-projected schema key {k} in declaration"
                );
                if k == "properties" {
                    for prop in v.as_object().unwrap().values() {
                        assert_projected_only(prop);
                    }
                } else if k == "items" {
                    assert_projected_only(v);
                }
            }
        }
        assert_projected_only(&decl.parameters);
        assert_eq!(decl.parameters["description"], "Append arguments");
        assert_eq!(
            decl.parameters["properties"]["doc_id"]["description"],
            "Canonical document UUID"
        );
        assert!(decl.parameters.get("title").is_none());
        assert!(
            decl.parameters["properties"]["doc_id"]
                .get("format")
                .is_none()
        );
        assert!(decl.parameters["properties"]["mode"].get("enum").is_none());
        assert!(
            decl.parameters["properties"]["retries"]
                .get("default")
                .is_none()
        );
        assert!(
            decl.parameters["properties"]["tags"]
                .get("minItems")
                .is_none()
        );

        // Full validation and default expansion still run in `proposal()`.
        let ok = contract
            .proposal(
                "k-rich-1",
                br#"{"doc_id":"00000000-0000-4000-8000-000000000001","mode":"append"}"#,
            )
            .unwrap();
        assert_eq!(ok.arguments()["retries"], 2);
        assert_eq!(ok.arguments()["tags"], json!(["v1"]));

        for bad in [
            br#"{"doc_id":"not-a-uuid","mode":"append"}"#.as_slice(),
            br#"{"doc_id":"00000000-0000-4000-8000-000000000001","mode":"delete"}"#,
            br#"{"doc_id":"00000000-0000-4000-8000-000000000001","mode":"append","retries":9}"#,
            br#"{"doc_id":"00000000-0000-4000-8000-000000000001","mode":"append","tags":[]}"#,
        ] {
            assert_eq!(
                contract.proposal("k-rich-bad", bad).err(),
                Some(ToolFault::TerminalRefusal)
            );
        }
    }

    #[test]
    fn string_length_constraints_count_unicode_scalars_while_preserving_byte_cap() {
        let mut unicode = sample_contract();
        unicode.input_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["doc_id", "body"],
            "properties": {
                "doc_id": {"type": "string", "minLength": 1, "maxLength": 16},
                "body": {"type": "string", "minLength": 2, "maxLength": 2}
            }
        });
        let mut registry = ExternalRegistry::new();
        registry.register(unicode).unwrap();

        // 2 Unicode scalars ("é" = 2 bytes, "🦀" = 4 bytes -> 6 UTF-8 bytes) satisfy [2, 2].
        let ok_body = json!({"doc_id": "d1", "body": "é🦀"}).to_string();
        assert!(
            registry
                .proposal("u-ok", "docs.append", "1", ok_body.as_bytes())
                .is_ok()
        );

        // 1 Unicode scalar ("é" = 2 UTF-8 bytes) must FAIL minLength: 2!
        let short_body = json!({"doc_id": "d1", "body": "é"}).to_string();
        assert_eq!(
            registry
                .proposal("u-short", "docs.append", "1", short_body.as_bytes())
                .err(),
            Some(ToolFault::TerminalRefusal)
        );

        // 3 Unicode scalars ("é🦀a") must FAIL maxLength: 2!
        let long_body = json!({"doc_id": "d1", "body": "é🦀a"}).to_string();
        assert_eq!(
            registry
                .proposal("u-long", "docs.append", "1", long_body.as_bytes())
                .err(),
            Some(ToolFault::TerminalRefusal)
        );

        // Byte cap (MAX_STRING_BYTES) still rejects strings whose scalar count fits maxLength
        // but whose UTF-8 byte length exceeds MAX_STRING_BYTES.
        let mut wide = sample_contract();
        wide.input_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["doc_id", "body"],
            "properties": {
                "doc_id": {"type": "string", "minLength": 1, "maxLength": 16},
                "body": {"type": "string", "maxLength": MAX_STRING_BYTES}
            }
        });
        let mut wide_reg = ExternalRegistry::new();
        wide_reg.register(wide).unwrap();
        let over_bytes = json!({
            "doc_id": "d1",
            "body": "🦀".repeat(MAX_STRING_BYTES / 4 + 1)
        })
        .to_string();
        assert_eq!(
            wide_reg
                .proposal("u-bytes", "docs.append", "1", over_bytes.as_bytes())
                .err(),
            Some(ToolFault::TerminalRefusal)
        );
    }
}
