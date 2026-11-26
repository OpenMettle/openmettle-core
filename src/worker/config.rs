//! The packaged worker's inference configuration (ADR 0043).
//!
//! `OPENMETTLE_WORKER_INFERENCE_CONFIG` names one strict JSON document. The document and the
//! files it names are read once at startup, before telemetry, the listener or any database, DNS
//! or network work. It carries only what turn execution needs: the model catalog the API admits
//! against (ADR 0036), one qualified route per catalog model to OpenMettle's own gateway
//! (ADR 0038, ADR 0044) and the gateway installation each round is reserved and reported under.
//! The per-round bearer is made at handoff (ADR 0044), so the document holds no credential.
//! Login, cursor and session material stays in the API's document. Refusals are fixed
//! categories that never carry a path, URL, identifier or key byte.
use super::turns::{Route, TurnRoutes};
use crate::{
    auth_config::{self, Error as Shape, Object},
    authz::{
        CapabilityGate,
        approvals::{EffectClass, Proposal},
        runs::ClaimedRun,
    },
    mcp::contract::{
        ExternalRegistry, ExternalToolContract, IdempotencyCarrier, IdempotencyWindow,
        ReconcileSpec,
    },
    model_config::{Catalog, Effective, ProfilePin},
    provider_http::{
        Trust,
        inference::{
            self, Call, Gateway, History, Protocol, Qualification, SchemaSubset, Timeouts, Tool,
        },
        mcp::{McpTimeouts, McpTransport},
    },
    provider_keys::documents,
    vault::{HttpsRefreshClient, RefreshTimeouts, VaultRefreshRegistry},
    worker::DeclaredTool,
};
use serde_json::{Value, error::Category};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    sync::Arc,
    time::Duration,
};

/// The only accepted document version.
pub const VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A shape, path, file or catalog refusal, with the auth document's fixed text.
    Document(Shape),
    Installation,
    Coverage,
    Profile,
    DeviceSlot,
    Route,
    /// An `http://` route without `private_cidrs` to hold every gateway address.
    PlainRange,
    /// Invalid `external_mcp` connection transport, refresh route, or reviewed tool contract.
    ExternalMcp,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Document(error) => return error.fmt(f),
            Self::Installation => "gateway installation is not a canonical UUID",
            Self::Coverage => "inference routes do not name exactly the catalog's models",
            Self::Profile => "an inference route does not match its catalog profile",
            Self::DeviceSlot => {
                "a catalog profile requires a device slot, which the worker cannot grant"
            }
            Self::Route => {
                "an inference route endpoint, trust, address policy or timeout is invalid"
            }
            Self::PlainRange => {
                "a plain HTTP inference route needs private_cidrs holding every gateway address"
            }
            Self::ExternalMcp => {
                "external MCP transport, refresh route or tool contract configuration is invalid"
            }
        })
    }
}
impl std::error::Error for Error {}
impl From<Shape> for Error {
    fn from(error: Shape) -> Self {
        Self::Document(error)
    }
}

/// Validated external MCP transports, reviewed tool contracts, and optional provider-bound
/// OAuth refresh registry loaded from `OPENMETTLE_WORKER_INFERENCE_CONFIG` (ADRs 0039, 0045).
pub struct ExternalMcpRuntimeConfig {
    pub registry: Arc<ExternalRegistry>,
    pub transports: BTreeMap<String, Arc<McpTransport>>,
    pub refresh_registry: Option<Arc<VaultRefreshRegistry>>,
}

/// The validated catalog, routes, and optional external MCP runtime config, constructed together
/// or not at all.
pub struct InferenceConfig {
    pub catalog: Arc<Catalog>,
    pub routes: GatewayRoutes,
    pub external_mcp: Option<ExternalMcpRuntimeConfig>,
}

/// Metered routes for one gateway installation, plus optional reviewed external MCP declarations.
pub struct GatewayRoutes {
    installation: String,
    models: BTreeMap<String, (Arc<Gateway>, bool)>,
    registry: Option<Arc<ExternalRegistry>>,
}

fn conservative_tool_prompt_bound(request: &inference::Request) -> u64 {
    let mut total = 0u64;
    for item in &request.history {
        let delta = match item {
            History::User(text) => (text.len() as u64).saturating_add(16),
            History::UserImage { text, bytes, .. } => (text.len() as u64)
                .saturating_add((bytes.len() as u64) / 3)
                .saturating_add(256),
            History::Assistant {
                parts,
                reasoning,
                calls,
            } => {
                let mut n = 32u64;
                for part in parts {
                    n = n.saturating_add(part.len() as u64);
                }
                if let Some(r) = reasoning {
                    n = n.saturating_add(r.storage_bytes as u64);
                }
                for call in calls {
                    let args_len = serde_json::to_vec(&call.arguments)
                        .map(|v| v.len() as u64)
                        .unwrap_or(64);
                    n = n
                        .saturating_add(call.id.len() as u64)
                        .saturating_add(call.name.len() as u64)
                        .saturating_add(args_len)
                        .saturating_add(32);
                }
                n
            }
            History::ToolResult { id, output } => (id.len() as u64)
                .saturating_add(output.len() as u64)
                .saturating_add(32),
            History::RejectedGroup(errors) => {
                let mut n = 32u64;
                for err in errors {
                    n = n
                        .saturating_add(err.call_id.len() as u64)
                        .saturating_add(64);
                }
                n
            }
        };
        total = total.saturating_add(delta);
    }
    if let Some(tools) = &request.tools {
        for tool in tools {
            let schema_len = tool.parameters.to_string().len() as u64;
            total = total
                .saturating_add(tool.name.len() as u64)
                .saturating_add(tool.description.len() as u64)
                .saturating_add(schema_len)
                .saturating_add(64);
        }
    }
    total
}

impl TurnRoutes for GatewayRoutes {
    async fn route(
        &self,
        _: &ClaimedRun,
        _: &str,
        model: &Effective,
    ) -> Result<Route, inference::Error> {
        // Startup proved every model of the loaded catalog has a route. A run pinned under
        // another catalog has none and fails before any reservation.
        let (gateway, stream) = self
            .models
            .get(&model.model)
            .ok_or(inference::Error::Provisioning)?;
        Ok(Route::metered(
            gateway.clone(),
            self.installation.clone(),
            *stream,
        ))
    }

    fn tools(&self, _: &ClaimedRun) -> Vec<Tool> {
        self.registry
            .as_deref()
            .map(|r| {
                r.contracts()
                    .map(ExternalToolContract::declaration)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn declared_tools(&self, _: &ClaimedRun) -> Vec<DeclaredTool> {
        self.registry
            .as_deref()
            .map(|r| {
                r.contracts()
                    .map(ExternalToolContract::declared_tool)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn tool_prompt_bound(&self, _: &Effective, request: &inference::Request) -> Option<u64> {
        self.registry
            .as_ref()
            .map(|_| conservative_tool_prompt_bound(request))
    }

    fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
        let registry = self.registry.as_deref()?;
        let matches = registry.find_by_tool_id(&call.name);
        let [contract] = matches.as_slice() else {
            return None;
        };
        let raw_args = serde_json::to_vec(&call.arguments).ok()?;
        contract.proposal(&call.id, &raw_args).ok()
    }
}

/// One `routes` member, checked for shape before any file is read.
struct RouteFile {
    endpoint: String,
    /// `None` for an `http://` endpoint, which has no TLS and therefore no `trust` member;
    /// otherwise the bundle path, or `None` within for the native roots.
    trust: Option<Option<String>>,
    private_cidrs: Vec<String>,
    pin: ProfilePin,
    protocol: Protocol,
    stream: bool,
    images: bool,
    usage: bool,
    functions: Option<SchemaSubset>,
    parallel: bool,
    tool_separator_whitespace: bool,
    timeouts_ms: [u64; 3],
}
impl RouteFile {
    fn parse(value: Value) -> Result<Self, Shape> {
        let mut route = Object::new(value)?;
        let endpoint = route.string("endpoint")?;
        // An `http://` route has no TLS and so no `trust` member: `end` refuses one as unknown.
        // Every other route needs it. `Gateway::metered` checks that pairing again on the
        // parsed endpoint.
        let trust = match endpoint.starts_with("http://") {
            true => None,
            false => Some(auth_config::trust(&mut route)?),
        };
        let private_cidrs = auth_config::private_cidrs(&mut route)?;
        let mut pin = route.object("pin")?;
        let functions = match route.take_optional("functions") {
            None => None,
            Some(Value::String(s)) if s == "flat" => Some(SchemaSubset::Flat),
            Some(Value::String(s)) if s == "nested" => Some(SchemaSubset::Nested),
            Some(_) => return Err(Shape::Field),
        };
        let parallel = match route.take_optional("parallel") {
            None => false,
            Some(Value::Bool(b)) => b,
            Some(_) => return Err(Shape::Field),
        };
        let tool_separator_whitespace = match route.take_optional("tool_separator_whitespace") {
            None => false,
            Some(Value::Bool(b)) => b,
            Some(_) => return Err(Shape::Field),
        };
        let parsed = Self {
            endpoint,
            trust,
            private_cidrs,
            pin: ProfilePin {
                provider: pin.string("provider")?,
                revision: pin.string("revision")?,
                checkpoint: pin.string("checkpoint")?,
                template: pin.string("template")?,
                parser: pin.string("parser")?,
                runtime: pin.string("runtime")?,
                gateway: pin.string("gateway")?,
            },
            protocol: match route.string("protocol")?.as_str() {
                "chat_completions" => Protocol::Chat,
                "responses" => Protocol::Responses,
                _ => return Err(Shape::Field),
            },
            stream: route.boolean("stream")?,
            images: route.boolean("images")?,
            usage: route.boolean("usage")?,
            functions,
            parallel,
            tool_separator_whitespace,
            timeouts_ms: [
                route.integer("setup_timeout_milliseconds")?,
                route.integer("idle_timeout_milliseconds")?,
                route.integer("overall_timeout_milliseconds")?,
            ],
        };
        pin.end()?;
        route.end()?;
        Ok(parsed)
    }

    /// Setup covers DNS, connect and TLS; idle bounds each body read; overall bounds the call.
    fn timeouts(&self) -> Option<Timeouts> {
        let [setup, idle, overall] = self.timeouts_ms;
        ((100..=30_000).contains(&setup)
            && (1_000..=3_600_000).contains(&idle)
            && (1_000..=86_400_000).contains(&overall)
            && setup <= overall
            && idle <= overall)
            .then(|| Timeouts {
                setup: Duration::from_millis(setup),
                idle: Duration::from_millis(idle),
                overall: Duration::from_millis(overall),
            })
    }
}

fn opt_string(obj: &mut Object, name: &str) -> Result<Option<String>, Shape> {
    match obj.take_optional(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(Shape::Field),
    }
}

fn signed_i64(obj: &mut Object, name: &str) -> Result<i64, Shape> {
    obj.take(name)?.as_i64().ok_or(Shape::Field)
}

struct McpConnectionFile {
    endpoint: String,
    bundle_path: Option<String>,
    private_cidrs: Vec<String>,
    timeouts_ms: [u64; 3],
}

impl McpConnectionFile {
    fn parse(value: Value) -> Result<Self, Shape> {
        let mut obj = Object::new(value)?;
        let endpoint = obj.string("endpoint")?;
        let bundle_path = auth_config::trust(&mut obj)?;
        let private_cidrs = auth_config::private_cidrs(&mut obj)?;
        let timeouts_ms = [
            obj.integer("setup_timeout_milliseconds")?,
            obj.integer("idle_read_timeout_milliseconds")?,
            obj.integer("call_timeout_milliseconds")?,
        ];
        obj.end()?;
        Ok(Self {
            endpoint,
            bundle_path,
            private_cidrs,
            timeouts_ms,
        })
    }

    fn build(self) -> Result<Arc<McpTransport>, Error> {
        let [setup, idle, call] = self.timeouts_ms;
        if !(100..=30_000).contains(&setup)
            || !(100..=300_000).contains(&idle)
            || !(100..=300_000).contains(&call)
            || setup > call
            || idle > call
        {
            return Err(Error::ExternalMcp);
        }
        let bundle = self
            .bundle_path
            .as_deref()
            .map(auth_config::trust_bundle)
            .transpose()?;
        let trust = bundle.as_deref().map_or(Trust::Native, Trust::Bundle);
        let ranges: Vec<&str> = self.private_cidrs.iter().map(String::as_str).collect();
        let transport = McpTransport::new(
            &self.endpoint,
            trust,
            &ranges,
            McpTimeouts {
                setup: Duration::from_millis(setup),
                idle_read: Duration::from_millis(idle),
                call: Duration::from_millis(call),
            },
        )
        .map_err(|_| Error::ExternalMcp)?;
        Ok(Arc::new(transport))
    }
}

struct RefreshRouteFile {
    provider_kind: String,
    allowed_origins: Vec<String>,
    token_endpoint: String,
    bundle_path: Option<String>,
    private_cidrs: Vec<String>,
    client_id: Option<String>,
    timeouts_ms: [u64; 2],
}

impl RefreshRouteFile {
    fn parse(value: Value) -> Result<Self, Shape> {
        let mut obj = Object::new(value)?;
        let provider_kind = obj.string("provider_kind")?;
        let Value::Array(origins_raw) = obj.take("allowed_origins")? else {
            return Err(Shape::Field);
        };
        let mut allowed_origins = Vec::with_capacity(origins_raw.len());
        for item in origins_raw {
            match item {
                Value::String(s) => allowed_origins.push(s),
                _ => return Err(Shape::Field),
            }
        }
        let token_endpoint = obj.string("token_endpoint")?;
        let bundle_path = auth_config::trust(&mut obj)?;
        let private_cidrs = auth_config::private_cidrs(&mut obj)?;
        let client_id = opt_string(&mut obj, "client_id")?;
        let timeouts_ms = [
            obj.integer("setup_timeout_milliseconds")?,
            obj.integer("total_timeout_milliseconds")?,
        ];
        obj.end()?;
        Ok(Self {
            provider_kind,
            allowed_origins,
            token_endpoint,
            bundle_path,
            private_cidrs,
            client_id,
            timeouts_ms,
        })
    }

    fn build(self) -> Result<Arc<HttpsRefreshClient>, Error> {
        let [setup, total] = self.timeouts_ms;
        if !(100..=30_000).contains(&setup) || !(100..=60_000).contains(&total) || setup > total {
            return Err(Error::ExternalMcp);
        }
        let bundle = self
            .bundle_path
            .as_deref()
            .map(auth_config::trust_bundle)
            .transpose()?;
        let trust = bundle.as_deref().map_or(Trust::Native, Trust::Bundle);
        let origins: Vec<&str> = self.allowed_origins.iter().map(String::as_str).collect();
        let ranges: Vec<&str> = self.private_cidrs.iter().map(String::as_str).collect();
        let client = HttpsRefreshClient::new(
            &self.provider_kind,
            &origins,
            &self.token_endpoint,
            trust,
            &ranges,
            self.client_id,
            RefreshTimeouts {
                setup: Duration::from_millis(setup),
                total: Duration::from_millis(total),
            },
        )
        .map_err(|_| Error::ExternalMcp)?;
        Ok(Arc::new(client))
    }
}

fn parse_tool_contract(value: Value) -> Result<ExternalToolContract, Shape> {
    let mut obj = Object::new(value)?;
    let tool_id = obj.string("tool_id")?;
    let remote_name = obj.string("remote_name")?;
    let version = obj.string("version")?;
    let description = obj.string("description")?;
    let input_schema = obj.take("input_schema")?;
    if !input_schema.is_object() {
        return Err(Shape::Field);
    }
    let connection_id = obj.string("connection_id")?;
    let account_id = obj.string("account_id")?;
    let action = obj.string("action")?;
    let resource_field = opt_string(&mut obj, "resource_field")?;
    let fixed_resource = obj.string("fixed_resource")?;
    let class = match obj.string("class")?.as_str() {
        "prohibited" => EffectClass::Prohibited,
        "human_required" => EffectClass::HumanRequired,
        "sharing" => EffectClass::Sharing,
        "eligible_write" => EffectClass::EligibleWrite,
        "read" => EffectClass::Read,
        _ => return Err(Shape::Field),
    };
    let capability = obj.string("capability")?;
    let gate = match obj.string("gate")?.as_str() {
        "on_by_default" => CapabilityGate::OnByDefault,
        "opt_in" => CapabilityGate::OptIn,
        _ => return Err(Shape::Field),
    };
    let tool_policy = obj.string("tool_policy")?;
    let destination_policy = obj.string("destination_policy")?;
    let endpoint_id = obj.string("endpoint_id")?;
    let endpoint_version = obj.string("endpoint_version")?;
    let authoritative_lookup = obj.boolean("authoritative_lookup")?;
    let semantic_errors_are_side_effect_free =
        obj.boolean("semantic_errors_are_side_effect_free")?;
    let handle_field = opt_string(&mut obj, "handle_field")?;
    let idempotency = match obj.take_optional("idempotency") {
        None => None,
        Some(v) => {
            let mut id = Object::new(v)?;
            let namespace = id.string("namespace")?;
            let carrier_kind = id.string("carrier_kind")?;
            let carrier_name = id.string("carrier_name")?;
            let carrier = match carrier_kind.as_str() {
                "header" => IdempotencyCarrier::Header(carrier_name),
                "meta" => IdempotencyCarrier::Meta(carrier_name),
                _ => return Err(Shape::Field),
            };
            let valid_from_us = signed_i64(&mut id, "valid_from_us")?;
            let expires_us = signed_i64(&mut id, "expires_us")?;
            id.end()?;
            Some(IdempotencyWindow {
                namespace,
                carrier,
                valid_from_us,
                expires_us,
            })
        }
    };
    let reconcile = match obj.take_optional("reconcile") {
        None => None,
        Some(v) => {
            let mut rec = Object::new(v)?;
            let lookup_tool = rec.string("lookup_tool")?;
            let lookup_scope = rec.string("lookup_scope")?;
            let handle_argument = opt_string(&mut rec, "handle_argument")?;
            let deterministic_key_argument = opt_string(&mut rec, "deterministic_key_argument")?;
            let status_field = rec.string("status_field")?;
            rec.end()?;
            Some(ReconcileSpec {
                lookup_tool,
                lookup_scope,
                handle_argument,
                deterministic_key_argument,
                status_field,
            })
        }
    };
    let call_timeout_ms = obj.integer("call_timeout_milliseconds")?;
    obj.end()?;
    Ok(ExternalToolContract {
        tool_id,
        remote_name,
        version,
        description,
        input_schema,
        schema_digest: [0; 32],
        connection_id,
        account_id,
        action,
        resource_field,
        fixed_resource,
        class,
        capability,
        gate,
        tool_policy,
        destination_policy,
        endpoint_id,
        endpoint_version,
        idempotency,
        authoritative_lookup,
        semantic_errors_are_side_effect_free,
        handle_field,
        reconcile,
        call_timeout: Duration::from_millis(call_timeout_ms),
    })
}

struct ExternalMcpFile {
    connections: BTreeMap<String, McpConnectionFile>,
    refresh_routes: Vec<RefreshRouteFile>,
    tools: Vec<ExternalToolContract>,
}

impl ExternalMcpFile {
    fn parse(value: Value) -> Result<Self, Shape> {
        let mut obj = Object::new(value)?;
        let Value::Object(conns_raw) = obj.take("connections")? else {
            return Err(Shape::Field);
        };
        let connections = conns_raw
            .into_iter()
            .map(|(id, cfg)| Ok((id, McpConnectionFile::parse(cfg)?)))
            .collect::<Result<BTreeMap<_, _>, Shape>>()?;
        let refresh_routes = match obj.take_optional("refresh_routes") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .into_iter()
                .map(RefreshRouteFile::parse)
                .collect::<Result<Vec<_>, Shape>>()?,
            Some(_) => return Err(Shape::Field),
        };
        let Value::Array(tools_raw) = obj.take("tools")? else {
            return Err(Shape::Field);
        };
        let tools = tools_raw
            .into_iter()
            .map(parse_tool_contract)
            .collect::<Result<Vec<_>, Shape>>()?;
        obj.end()?;
        Ok(Self {
            connections,
            refresh_routes,
            tools,
        })
    }

    fn build(self) -> Result<ExternalMcpRuntimeConfig, Error> {
        if self.connections.is_empty() || self.tools.is_empty() {
            return Err(Error::ExternalMcp);
        }
        let mut transports = BTreeMap::new();
        for (connection_id, conn_file) in self.connections {
            if !crate::runs::is_canonical_uuid(&connection_id) {
                return Err(Error::ExternalMcp);
            }
            transports.insert(connection_id, conn_file.build()?);
        }
        let refresh_registry = if self.refresh_routes.is_empty() {
            None
        } else {
            let mut reg = VaultRefreshRegistry::new();
            for route in self.refresh_routes {
                reg.register(route.build()?)
                    .map_err(|_| Error::ExternalMcp)?;
            }
            Some(Arc::new(reg))
        };
        let mut registry = ExternalRegistry::new();
        let mut seen_tool_ids = BTreeSet::new();
        for contract in self.tools {
            if !transports.contains_key(&contract.connection_id)
                || !seen_tool_ids.insert(contract.tool_id.clone())
                || contract.call_timeout < Duration::from_millis(100)
            {
                return Err(Error::ExternalMcp);
            }
            registry
                .register(contract)
                .map_err(|_| Error::ExternalMcp)?;
        }
        Ok(ExternalMcpRuntimeConfig {
            registry: Arc::new(registry),
            transports,
            refresh_registry,
        })
    }
}

/// Loads and validates the document at `path` and every file it names. Offline and read-only.
pub fn load(path: &Path) -> Result<InferenceConfig, Error> {
    let bytes = auth_config::read(path, auth_config::MAX_CONFIG_BYTES, Shape::ConfigFile)?;
    let value = documents::unique(&bytes).map_err(|e| match e.classify() {
        Category::Data => Shape::DuplicateField,
        _ => Shape::Json,
    })?;
    let mut root = Object::new(value).map_err(|_| Shape::Version)?;
    if root.take("version").ok().and_then(|v| v.as_u64()) != Some(VERSION) {
        return Err(Shape::Version.into());
    }
    let catalog_file = root.string("catalog_file")?;
    let installation = root.string("installation")?;
    let Value::Object(members) = root.take("routes")? else {
        return Err(Shape::Field.into());
    };
    let routes = members
        .into_iter()
        .map(|(model, route)| Ok((model, RouteFile::parse(route)?)))
        .collect::<Result<BTreeMap<_, _>, Shape>>()?;
    let external_mcp_file = root
        .take_optional("external_mcp")
        .map(ExternalMcpFile::parse)
        .transpose()?;
    root.end()?;

    if !crate::runs::is_canonical_uuid(&installation) {
        return Err(Error::Installation);
    }
    let catalog = auth_config::catalog(&catalog_file)?;
    if !routes.keys().eq(catalog.models().keys()) {
        return Err(Error::Coverage);
    }
    let mut models = BTreeMap::new();
    for (model, route) in routes {
        let profile = catalog.model(&model).ok_or(Error::Coverage)?;
        if route.pin != profile.pin {
            return Err(Error::Profile);
        }
        // Device slots need capacity grants (ADR 0042), which this worker does not hold.
        if profile.requires_device_slot {
            return Err(Error::DeviceSlot);
        }
        let timeouts = route.timeouts().ok_or(Error::Route)?;
        let bundle = route
            .trust
            .as_ref()
            .and_then(Option::as_deref)
            .map(auth_config::trust_bundle)
            .transpose()?;
        let trust = route
            .trust
            .as_ref()
            .map(|_| bundle.as_deref().map_or(Trust::Native, Trust::Bundle));
        // A plain route reaches only its configured ranges (ADR 0044).
        if route.trust.is_none() && route.private_cidrs.is_empty() {
            return Err(Error::PlainRange);
        }
        let ranges: Vec<&str> = route.private_cidrs.iter().map(String::as_str).collect();
        let qualification = Qualification {
            model: model.clone(),
            pin: route.pin,
            protocol: route.protocol,
            json: !route.stream,
            sse: route.stream,
            functions: route.functions,
            images: route.images,
            parallel: route.parallel,
            usage: route.usage,
            tool_separator_whitespace: route.tool_separator_whitespace,
        };
        let gateway = Gateway::metered(&route.endpoint, trust, &ranges, qualification, timeouts)
            .map_err(|_| Error::Route)?;
        models.insert(model, (Arc::new(gateway), route.stream));
    }
    let external_mcp = external_mcp_file.map(ExternalMcpFile::build).transpose()?;
    let registry = external_mcp.as_ref().map(|ext| Arc::clone(&ext.registry));
    Ok(InferenceConfig {
        catalog: Arc::new(catalog),
        routes: GatewayRoutes {
            installation,
            models,
            registry,
        },
        external_mcp,
    })
}

#[cfg(test)]
mod tests;
