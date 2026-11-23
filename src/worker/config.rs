//! The packaged worker's inference configuration (ADR 0043).
//!
//! `OPENMETTLE_WORKER_INFERENCE_CONFIG` names one strict JSON document. The document and the
//! files it names are read once at startup, before telemetry, the listener or any database, DNS
//! or network work. It carries only what turn execution needs: the model catalog the API admits
//! against (ADR 0036), one qualified HTTPS route per catalog model (ADR 0038) and, provisionally,
//! the dispatch credential source of the library's metered path: the gateway installation and the
//! API document's `gateway_keys` ring format (ADR 0037). A later gateway-authorization increment
//! replaces that source. Login, cursor and session material stays in the API's document.
//! Refusals are fixed categories that never carry a path, URL, identifier or key byte.
use super::turns::{Route, TurnRoutes};
use crate::{
    auth_config::{self, CursorFiles, Error as Shape, Object},
    authz::runs::ClaimedRun,
    model_config::{Catalog, Effective, ProfilePin},
    provider_http::{
        Trust,
        inference::{self, Gateway, Protocol, Qualification, Timeouts},
    },
    provider_keys::{documents, gateway::GatewayKeys},
};
use serde_json::{Value, error::Category};
use std::{collections::BTreeMap, fmt, path::Path, sync::Arc, time::Duration};

/// The only accepted document version.
pub const VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A shape, path, file, catalog or key-ring refusal, with the auth document's fixed text.
    Document(Shape),
    Installation,
    Coverage,
    Profile,
    DeviceSlot,
    Route,
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
        })
    }
}
impl std::error::Error for Error {}
impl From<Shape> for Error {
    fn from(error: Shape) -> Self {
        Self::Document(error)
    }
}

/// The validated catalog and routes, constructed together or not at all.
pub struct InferenceConfig {
    pub catalog: Arc<Catalog>,
    pub routes: GatewayRoutes,
}

/// Metered routes for one gateway installation.
pub struct GatewayRoutes {
    installation: String,
    /// Provisional dispatch credential source (ADR 0043): the library's metered handoff unseals
    /// the admitted actor's gateway key with this ring. [`TurnRoutes::route`] below is the only
    /// place the worker supplies it; the gateway-authorization increment replaces both.
    keys: Arc<GatewayKeys>,
    models: BTreeMap<String, (Arc<Gateway>, bool)>,
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
            self.keys.clone(),
            *stream,
        ))
    }
}

/// One `routes` member, checked for shape before any file is read.
struct RouteFile {
    endpoint: String,
    bundle_path: Option<String>,
    private_cidrs: Vec<String>,
    pin: ProfilePin,
    protocol: Protocol,
    stream: bool,
    images: bool,
    usage: bool,
    timeouts_ms: [u64; 3],
}
impl RouteFile {
    fn parse(value: Value) -> Result<Self, Shape> {
        let mut route = Object::new(value)?;
        let (bundle_path, private_cidrs) = auth_config::destination(&mut route)?;
        let mut pin = route.object("pin")?;
        let parsed = Self {
            endpoint: route.string("endpoint")?,
            bundle_path,
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
    let keys = CursorFiles::parse(root.object("gateway_keys")?, "decrypt_only")?;
    let Value::Object(members) = root.take("routes")? else {
        return Err(Shape::Field.into());
    };
    let routes = members
        .into_iter()
        .map(|(model, route)| Ok((model, RouteFile::parse(route)?)))
        .collect::<Result<BTreeMap<_, _>, Shape>>()?;
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
            .bundle_path
            .as_deref()
            .map(auth_config::trust_bundle)
            .transpose()?;
        let ranges: Vec<&str> = route.private_cidrs.iter().map(String::as_str).collect();
        // The worker offers no tools until reviewed tool rounds are wired (V1-14), so the
        // function, parallel-call and separator qualifications stay off.
        let qualification = Qualification {
            model: model.clone(),
            pin: route.pin,
            protocol: route.protocol,
            json: !route.stream,
            sse: route.stream,
            functions: None,
            images: route.images,
            parallel: false,
            usage: route.usage,
            tool_separator_whitespace: false,
        };
        let gateway = Gateway::new(
            &route.endpoint,
            bundle.as_deref().map_or(Trust::Native, Trust::Bundle),
            &ranges,
            qualification,
            timeouts,
        )
        .map_err(|_| Error::Route)?;
        models.insert(model, (Arc::new(gateway), route.stream));
    }
    // Provisional (ADR 0043): the API document's ring format, read last and only here.
    let keys = Arc::new(auth_config::gateway_keys(&keys.gateway_material()?)?);
    Ok(InferenceConfig {
        catalog: Arc::new(catalog),
        routes: GatewayRoutes {
            installation,
            keys,
            models,
        },
    })
}

#[cfg(test)]
mod tests;
