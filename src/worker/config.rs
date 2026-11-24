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
    authz::runs::ClaimedRun,
    model_config::{Catalog, Effective, ProfilePin},
    provider_http::{
        Trust,
        inference::{self, Gateway, Protocol, Qualification, Timeouts},
    },
    provider_keys::documents,
};
use serde_json::{Value, error::Category};
use std::{collections::BTreeMap, fmt, path::Path, sync::Arc, time::Duration};

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
            *stream,
        ))
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
        let gateway = Gateway::metered(&route.endpoint, trust, &ranges, qualification, timeouts)
            .map_err(|_| Error::Route)?;
        models.insert(model, (Arc::new(gateway), route.stream));
    }
    Ok(InferenceConfig {
        catalog: Arc::new(catalog),
        routes: GatewayRoutes {
            installation,
            models,
        },
    })
}

#[cfg(test)]
mod tests;
