//! Recompile the production route and codec under cfg(test) for the loopback-only DNS seam.
//! The normal library cannot construct a loopback gateway. Reuse its worker and catalog types.
use openmettle_core::{authz, model_config, worker};
#[path = "provider_inference/authentication.rs"]
mod authentication;
#[path = "provider_inference/conformance.rs"]
mod conformance;
#[path = "provider_inference/dns.rs"]
mod dns;
#[path = "provider_inference/http.rs"]
pub mod provider_http;
#[path = "provider_inference/recorded_sglang.rs"]
mod recorded_sglang;
#[path = "support/sglang_recorded.rs"]
mod sglang_recorded;
#[path = "provider_inference/support.rs"]
mod support;
#[path = "provider_inference/timing.rs"]
mod timing;
#[path = "provider_inference/wire.rs"]
mod wire;
