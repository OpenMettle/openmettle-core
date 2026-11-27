pub use openmettle_core::provider_http::{
    DNS_LOOKUP_SLOTS, Error, MAX_ADDRESSES, MAX_PRIVATE_RANGES, MAX_REQUEST_HEADER_BYTES,
    MAX_RESPONSE_HEADER_BYTES, MAX_RESPONSE_HEADERS, MAX_TRUST_BUNDLE_BYTES, ProviderMetricSlot,
    Trust, provider_error_outcome,
};
#[path = "../provider_http_support/wire.rs"]
pub(crate) mod fixture;
#[path = "../../src/provider_http/inference/mod.rs"]
pub mod inference;
#[path = "../../src/provider_http/transport.rs"]
pub mod transport;
