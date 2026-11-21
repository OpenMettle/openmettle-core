mod wire;
use super::{ProviderTransport, Trust};
use openidconnect::{HttpRequest, http};
pub use wire::*;
pub fn url(port: u16) -> String {
    format!("https://{HOST}:{port}/token")
}

pub fn transport(port: u16, ca: &Ca) -> ProviderTransport {
    ProviderTransport::new(&url(port), Trust::Bundle(&ca.pem()), &[])
        .unwrap()
        .with_lookup(loopback)
        .allow_loopback_fixture()
}

/// The request shape the library produces for a public-client token exchange.
pub fn token_request(url: &str) -> HttpRequest {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header(http::header::ACCEPT, "application/json")
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(b"grant_type=authorization_code&code=synthetic".to_vec())
        .unwrap()
}
