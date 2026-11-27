//! Recompile the production route and codec under cfg(test) for the loopback-only DNS seam.
//! The normal library cannot construct a loopback gateway. Reuse its worker and catalog types.
use openmettle_core::{authz, model_config, telemetry, worker};
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

#[tokio::test]
async fn inference_gateway_records_provider_http_metrics_once_per_exchange() {
    use provider_http::{
        fixture::{Reply, response},
        inference::{Credential, Error, Protocol},
    };
    use serde_json::json;
    use support::*;
    use telemetry::metrics::{self, ProviderOperation, ProviderOutcome};

    // 1. Non-streaming 200 increments Ok by 1.
    let before =
        metrics::global().provider_http_count(ProviderOperation::Inference, ProviderOutcome::Ok);
    let body = wire(
        Protocol::Chat,
        false,
        json!({"role": "assistant", "content": "hi"}),
        json!("stop"),
        vec![],
    );
    assert!(once(Protocol::Chat, false, body).await.is_ok());
    assert!(
        metrics::global().provider_http_count(ProviderOperation::Inference, ProviderOutcome::Ok)
            > before
    );

    // 2. Multi-chunk streaming 200 SSE increments Ok by exactly 1 (not per chunk).
    let stream_body = sse(
        &(delta(json!({"role": "assistant", "content": "a"}), json!(null))
            + &delta(json!({"content": "b"}), json!(null))
            + &delta(json!({"content": "c"}), json!("stop"))
            + "data: [DONE]\r\n\r\n"),
    );
    let before_stream =
        metrics::global().provider_http_count(ProviderOperation::Inference, ProviderOutcome::Ok);
    let mut chunks = 0usize;
    let c = catalog(Protocol::Chat, true);
    let e = effective(&c, false);
    let mock = Mock::new(Protocol::Chat, move |_| Reply::Bytes(stream_body.clone())).await;
    let turn = mock
        .gateway(&e, NORMAL)
        .caller(&c, &e, &request(true), Credential::Bearer(TOKEN), |_| {
            chunks += 1;
            async {}
        })
        .await
        .unwrap();
    assert_eq!(turn.answers[0].parts.concat(), "abc");
    assert!(chunks >= 3, "expected multi-chunk stream, got {chunks}");
    assert!(
        metrics::global().provider_http_count(ProviderOperation::Inference, ProviderOutcome::Ok)
            > before_stream
    );

    // 3. Non-2xx response increments HttpError.
    let before_err = metrics::global()
        .provider_http_count(ProviderOperation::Inference, ProviderOutcome::HttpError);
    let err = once(Protocol::Chat, false, response(502, &[], b"bad gateway"))
        .await
        .err();
    assert_eq!(err, Some(Error::Provider));
    assert!(
        metrics::global()
            .provider_http_count(ProviderOperation::Inference, ProviderOutcome::HttpError)
            > before_err
    );

    // 4. Pre-connect local validation failure (MissingEntitlement) never sends HTTP traffic.
    let mock_unused = Mock::new(Protocol::Chat, |_| Reply::Bytes(response(200, &[], b""))).await;
    let local_err = mock_unused
        .gateway(&e, NORMAL)
        .caller(
            &c,
            &e,
            &request(false),
            Credential::MissingEntitlement,
            |_| async {},
        )
        .await
        .err();
    assert_eq!(local_err, Some(Error::Provisioning));
    mock_unused.assert_inference_only(0);
}
