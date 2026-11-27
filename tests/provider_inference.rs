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

const METRICS_CHILD: &str = "OPENMETTLE_INFERENCE_METRICS_CHILD";

#[test]
fn inference_gateway_records_provider_http_metrics_once_per_exchange() {
    // Isolate process-wide metrics in a child subprocess so parallel test threads cannot perturb
    // exact `== 1` / `== 0` counter deltas.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inference_gateway_metrics_child",
            "--ignored",
            "--nocapture",
        ])
        .env(METRICS_CHILD, "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "metrics child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
}

#[tokio::test]
#[ignore = "subprocess with isolated global metrics"]
async fn inference_gateway_metrics_child() {
    if std::env::var(METRICS_CHILD).as_deref() != Ok("1") {
        return;
    }
    use provider_http::{
        fixture::{Reply, response},
        inference::{Credential, Error, Protocol, Timeouts},
    };
    use serde_json::json;
    use std::time::Duration;
    use support::*;
    use telemetry::metrics::{self, ProviderOperation, ProviderOutcome};

    let count =
        |outcome| metrics::global().provider_http_count(ProviderOperation::Inference, outcome);
    let total_all = || -> u64 { ProviderOutcome::ALL.iter().map(|&o| count(o)).sum() };

    // 1. Non-streaming 200 increments Ok by exact 1.
    let before = count(ProviderOutcome::Ok);
    let body = wire(
        Protocol::Chat,
        false,
        json!({"role": "assistant", "content": "hi"}),
        json!("stop"),
        vec![],
    );
    assert!(once(Protocol::Chat, false, body).await.is_ok());
    assert_eq!(count(ProviderOutcome::Ok) - before, 1);

    // 2. Multi-chunk streaming 200 SSE increments Ok by exact 1 (never per chunk).
    let stream_body = sse(
        &(delta(json!({"role": "assistant", "content": "a"}), json!(null))
            + &delta(json!({"content": "b"}), json!(null))
            + &delta(json!({"content": "c"}), json!("stop"))
            + "data: [DONE]\r\n\r\n"),
    );
    let before_stream = count(ProviderOutcome::Ok);
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
    assert_eq!(count(ProviderOutcome::Ok) - before_stream, 1);

    // 3. Non-2xx response increments HttpError by exact 1 (and Ok by 0).
    let before_err = count(ProviderOutcome::HttpError);
    let before_ok = count(ProviderOutcome::Ok);
    let err = once(Protocol::Chat, false, response(502, &[], b"bad gateway"))
        .await
        .err();
    assert_eq!(err, Some(Error::Provider));
    assert_eq!(count(ProviderOutcome::HttpError) - before_err, 1);
    assert_eq!(count(ProviderOutcome::Ok) - before_ok, 0);

    // 4. Outer `within_overall` deadline expiry AFTER inner decode completes must record Timeout
    // (exact 1) and must NOT record Ok (exact 0).
    let slow_body = sse(&(delta(
        json!({"role": "assistant", "content": "late"}),
        json!("stop"),
    ) + "data: [DONE]\r\n\r\n"));
    let slow_mock = Mock::new(Protocol::Chat, move |_| Reply::Bytes(slow_body.clone())).await;
    let tight = Timeouts {
        setup: Duration::from_secs(2),
        idle: Duration::from_secs(2),
        overall: Duration::from_millis(60),
    };
    let before_timeout = count(ProviderOutcome::Timeout);
    let before_ok = count(ProviderOutcome::Ok);
    let timed = slow_mock
        .gateway(&e, tight)
        .caller(
            &c,
            &e,
            &request(true),
            Credential::Bearer(TOKEN),
            |_| async {
                // Sleep synchronously across the outer `overall` deadline while inside final delta
                // delivery so `dispatch` returns `Ok(Turn)` past `overall` and `within_overall` fires.
                std::thread::sleep(Duration::from_millis(90));
            },
        )
        .await
        .err();
    assert_eq!(timed, Some(Error::Timeout));
    assert_eq!(count(ProviderOutcome::Timeout) - before_timeout, 1);
    assert_eq!(count(ProviderOutcome::Ok) - before_ok, 0);

    // 5. Pre-connect local validation failure (MissingEntitlement) emits exact 0 metrics.
    let mock_unused = Mock::new(Protocol::Chat, |_| Reply::Bytes(response(200, &[], b""))).await;
    let before_all = total_all();
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
    assert_eq!(total_all() - before_all, 0);
}
