//! Gateway endpoint and usage-report transport unit checks (ADR 0044).
use openmettle_core::provider_http::{
    ProviderTransport, Trust,
    gateway::UsageReport,
    inference::{Gateway, Protocol, Qualification, Timeouts},
};
use std::time::Duration;

#[test]
fn generic_and_bearer_inference_endpoints_refuse_queries_and_plain_http() {
    let catalog = openmettle_core::model_config::Catalog::load(include_bytes!(
        "fixtures/conversation-catalog-v1.json"
    ))
    .unwrap();
    let qual = || Qualification {
        model: "a".into(),
        pin: catalog.model("a").unwrap().pin.clone(),
        protocol: Protocol::Chat,
        json: true,
        sse: false,
        functions: None,
        images: false,
        parallel: false,
        usage: true,
        tool_separator_whitespace: false,
    };
    let timeouts = Timeouts {
        setup: Duration::from_secs(1),
        idle: Duration::from_secs(1),
        overall: Duration::from_secs(1),
    };

    assert!(
        ProviderTransport::new(
            "https://gateway.example.test/admin/v1/budgets?page=1",
            Trust::Native,
            &[],
        )
        .is_err()
    );
    assert!(
        ProviderTransport::new(
            "http://gateway.example.test:8082/v1/chat/completions",
            Trust::Native,
            &["10.0.0.0/8"],
        )
        .is_err()
    );
    assert!(
        Gateway::new(
            "http://gateway.example.test:8082/v1/chat/completions",
            Trust::Native,
            &["10.0.0.0/8"],
            qual(),
            timeouts,
        )
        .is_err()
    );
    assert!(
        Gateway::new(
            "https://gateway.example.test/v1/chat/completions",
            Trust::Native,
            &[],
            qual(),
            timeouts,
        )
        .is_ok()
    );
}

#[test]
fn usage_report_validates_identifiers_counts_and_measured_totals() {
    let id = |n| format!("00000000-0000-4000-8000-{n:012}");
    let base = UsageReport {
        request: id(1),
        installation: id(2),
        principal: id(3),
        scope: id(4),
        source: id(2),
        report_id: id(1),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(10),
        completion_tokens: Some(6),
        reasoning_tokens: Some(4),
        reasoning_included: Some(true),
        cost: None,
        unit: None,
    };
    assert!(base.valid());
    assert_eq!(base.measured(), Some(16));

    let separate = UsageReport {
        reasoning_included: Some(false),
        ..base.clone()
    };
    assert!(separate.valid());
    assert_eq!(separate.measured(), Some(20));

    let missing_flag = UsageReport {
        reasoning_included: None,
        ..base.clone()
    };
    assert!(!missing_flag.valid());

    let negative_rev = UsageReport {
        revision: -1,
        ..base.clone()
    };
    assert!(!negative_rev.valid());

    let half_cost = UsageReport {
        cost: Some("10".into()),
        unit: None,
        ..base
    };
    assert!(!half_cost.valid());
}
