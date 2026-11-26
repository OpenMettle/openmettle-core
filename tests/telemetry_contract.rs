//! Telemetry contract v1 conformance, bounded-cardinality, privacy and alert-rule checks
//! (V1-29 Increment 3 / ADR 0028). Runs completely offline without PostgreSQL or a cluster.
use openmettle_core::telemetry::{
    self, Process,
    metrics::{
        self, CONTRACT_VERSION, CapacityOperation, CapacityOutcome, CapacityStaleSurface,
        CapacityWaitOutcome, DESCRIPTORS, DURATION_BUCKETS, DroppedSignal, InstrumentKind, Metrics,
        ProviderOperation, ProviderOutcome, QuotaDriftOutcome, ReadinessOutcome, RouteClass,
        StatusClass, StorageOperation, StorageOutcome,
    },
};
use opentelemetry_proto::tonic::metrics::v1::metric;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Duration,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_contract() -> Value {
    let text = std::fs::read_to_string(root().join("contracts/telemetry/v1.json"))
        .expect("contracts/telemetry/v1.json must exist");
    serde_json::from_str(&text).expect("contracts/telemetry/v1.json must be valid JSON")
}

#[test]
fn telemetry_contract_matches_compiled_log_and_trace_allowlists() {
    let contract = load_contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some(CONTRACT_VERSION)
    );
    assert_eq!(contract["service_namespace"].as_str(), Some("openmettle"));
    assert_eq!(
        contract["policy"]["inbound_trace_context"].as_str(),
        Some("ignored")
    );
    assert_eq!(
        contract["policy"]["prometheus_translation"].as_str(),
        Some("UnderscoreEscapingWithSuffixes")
    );
    let resource_attrs: Vec<&str> = contract["policy"]["resource_attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(resource_attrs, ["service.name", "service.instance.id"]);
    assert_eq!(
        contract["policy"]["retention_ceilings"]["traces_hours"].as_u64(),
        Some(72)
    );
    assert_eq!(
        contract["policy"]["retention_ceilings"]["logs_days"].as_u64(),
        Some(7)
    );
    assert_eq!(
        contract["policy"]["retention_ceilings"]["metrics_days"].as_u64(),
        Some(14)
    );

    assert_eq!(contract["logs"]["target"].as_str(), Some(telemetry::TARGET));
    let contract_log_fields: Vec<&str> = contract["logs"]["allowed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(contract_log_fields.as_slice(), telemetry::FIELDS);

    assert_eq!(
        contract["traces"]["target"].as_str(),
        Some(telemetry::TARGET)
    );
    let contract_span_fields: Vec<&str> = contract["traces"]["allowed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(contract_span_fields.as_slice(), telemetry::SPAN_FIELDS);

    // Every log event field must belong to the compiled allowlist.
    let allowed: BTreeSet<&str> = telemetry::FIELDS.iter().copied().collect();
    for event in contract["logs"]["events"].as_array().unwrap() {
        let name = event["name"].as_str().unwrap();
        for field in event["fields"].as_array().unwrap() {
            let field = field.as_str().unwrap();
            assert!(
                allowed.contains(field),
                "event {name} references field {field} outside telemetry::FIELDS"
            );
        }
    }
}

#[test]
fn telemetry_contract_metrics_match_rust_descriptors_and_cardinality_ceiling() {
    let contract = load_contract();
    let disallowed: Vec<&str> = contract["policy"]["disallowed_metric_label_substrings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!disallowed.is_empty());

    let contract_metrics = contract["metrics"].as_array().unwrap();
    assert_eq!(
        contract_metrics.len(),
        DESCRIPTORS.len(),
        "contracts/telemetry/v1.json metric list must match metrics::DESCRIPTORS 1:1"
    );

    let mut total_streams = 0usize;
    let mut total_prom_series = 0usize;
    let mut seen_otel = BTreeSet::new();
    let mut seen_prom = BTreeSet::new();
    for (entry, descriptor) in contract_metrics.iter().zip(DESCRIPTORS.iter()) {
        assert!(seen_otel.insert(descriptor.name), "duplicate OTel metric");
        assert!(
            seen_prom.insert(descriptor.prometheus_name),
            "duplicate Prometheus metric"
        );
        assert_eq!(entry["name"].as_str(), Some(descriptor.name));
        assert_eq!(
            entry["prometheus_name"].as_str(),
            Some(descriptor.prometheus_name)
        );
        assert_eq!(entry["kind"].as_str(), Some(descriptor.kind.as_str()));
        assert_eq!(entry["unit"].as_str(), Some(descriptor.unit));
        assert_eq!(
            entry["max_series"].as_u64(),
            Some(descriptor.max_series() as u64),
            "max_series mismatch on {}",
            descriptor.name
        );
        total_streams += descriptor.max_series();
        total_prom_series += descriptor.max_prometheus_series();

        match descriptor.buckets {
            Some(expected_buckets) => {
                let actual: Vec<f64> = entry["buckets"]
                    .as_array()
                    .unwrap_or_else(|| panic!("missing buckets on {}", descriptor.name))
                    .iter()
                    .map(|v| v.as_f64().unwrap())
                    .collect();
                assert_eq!(actual.as_slice(), expected_buckets);
                assert!(actual.windows(2).all(|w| w[0] < w[1]));
            }
            None => assert!(
                entry.get("buckets").is_none(),
                "counter {} must not declare buckets",
                descriptor.name
            ),
        }

        let contract_labels = entry["labels"].as_object().unwrap();
        assert_eq!(
            contract_labels.len(),
            descriptor.labels.len(),
            "label count mismatch on {}",
            descriptor.name
        );
        for label in descriptor.labels {
            let lower = label.name.to_ascii_lowercase();
            for bad in &disallowed {
                assert!(
                    !lower.contains(bad),
                    "metric {} label {} contains disallowed substring {bad}",
                    descriptor.name,
                    label.name
                );
            }
            let values: Vec<&str> = contract_labels
                .get(label.name)
                .unwrap_or_else(|| {
                    panic!(
                        "metric {} missing label {} in v1.json",
                        descriptor.name, label.name
                    )
                })
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(
                values.as_slice(),
                label.values,
                "label values mismatch on {}.{}",
                descriptor.name,
                label.name
            );
            assert!(
                !values.is_empty(),
                "label {}.{} must not be empty",
                descriptor.name,
                label.name
            );
            let unique: BTreeSet<&str> = values.iter().copied().collect();
            assert_eq!(
                unique.len(),
                values.len(),
                "duplicate values on {}.{}",
                descriptor.name,
                label.name
            );
        }
    }

    assert_eq!(total_streams, metrics::max_total_series());
    assert_eq!(total_prom_series, metrics::max_total_prometheus_series());
    assert_eq!(
        contract["policy"]["max_data_point_streams"].as_u64(),
        Some(total_streams as u64)
    );
    assert_eq!(
        contract["policy"]["max_prometheus_series_per_process"].as_u64(),
        Some(total_prom_series as u64)
    );

    // Both capacity.grants (V1-18) and storage.quota.drift (V1-17) are now implemented in
    // `metrics`; only V1-10 queue age and V1-30 backup runs remain reserved.
    let reserved = contract["reserved_signals"].as_array().unwrap();
    let mut reserved_by_name = BTreeMap::new();
    for entry in reserved {
        let name = entry["name"].as_str().unwrap();
        let owner = entry["owner_ticket"].as_str().unwrap();
        assert!(
            !seen_otel.contains(name),
            "implemented metric {name} must not remain in reserved_signals"
        );
        assert!(
            reserved_by_name.insert(name, owner).is_none(),
            "duplicate reserved signal {name}"
        );
    }
    assert_eq!(
        reserved_by_name.get("openmettle.runs.queue.age"),
        Some(&"V1-10")
    );
    assert_eq!(
        reserved_by_name.get("openmettle.backup.runs"),
        Some(&"V1-30")
    );
    assert_eq!(reserved_by_name.len(), 2);
    assert!(!reserved_by_name.contains_key("openmettle.storage.quota.drift"));
    assert!(!reserved_by_name.contains_key("openmettle.capacity.grants"));
    for implemented in [
        "openmettle.capacity.grants",
        "openmettle.capacity.observations.stale",
        "openmettle.capacity.wait.duration",
        "openmettle.storage.quota.drift",
    ] {
        assert!(
            seen_otel.contains(implemented),
            "missing implemented v1 metric {implemented}"
        );
    }
}

#[test]
fn exhaustive_metric_recording_never_exceeds_contract_cardinality() {
    let instance_id = "11111111-2222-4333-8444-555555555555";
    let store = Metrics::new();
    let baseline = store
        .encode_otlp(Process::Api, Some(instance_id))
        .expect("fresh registry emits zero-initialized openmettle.telemetry.dropped baseline");
    let baseline_metrics = &baseline.resource_metrics[0].scope_metrics[0].metrics;
    assert_eq!(baseline_metrics.len(), 1);
    assert_eq!(baseline_metrics[0].name, "openmettle.telemetry.dropped");
    match baseline_metrics[0].data.as_ref().unwrap() {
        metric::Data::Sum(sum) => {
            assert_eq!(sum.data_points.len(), DroppedSignal::ALL.len());
            assert!(sum.data_points.iter().all(|dp| {
                matches!(
                    dp.value,
                    Some(
                        opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(0)
                    )
                )
            }));
        }
        other => panic!("expected Sum for openmettle.telemetry.dropped, got {other:?}"),
    }

    // Worker baseline additionally emits zero-initialized overdue handoffs and all 8 quota drift outcomes.
    let worker_baseline = store
        .encode_otlp(Process::Worker, Some(instance_id))
        .expect("fresh worker registry emits zero-initialized baseline series");
    let worker_metrics = &worker_baseline.resource_metrics[0].scope_metrics[0].metrics;
    let worker_names: Vec<&str> = worker_metrics.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        worker_names,
        [
            "openmettle.telemetry.dropped",
            "openmettle.quota.overdue.handoffs",
            "openmettle.storage.quota.drift",
        ]
    );
    match worker_metrics[2].data.as_ref().unwrap() {
        metric::Data::Sum(sum) => {
            assert_eq!(sum.data_points.len(), QuotaDriftOutcome::ALL.len());
            assert!(sum.data_points.iter().all(|dp| {
                matches!(
                    dp.value,
                    Some(
                        opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(0)
                    )
                )
            }));
        }
        other => panic!("expected Sum for openmettle.storage.quota.drift, got {other:?}"),
    }

    // An overdue handoff can be observed again on a later sweep.
    for step in metrics::GatewayStep::ALL {
        for cause in metrics::GatewayCause::ALL {
            store.record_gateway_failure(step, cause);
        }
    }
    for age in [0, 60, 3600] {
        store.record_gateway_lag(age);
    }
    store.record_overdue_handoffs(3);
    store.record_overdue_handoffs(2);

    // Exhaust every single enum combination across all metrics.
    for &m in telemetry::Method::ALL {
        for &r in RouteClass::ALL {
            for &s in StatusClass::ALL {
                store.record_http(m, r, s, Duration::from_millis(12));
            }
        }
    }
    for &o in ReadinessOutcome::ALL {
        store.record_db_readiness(o, Duration::from_millis(3));
    }
    for &op in ProviderOperation::ALL {
        for &o in ProviderOutcome::ALL {
            store.record_provider_http(op, o, Duration::from_millis(45));
        }
    }
    for &op in StorageOperation::ALL {
        for &o in StorageOutcome::ALL {
            store.record_storage(op, o);
        }
    }
    use openmettle_core::authz::leases::CancelReason;
    for reason in [CancelReason::Requested, CancelReason::Revoked] {
        store.record_cancellation(reason);
    }
    for &sig in DroppedSignal::ALL {
        store.record_dropped(sig, 1);
    }
    for &op in CapacityOperation::ALL {
        for &outcome in CapacityOutcome::ALL {
            store.record_capacity_grant(op, outcome);
        }
    }
    for &surface in CapacityStaleSurface::ALL {
        store.record_capacity_stale_observation(surface);
    }
    for &outcome in CapacityWaitOutcome::ALL {
        store.record_capacity_wait(outcome, Duration::from_millis(25));
    }
    for &outcome in QuotaDriftOutcome::ALL {
        store.record_quota_drift(outcome, 1);
    }

    let request = store
        .encode_otlp(Process::Api, Some(instance_id))
        .expect("populated registry encodes OTLP metrics");
    assert_eq!(request.resource_metrics.len(), 1);
    let rm = &request.resource_metrics[0];
    let res_attrs: BTreeMap<&str, &str> = rm
        .resource
        .as_ref()
        .unwrap()
        .attributes
        .iter()
        .map(|kv| {
            let val = match kv.value.as_ref().unwrap().value.as_ref().unwrap() {
                opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s) => {
                    s.as_str()
                }
                other => panic!("expected string resource attribute, got {other:?}"),
            };
            (kv.key.as_str(), val)
        })
        .collect();
    assert_eq!(res_attrs.get("service.name"), Some(&"openmettle-api"));
    assert_eq!(res_attrs.get("service.instance.id"), Some(&instance_id));
    assert_eq!(res_attrs.len(), 2);

    let scope = &rm.scope_metrics[0];
    assert_eq!(scope.scope.as_ref().unwrap().version, CONTRACT_VERSION);
    assert_eq!(scope.metrics.len(), DESCRIPTORS.len());

    let mut total_points = 0usize;
    for (proto_metric, descriptor) in scope.metrics.iter().zip(DESCRIPTORS.iter()) {
        assert_eq!(proto_metric.name, descriptor.name);
        assert_eq!(proto_metric.unit, descriptor.unit);
        let point_count = match (descriptor.kind, proto_metric.data.as_ref().unwrap()) {
            (InstrumentKind::Counter, metric::Data::Sum(sum)) => {
                assert!(sum.is_monotonic);
                if descriptor.name == "openmettle.quota.overdue.handoffs" {
                    assert!(sum.data_points[0].attributes.is_empty());
                    assert!(matches!(sum.data_points[0].value, Some(
                        opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(5)
                    )));
                }
                sum.data_points.len()
            }
            (InstrumentKind::Histogram, metric::Data::Histogram(hist)) => {
                for dp in &hist.data_points {
                    assert_eq!(dp.explicit_bounds.as_slice(), &DURATION_BUCKETS);
                    assert_eq!(dp.bucket_counts.len(), DURATION_BUCKETS.len() + 1);
                    let bucket_sum: u64 = dp.bucket_counts.iter().sum();
                    assert_eq!(dp.count, bucket_sum);
                }
                hist.data_points.len()
            }
            _ => panic!("unexpected OTLP data kind for {}", descriptor.name),
        };
        assert_eq!(point_count, descriptor.max_series());
        total_points += point_count;
    }
    assert_eq!(total_points, metrics::max_total_series());
}

/// Extracts every `expr: |` PromQL block from `contracts/telemetry/alerts-v1.yaml`.
fn extract_alert_exprs(yaml: &str) -> Vec<String> {
    let mut exprs = Vec::new();
    let lines: Vec<&str> = yaml.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let trimmed = lines[idx].trim_start();
        if trimmed == "expr: |" {
            let base_indent = lines[idx].len() - trimmed.len();
            idx += 1;
            let mut block = String::new();
            while idx < lines.len() {
                let line = lines[idx];
                if line.trim().is_empty() {
                    block.push('\n');
                    idx += 1;
                    continue;
                }
                let indent = line.len() - line.trim_start().len();
                if indent <= base_indent {
                    break;
                }
                block.push_str(line.trim());
                block.push('\n');
                idx += 1;
            }
            exprs.push(block);
        } else {
            idx += 1;
        }
    }
    exprs
}

#[test]
fn alert_rules_reference_only_declared_v1_metrics_and_safe_labels() {
    let contract = load_contract();
    let disallowed: Vec<&str> = contract["policy"]["disallowed_metric_label_substrings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    // Map each Prometheus metric name to its allowed Prometheus-normalized label names -> enum values.
    let mut allowed_metrics: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for entry in contract["metrics"].as_array().unwrap() {
        let prom_name = entry["prometheus_name"].as_str().unwrap().to_owned();
        let mut labels: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (k, vals) in entry["labels"].as_object().unwrap() {
            let set = vals
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            labels.insert(k.replace('.', "_"), set);
        }
        // Standard Prometheus resource label derived from `service.name`.
        labels.insert(
            "job".to_owned(),
            [
                "openmettle-api".to_owned(),
                "openmettle-worker".to_owned(),
                "openmettle-gateway".to_owned(),
            ]
            .into(),
        );
        allowed_metrics.insert(prom_name, labels);
    }

    let yaml = std::fs::read_to_string(root().join("contracts/telemetry/alerts-v1.yaml"))
        .expect("contracts/telemetry/alerts-v1.yaml must exist");
    let alert_count = yaml
        .lines()
        .filter(|line| line.trim_start().starts_with("- alert:"))
        .count();
    assert!(alert_count >= 5, "expected at least 5 v1 alert rules");
    assert!(yaml.contains("signal_contract: v1"));

    let exprs = extract_alert_exprs(&yaml);
    assert_eq!(
        exprs.len(),
        alert_count,
        "every alert rule must have an expr block"
    );

    let mut found_metrics = BTreeSet::new();
    for expr in &exprs {
        // Disallowed identifier substrings are checked on PromQL expressions (not comments/descriptions).
        let lower = expr.to_ascii_lowercase();
        for bad in &disallowed {
            assert!(
                !lower.contains(bad),
                "alert expr must not reference disallowed identifier/field {bad}: {expr}"
            );
        }

        // Collect every `openmettle_*` metric referenced in this expression and validate selectors.
        let bytes = expr.as_bytes();
        let mut i = 0;
        let mut expr_metrics = Vec::new();
        while i < bytes.len() {
            if expr[i..].starts_with("openmettle_") {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let ident = &expr[start..i];
                let allowed_labels = allowed_metrics.get(ident).unwrap_or_else(|| {
                    panic!("alerts-v1.yaml references undeclared metric {ident}")
                });
                found_metrics.insert(ident.to_owned());
                expr_metrics.push(ident.to_owned());

                if i < bytes.len() && bytes[i] == b'{' {
                    let close = expr[i..]
                        .find('}')
                        .expect("unclosed PromQL selector in alerts-v1.yaml")
                        + i;
                    let selector = &expr[i + 1..close];
                    for matcher in selector.split(',') {
                        let matcher = matcher.trim();
                        if matcher.is_empty() {
                            continue;
                        }
                        let op_pos = matcher
                            .find(['=', '!'])
                            .unwrap_or_else(|| panic!("malformed selector {matcher:?}"));
                        let key = matcher[..op_pos].trim();
                        let allowed_values = allowed_labels.get(key).unwrap_or_else(|| {
                            panic!("alerts-v1.yaml references undeclared label {key} on {ident}")
                        });
                        let rhs = matcher[op_pos..]
                            .trim_start_matches(['=', '!', '~'])
                            .trim()
                            .trim_matches('"');
                        for atom in rhs.split('|') {
                            assert!(
                                allowed_values.contains(atom),
                                "alerts-v1.yaml uses undeclared value {atom:?} for {ident}.{key} (allowed: {allowed_values:?})"
                            );
                        }
                    }
                    i = close + 1;
                }
            } else {
                i += 1;
            }
        }

        // Validate every `by (...)` grouping clause against the metrics referenced in this expr.
        let mut rest = expr.as_str();
        while let Some(pos) = rest.find("by (") {
            let after = &rest[pos + 4..];
            let close = after
                .find(')')
                .expect("unclosed by (...) in alerts-v1.yaml");
            let group_labels = &after[..close];
            for label in group_labels
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                assert!(
                    expr_metrics
                        .iter()
                        .all(|m| allowed_metrics[m].contains_key(label)),
                    "alerts-v1.yaml groups by undeclared label {label:?} on {expr_metrics:?}"
                );
            }
            rest = &after[close + 1..];
        }
    }
    assert!(
        found_metrics.len() >= 5,
        "expected alerts covering HTTP, DB readiness, telemetry drops, provider transport and quota drift; got {found_metrics:?}"
    );
    assert!(
        found_metrics.contains("openmettle_storage_quota_drift_total"),
        "expected alert covering openmettle_storage_quota_drift_total; got {found_metrics:?}"
    );
}
