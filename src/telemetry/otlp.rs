//! OTLP/HTTP protobuf trace and metrics export (ADRs 0026, 0028), off by default.
//!
//! Configured only through `OTLP_TRACES_ENDPOINT` and/or `OTLP_METRICS_ENDPOINT` (with optional
//! `OTLP_CA_FILE` and `OTLP_PRIVATE_RANGES`) under the API's or worker's prefix. Unset, none of
//! this module runs: no tracer provider, export task, DNS slot or socket exists.
//!
//! When trace export is configured, [`SpanGuard`](super::SpanGuard) admits only this crate's
//! request span, so the SDK sees nothing else. Ended spans are offered to a bounded queue without
//! waiting ([`Processor`]); one Tokio task batches them, encodes `ExportTraceServiceRequest` and
//! POSTs each batch over the ADR 0010 transport core ([`Route`]). When metrics export is
//! configured, one Tokio task periodically snapshots the fixed-cardinality [`Metrics`] registry,
//! encodes `ExportMetricsServiceRequest` and POSTs it over the same [`Route`] and DNS slots.
//! Failures drop without retry and emit one `telemetry.dropped` event to stderr per cycle.
use super::{
    Process, RequestId, TARGET, metric_exports_dropped,
    metrics::{DroppedSignal, MetricsSource},
    spans_dropped,
};
use crate::provider_http::{
    MAX_PRIVATE_RANGES, MAX_RESPONSE_HEADER_BYTES, MAX_RESPONSE_HEADERS, MAX_TRUST_BUNDLE_BYTES,
    Trust,
    transport::{self, Endpoint, Limits, Lookup, Range, Route},
};
use openidconnect::http::{self, HeaderMap, HeaderValue, header};
use opentelemetry::{InstrumentationScope, KeyValue, trace::TracerProvider as _};
use opentelemetry_proto::{
    tonic::collector::trace::v1::ExportTraceServiceRequest,
    transform::{
        common::tonic::ResourceAttributesWithSchema,
        trace::tonic::group_spans_by_resource_and_scope,
    },
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    trace::{Sampler, SdkTracer, SdkTracerProvider, Span, SpanData, SpanLimits, SpanProcessor},
};
use prost::Message;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, Semaphore, mpsc},
    task::JoinHandle,
    time::Instant,
};

/// Ended spans held while the exporter is behind.
pub const QUEUE_CAPACITY: usize = 2048;
/// Spans per request.
pub const MAX_BATCH: usize = 512;
/// The longest a span waits for a batch to fill, and the metrics snapshot export period.
pub const EXPORT_INTERVAL: Duration = Duration::from_secs(5);
/// One export, from DNS queueing to the end of the response.
pub const EXPORT_DEADLINE: Duration = Duration::from_secs(3);
/// Encoded request ceiling; a larger batch is dropped before any DNS work.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Response body ceiling. The body is read only to complete the exchange; it is not decoded.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Outstanding operating-system lookups for the exporter, separate from the provider pool.
pub const DNS_LOOKUP_SLOTS: usize = 2;

/// Validated export settings. Nothing is read from disk until [`Destination::load`].
#[derive(Clone)]
pub struct Settings {
    traces: Option<Endpoint>,
    metrics: Option<Endpoint>,
    allowed: Vec<Range>,
    ca_file: Option<PathBuf>,
}

impl Settings {
    /// Reads `OTLP_TRACES_ENDPOINT`, `OTLP_METRICS_ENDPOINT`, `OTLP_CA_FILE` and
    /// `OTLP_PRIVATE_RANGES`, always all four and in that order. When neither endpoint is set,
    /// export is off and the other two are refused so a CA or range is never silently ignored.
    /// Errors name the key, never the value.
    pub fn parse(
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Option<Self>, &'static str> {
        let traces = get("OTLP_TRACES_ENDPOINT")?;
        let metrics = get("OTLP_METRICS_ENDPOINT")?;
        let ca_file = get("OTLP_CA_FILE")?;
        let ranges = get("OTLP_PRIVATE_RANGES")?;
        if traces.is_none() && metrics.is_none() {
            if ca_file.is_some() {
                return Err("invalid OTLP_CA_FILE");
            }
            if ranges.is_some() {
                return Err("invalid OTLP_PRIVATE_RANGES");
            }
            return Ok(None);
        }
        let traces = traces
            .map(|url| transport::endpoint(&url).map_err(|_| "invalid OTLP_TRACES_ENDPOINT"))
            .transpose()?;
        let metrics = metrics
            .map(|url| transport::endpoint(&url).map_err(|_| "invalid OTLP_METRICS_ENDPOINT"))
            .transpose()?;
        let ca_file = ca_file.map(PathBuf::from);
        if ca_file.as_deref().is_some_and(|path| !path.is_absolute()) {
            return Err("invalid OTLP_CA_FILE");
        }
        let allowed = match ranges {
            None => Vec::new(),
            Some(text) => {
                let items: Vec<&str> = text.split(',').collect();
                if items.len() > MAX_PRIVATE_RANGES {
                    return Err("invalid OTLP_PRIVATE_RANGES");
                }
                let mut allowed = Vec::with_capacity(items.len());
                for item in items {
                    let range = transport::private_range(item)
                        .map_err(|_| "invalid OTLP_PRIVATE_RANGES")?;
                    if allowed.contains(&range) {
                        return Err("invalid OTLP_PRIVATE_RANGES");
                    }
                    allowed.push(range);
                }
                allowed
            }
        };
        Ok(Some(Self {
            traces,
            metrics,
            allowed,
            ca_file,
        }))
    }
}

/// Bounds of the queue, batching and each export. Production uses [`TUNING`]; tests shorten
/// them.
#[derive(Clone, Copy)]
pub(crate) struct Tuning {
    pub(crate) queue: usize,
    pub(crate) batch: usize,
    pub(crate) interval: Duration,
    pub(crate) deadline: Duration,
    pub(crate) request_body: usize,
}

const TUNING: Tuning = Tuning {
    queue: QUEUE_CAPACITY,
    batch: MAX_BATCH,
    interval: EXPORT_INTERVAL,
    deadline: EXPORT_DEADLINE,
    request_body: MAX_REQUEST_BYTES,
};

/// A loaded destination: configured endpoints, address allowlist, TLS trust and DNS slots.
pub struct Destination {
    traces: Option<Endpoint>,
    metrics: Option<Endpoint>,
    allowed: Vec<Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: Lookup,
    pub(crate) slots: Arc<Semaphore>,
    tuning: Tuning,
    #[cfg(test)]
    loopback: bool,
}

impl Destination {
    /// Reads the CA file, if any (a regular file of at most 1 MiB, PEM certificates only), or
    /// the platform roots, and builds the TLS client. Errors are fixed lines naming the key.
    pub fn load(settings: &Settings) -> Result<Self, &'static str> {
        let (trust, refusal) = match &settings.ca_file {
            Some(path) => {
                let pem = crate::auth_config::read_bounded(path, MAX_TRUST_BUNDLE_BYTES)
                    .ok_or("invalid OTLP_CA_FILE")?;
                (Some(pem), "invalid OTLP_CA_FILE")
            }
            None => (None, "OTLP trust roots unavailable"),
        };
        let roots = match &trust {
            Some(pem) => transport::roots(Trust::Bundle(pem)),
            None => transport::roots(Trust::Native),
        }
        .map_err(|_| refusal)?;
        let tls = transport::client_config(roots).map_err(|_| refusal)?;
        Ok(Self {
            traces: settings.traces.clone(),
            metrics: settings.metrics.clone(),
            allowed: settings.allowed.clone(),
            tls,
            lookup: Arc::new(transport::system_lookup),
            slots: Arc::new(Semaphore::new(DNS_LOOKUP_SLOTS)),
            tuning: TUNING,
            #[cfg(test)]
            loopback: false,
        })
    }
}

/// Test seams; production construction is [`Destination::load`] only.
#[cfg(test)]
impl Destination {
    pub(crate) fn with_lookup(
        mut self,
        lookup: impl Fn(&str, u16) -> std::io::Result<Vec<std::net::SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.lookup = Arc::new(lookup);
        self
    }
    pub(crate) fn with_tuning(mut self, tuning: Tuning) -> Self {
        self.tuning = tuning;
        self
    }
    /// Permits 127.0.0.1 and ::1 only, for the in-process TLS collector.
    pub(crate) fn allow_loopback_fixture(mut self) -> Self {
        self.loopback = true;
        self
    }
}

/// State shared by the processor and the export task.
#[derive(Debug, Default)]
struct Shared {
    /// Spans refused by a full queue or lost with a failed batch, not yet reported.
    dropped: AtomicU64,
    stop: Notify,
}

/// Offers each ended span to the queue and never waits.
#[derive(Debug)]
struct Processor {
    queue: mpsc::Sender<SpanData>,
    shared: Arc<Shared>,
}

impl SpanProcessor for Processor {
    fn on_start(&self, _: &mut Span, _: &opentelemetry::Context) {}
    fn on_end(&self, span: SpanData) {
        if self.queue.try_send(span).is_err() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }
    /// Signals the task to send what is queued and stop; the caller bounds the wait.
    fn shutdown_with_timeout(&self, _: Duration) -> OTelSdkResult {
        self.shared.stop.notify_one();
        Ok(())
    }
}

/// Shared transport settings held by whichever OTLP export tasks are active.
struct SharedTransport {
    allowed: Vec<Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: Lookup,
    slots: Arc<Semaphore>,
    tuning: Tuning,
    #[cfg(test)]
    loopback: bool,
}

/// The running OTLP exporter(s), kept by the process to stop them within the shutdown deadline.
pub struct Exporter {
    traces: Option<(SdkTracerProvider, JoinHandle<()>)>,
    metrics: Option<(Arc<Notify>, JoinHandle<()>)>,
}

impl Exporter {
    /// Stops accepting spans and signals the metrics task, lets active exporters finish until
    /// `deadline`, then aborts any remaining task (closing its socket).
    pub async fn stop(mut self, deadline: Instant) {
        if let Some((provider, _)) = &self.traces {
            let _ = provider.shutdown();
        }
        if let Some((stop, _)) = &self.metrics {
            stop.notify_one();
        }
        let mut trace_task = self.traces.as_mut().map(|(_, task)| task);
        let mut metric_task = self.metrics.as_mut().map(|(_, task)| task);
        let drain = async {
            let t = async {
                if let Some(task) = trace_task.as_deref_mut() {
                    let _ = task.await;
                }
            };
            let m = async {
                if let Some(task) = metric_task.as_deref_mut() {
                    let _ = task.await;
                }
            };
            tokio::join!(t, m);
        };
        if tokio::time::timeout_at(deadline, drain).await.is_err() {
            if let Some(task) = trace_task {
                task.abort();
            }
            if let Some(task) = metric_task {
                task.abort();
            }
        }
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        if let Some((_, task)) = &self.traces {
            task.abort();
        }
        if let Some((_, task)) = &self.metrics {
            task.abort();
        }
    }
}

/// Starts whichever OTLP export tasks `destination` configured on the current Tokio runtime.
/// Sampling, limits and resource are explicit, so ambient `OTEL_*` variables have no effect.
pub fn start(destination: Destination, role: Process) -> (Option<SdkTracer>, Exporter) {
    start_inner(
        destination,
        role,
        MetricsSource::Global(super::metrics::global()),
    )
}

#[cfg(test)]
pub(crate) fn start_with_metrics(
    destination: Destination,
    role: Process,
    metrics: Arc<super::metrics::Metrics>,
) -> (Option<SdkTracer>, Exporter) {
    start_inner(destination, role, MetricsSource::Owned(metrics))
}

fn start_inner(
    destination: Destination,
    role: Process,
    metrics: MetricsSource,
) -> (Option<SdkTracer>, Exporter) {
    let Destination {
        traces: trace_endpoint,
        metrics: metric_endpoint,
        allowed,
        tls,
        lookup,
        slots,
        tuning,
        #[cfg(test)]
        loopback,
    } = destination;
    let transport = Arc::new(SharedTransport {
        allowed,
        tls,
        lookup,
        slots,
        tuning,
        #[cfg(test)]
        loopback,
    });
    // Per-process random UUIDv4 so replicas produce distinct Prometheus `instance` streams
    // without disclosing any host, pod, user or scope identity.
    let instance_id = RequestId::generate().map(|id| id.to_string());
    let (tracer, traces) = match trace_endpoint {
        Some(endpoint) => {
            let (queue, spans) = mpsc::channel(transport.tuning.queue);
            let shared = Arc::new(Shared::default());
            let mut builder = Resource::builder_empty()
                .with_service_name(format!("openmettle-{}", role.as_str()));
            if let Some(id) = &instance_id {
                builder = builder.with_attribute(KeyValue::new("service.instance.id", id.clone()));
            }
            let resource = builder.build();
            let attributes = ResourceAttributesWithSchema::from(&resource);
            let limits = SpanLimits {
                max_attributes_per_span: 8,
                max_events_per_span: 0,
                max_links_per_span: 0,
                max_attributes_per_event: 0,
                max_attributes_per_link: 0,
            };
            let provider = SdkTracerProvider::builder()
                .with_sampler(Sampler::AlwaysOn)
                .with_span_limits(limits)
                .with_resource(resource)
                .with_span_processor(Processor {
                    queue,
                    shared: shared.clone(),
                })
                .build();
            let tracer = provider.tracer_with_scope(InstrumentationScope::builder(TARGET).build());
            let task = tokio::spawn(export_traces(
                spans,
                shared,
                metrics.clone(),
                transport.clone(),
                endpoint,
                attributes,
            ));
            (Some(tracer), Some((provider, task)))
        }
        None => (None, None),
    };
    let metrics = metric_endpoint.map(|endpoint| {
        let stop = Arc::new(Notify::new());
        let task = tokio::spawn(export_metrics(
            metrics,
            role,
            instance_id,
            stop.clone(),
            transport,
            endpoint,
        ));
        (stop, task)
    });
    (tracer, Exporter { traces, metrics })
}

/// The trace export task: one batch in flight at a time.
async fn export_traces(
    mut spans: mpsc::Receiver<SpanData>,
    shared: Arc<Shared>,
    metrics: MetricsSource,
    transport: Arc<SharedTransport>,
    endpoint: Endpoint,
    resource: ResourceAttributesWithSchema,
) {
    let tuning = transport.tuning;
    let mut batch = Vec::with_capacity(tuning.batch);
    loop {
        let wake = Instant::now() + tuning.interval;
        let stopping = loop {
            let room = tuning.batch - batch.len();
            tokio::select! {
                biased;
                () = shared.stop.notified() => break true,
                received = spans.recv_many(&mut batch, room) => {
                    if received == 0 {
                        break true;
                    }
                    if batch.len() >= tuning.batch {
                        break false;
                    }
                }
                () = tokio::time::sleep_until(wake) => break false,
            }
        };
        if stopping {
            spans.close();
            loop {
                while batch.len() < tuning.batch {
                    match spans.try_recv() {
                        Ok(span) => batch.push(span),
                        Err(_) => break,
                    }
                }
                if batch.is_empty() {
                    break;
                }
                send_spans(
                    &transport,
                    &endpoint,
                    &resource,
                    &shared,
                    std::mem::take(&mut batch),
                )
                .await;
            }
            report(&shared, &metrics);
            return;
        }
        if !batch.is_empty() {
            send_spans(
                &transport,
                &endpoint,
                &resource,
                &shared,
                std::mem::take(&mut batch),
            )
            .await;
        }
        report(&shared, &metrics);
    }
}

/// Periodic cumulative metrics export task: one snapshot in flight at a time.
async fn export_metrics(
    metrics: MetricsSource,
    role: Process,
    instance_id: Option<String>,
    stop: Arc<Notify>,
    transport: Arc<SharedTransport>,
    endpoint: Endpoint,
) {
    let interval = transport.tuning.interval;
    loop {
        let stopping = tokio::select! {
            biased;
            () = stop.notified() => true,
            () = tokio::time::sleep(interval) => false,
        };
        send_metrics(
            &transport,
            &endpoint,
            metrics.as_ref(),
            role,
            instance_id.as_deref(),
        )
        .await;
        if stopping {
            return;
        }
    }
}

async fn send_metrics(
    transport: &SharedTransport,
    endpoint: &Endpoint,
    metrics: &super::metrics::Metrics,
    role: Process,
    instance_id: Option<&str>,
) {
    let Some(request) = metrics.encode_otlp(role, instance_id) else {
        return;
    };
    if !post(transport, endpoint, request.encode_to_vec()).await {
        metrics.record_dropped(DroppedSignal::MetricExports, 1);
        metric_exports_dropped(1);
    }
}

/// At most one `telemetry.dropped` event per cycle, to stderr only.
fn report(shared: &Shared, metrics: &MetricsSource) {
    let dropped = shared.dropped.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        metrics
            .as_ref()
            .record_dropped(DroppedSignal::TraceSpans, dropped);
        spans_dropped(dropped);
    }
}

/// Exports one trace batch; any failure drops the whole batch and counts its spans.
async fn send_spans(
    transport: &SharedTransport,
    endpoint: &Endpoint,
    resource: &ResourceAttributesWithSchema,
    shared: &Shared,
    batch: Vec<SpanData>,
) {
    let count = batch.len() as u64;
    let request = ExportTraceServiceRequest {
        resource_spans: group_spans_by_resource_and_scope(batch, resource),
    };
    if !post(transport, endpoint, request.encode_to_vec()).await {
        shared.dropped.fetch_add(count, Ordering::Relaxed);
    }
}

/// One POST over the shared transport core: no retry, redirect, proxy or extra header. Only
/// a 2xx answer counts as delivered; a partial-success body is not decoded.
async fn post(transport: &SharedTransport, endpoint: &Endpoint, body: Vec<u8>) -> bool {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    let route = Route {
        endpoint,
        allowed: &transport.allowed,
        tls: Some(&transport.tls),
        lookup: &transport.lookup,
        slots: &transport.slots,
        #[cfg(test)]
        loopback: transport.loopback,
    };
    let limits = Limits {
        request_body: transport.tuning.request_body,
        response_body: MAX_RESPONSE_BYTES,
        response_headers: MAX_RESPONSE_HEADERS,
        response_header_bytes: MAX_RESPONSE_HEADER_BYTES,
        setup: transport.tuning.deadline,
        total: transport.tuning.deadline,
    };
    matches!(
        route.send(http::Method::POST, &headers, body, &limits).await,
        Ok(response) if response.status().is_success()
    )
}
