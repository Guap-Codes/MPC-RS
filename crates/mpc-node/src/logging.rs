//! # Logging and Observability Initialization
//!
//! This module configures the application's logging and tracing infrastructure.
//! It supports structured JSON logging to standard output and optional
//! export of distributed traces to an OpenTelemetry (OTLP) collector.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initializes the global tracing subscriber for the MPC node.
///
/// # Arguments
///
/// * `log_level` - The default log level (e.g., "info", "debug") if not
///   specified by the `RUST_LOG` environment variable.
/// * `otlp_endpoint` - An optional gRPC endpoint for an OpenTelemetry
///   collector (e.g., "http://localhost:4317"). If provided, traces will
///   be exported to this endpoint.
///
/// # Note
///
/// This function configures JSON-formatted logs with current span and
/// span list context, which is ideal for ingestion by log aggregators
/// like Datadog, ELK, or Grafana Loki.
pub fn init_logging(log_level: &str, otlp_endpoint: Option<&str>) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true);

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer);

    if let Some(endpoint) = otlp_endpoint {
        use opentelemetry_otlp::{SpanExporter, WithExportConfig};
        use opentelemetry_sdk::trace::SdkTracerProvider;
        use opentelemetry_sdk::Resource;
        use opentelemetry::global;

        let exporter = SpanExporter::builder()
            .with_tonic() // Requires the "grpc-tonic" feature in opentelemetry-otlp
            .with_endpoint(endpoint)
            .build()
            .expect("Failed to build OTLP span exporter");

        let resource = Resource::builder_empty()
            .with_attributes(vec![opentelemetry::KeyValue::new(
                "service.name",
                "mpc-node",
            )])
            .build();

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        global::set_tracer_provider(tracer_provider);

        let otlp_layer = tracing_opentelemetry::layer();
        subscriber.with(otlp_layer).init();
    } else {
        subscriber.init();
    }

    tracing::info!("Logging initialised");
}

