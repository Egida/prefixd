mod audit;
pub mod metrics;

pub use audit::*;
pub use metrics::*;

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::LogFormat;

fn log_filter(level: &str, environment: Option<EnvFilter>) -> EnvFilter {
    environment.unwrap_or_else(|| {
        // Preserve the existing ERROR fallback for empty or invalid config.
        let configured = EnvFilter::new(level);
        EnvFilter::new(format!("sqlx::postgres::notice=warn,{configured}"))
    })
}

pub fn init_tracing(format: LogFormat, level: &str) {
    let filter = log_filter(level, EnvFilter::try_from_default_env().ok());

    match format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().pretty())
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_filter_preserves_levels_and_operator_overrides() {
        for (configured, environment, expected) in [
            ("info", None, [false, true, true, true, true]),
            (
                "info,sqlx::postgres::notice=info",
                None,
                [true, true, true, true, true],
            ),
            ("error", Some("info"), [true, true, true, true, true]),
            ("", None, [false, true, true, false, true]),
            ("[", None, [false, true, true, false, true]),
        ] {
            let filter = log_filter(
                configured,
                environment.map(|value| EnvFilter::try_new(value).unwrap()),
            );
            let enabled = tracing::subscriber::with_default(
                tracing_subscriber::registry().with(filter),
                || {
                    [
                        tracing::enabled!(target: "sqlx::postgres::notice", tracing::Level::INFO),
                        tracing::enabled!(target: "sqlx::postgres::notice", tracing::Level::WARN),
                        tracing::enabled!(target: "sqlx::postgres::notice", tracing::Level::ERROR),
                        tracing::enabled!(target: "prefixd", tracing::Level::INFO),
                        tracing::enabled!(target: "prefixd", tracing::Level::ERROR),
                    ]
                },
            );
            assert_eq!(
                enabled, expected,
                "config={configured:?}, RUST_LOG={environment:?}"
            );
        }
    }

    #[test]
    fn configured_span_and_field_filters_survive_notice_default() {
        for (configured, other_span_enabled) in [
            ("info,prefixd[notice_probe]=debug", true),
            ("info,prefixd[notice_probe{kind=attack.*}]=debug", false),
        ] {
            tracing::subscriber::with_default(
                tracing_subscriber::registry().with(log_filter(configured, None)),
                || {
                    assert!(!tracing::enabled!(target: "prefixd", tracing::Level::DEBUG));
                    for (kind, expected) in [("normal", other_span_enabled), ("attack-42", true)] {
                        let span = tracing::info_span!(target: "prefixd", "notice_probe", kind);
                        let _entered = span.enter();
                        assert_eq!(
                            tracing::enabled!(target: "prefixd", tracing::Level::DEBUG),
                            expected,
                            "config={configured:?}, kind={kind}"
                        );
                    }
                },
            );
        }
    }
}
