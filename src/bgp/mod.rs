mod announcer;
mod gobgp;
mod mock;
mod proto;
#[cfg(feature = "bgp-rustbgpd")]
mod rustbgpd_proto;

pub use announcer::*;
pub use gobgp::*;
pub use mock::*;
pub use proto::apipb;
#[cfg(feature = "bgp-rustbgpd")]
pub use rustbgpd_proto::rustbgpd_pb;

#[cfg(feature = "bgp-rustbgpd")]
mod rustbgpd;
#[cfg(feature = "bgp-rustbgpd")]
pub use rustbgpd::RustBgpdAnnouncer;

pub async fn speaker_factory(
    config: &crate::config::BgpConfig,
) -> anyhow::Result<std::sync::Arc<dyn FlowSpecAnnouncer>> {
    use crate::config::BgpMode;
    tracing::info!(mode = ?config.mode, "selecting BGP speaker");
    Ok(match config.mode {
        BgpMode::Mock => std::sync::Arc::new(MockAnnouncer::new()),
        BgpMode::Sidecar | BgpMode::Gobgp => {
            anyhow::ensure!(!config.gobgp_grpc.is_empty(), "bgp.gobgp_grpc is required");
            let mut speaker = GoBgpAnnouncer::new(config.gobgp_grpc.clone());
            speaker.connect().await?;
            std::sync::Arc::new(speaker)
        }
        BgpMode::Rustbgpd => {
            #[cfg(feature = "bgp-rustbgpd")]
            {
                std::sync::Arc::new(
                    RustBgpdAnnouncer::connect(
                        config
                            .rustbgpd
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("bgp.rustbgpd is required"))?,
                    )
                    .await?,
                )
            }
            #[cfg(not(feature = "bgp-rustbgpd"))]
            {
                anyhow::bail!("rustbgpd backend requires the bgp-rustbgpd feature")
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn factory_selects_mock_and_rejects_unavailable_backends() {
        let mut config: crate::config::BgpConfig =
            serde_yaml::from_str("mode: mock\nlocal_asn: 65010\nrouter_id: 192.0.2.1").unwrap();
        assert!(
            speaker_factory(&config)
                .await
                .unwrap()
                .reader()
                .unwrap()
                .list_active()
                .await
                .unwrap()
                .is_empty()
        );
        config.mode = crate::config::BgpMode::Gobgp;
        assert!(speaker_factory(&config).await.is_err());
        config.mode = crate::config::BgpMode::Rustbgpd;
        let error = speaker_factory(&config).await.err().unwrap().to_string();
        #[cfg(feature = "bgp-rustbgpd")]
        assert!(error.contains("bgp.rustbgpd is required"));
        #[cfg(not(feature = "bgp-rustbgpd"))]
        assert!(error.contains("bgp-rustbgpd feature"));
    }
}
