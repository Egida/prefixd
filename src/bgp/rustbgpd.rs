use super::{FlowSpecAnnouncer, PeerStatus, SessionState, rustbgpd_pb as pb};
use crate::{
    config::RustBgpdConfig,
    domain::{ActionType, FlowSpecAction, FlowSpecNlri, FlowSpecRule},
    error::{PrefixdError, Result},
};
use async_trait::async_trait;
use std::{future::Future, time::Duration};
use tonic::{
    Code, Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

pub struct RustBgpdAnnouncer {
    channel: Channel,
    token: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
}

fn invalid(message: &str) -> PrefixdError {
    PrefixdError::Internal(format!("rustbgpd: {message}"))
}

impl RustBgpdAnnouncer {
    pub async fn connect(config: &RustBgpdConfig) -> anyhow::Result<Self> {
        let token = std::env::var(&config.bearer_token_env).map_err(|_| {
            anyhow::anyhow!("rustbgpd bearer token environment variable is missing")
        })?;
        Self::connect_with_token(config, &token).await
    }

    async fn connect_with_token(config: &RustBgpdConfig, token: &str) -> anyhow::Result<Self> {
        // Other HTTP dependencies can enable both Rustls providers.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let uri: tonic::codegen::http::Uri = config.endpoint.parse()?;
        anyhow::ensure!(
            uri.authority().is_some() && uri.authority().unwrap().as_str().find('@').is_none(),
            "invalid rustbgpd endpoint"
        );
        let mut endpoint = Endpoint::from_shared(config.endpoint.clone())?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        match uri.scheme_str() {
            Some("http") => {
                let host = uri
                    .host()
                    .unwrap_or_default()
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                anyhow::ensure!(
                    host.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback()),
                    "plaintext rustbgpd requires a literal loopback address"
                );
            }
            Some("https") => {
                let mut tls = ClientTlsConfig::new().with_native_roots();
                if let Some(path) = &config.ca_cert_path {
                    tls = tls.ca_certificate(Certificate::from_pem(tokio::fs::read(path).await?));
                }
                endpoint = endpoint.tls_config(tls)?;
            }
            _ => anyhow::bail!("rustbgpd endpoint must use http or https"),
        }
        anyhow::ensure!(
            !token.is_empty() && !token.chars().any(char::is_whitespace),
            "rustbgpd bearer token must not be empty or contain whitespace"
        );
        let mut token: tonic::metadata::MetadataValue<_> = format!("Bearer {token}")
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid rustbgpd bearer token"))?;
        token.set_sensitive(true);
        Ok(Self {
            channel: endpoint.connect().await?,
            token,
        })
    }

    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request.set_timeout(Duration::from_secs(30));
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        request
    }

    async fn rpc<T, F, Fut>(&self, operation: &str, mut call: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    {
        for attempt in 0..3 {
            let result = tokio::time::timeout(Duration::from_secs(30), call())
                .await
                .unwrap_or_else(|_| Err(tonic::Status::deadline_exceeded("RPC deadline elapsed")));
            match result {
                Ok(value) => return Ok(value.into_inner()),
                Err(status)
                    if attempt < 2
                        && matches!(status.code(), Code::Unavailable | Code::DeadlineExceeded) =>
                {
                    tracing::warn!(operation, attempt = attempt + 1, code = ?status.code(), "retrying rustbgpd RPC");
                    tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
                }
                Err(status) => {
                    return Err(invalid(&format!(
                        "{operation} RPC failed: {:?}",
                        status.code()
                    )));
                }
            }
        }
        unreachable!()
    }
}

fn encode_match(nlri: &FlowSpecNlri) -> Result<(i32, Vec<pb::FlowSpecComponent>)> {
    let prefix: ipnet::IpNet = nlri
        .dst_prefix
        .parse()
        .map_err(|_| invalid("invalid destination prefix"))?;
    if prefix != prefix.trunc() {
        return Err(invalid("destination prefix has host bits"));
    }
    let mut components = vec![pb::FlowSpecComponent {
        r#type: 1,
        prefix: prefix.to_string(),
        ..Default::default()
    }];
    if let Some(protocol) = nlri.protocol {
        components.push(pb::FlowSpecComponent {
            r#type: 3,
            value: format!("={protocol}"),
            ..Default::default()
        });
    }
    let mut ports = nlri.dst_ports.clone();
    if ports.len() > 8 {
        return Err(invalid("at most eight destination ports are supported"));
    }
    ports.sort_unstable();
    if !ports.is_empty() {
        components.push(pb::FlowSpecComponent {
            r#type: 5,
            value: ports
                .iter()
                .map(|port| format!("={port}"))
                .collect::<Vec<_>>()
                .join(", "),
            ..Default::default()
        });
    }
    let family = if prefix.addr().is_ipv4() {
        pb::AddressFamily::Ipv4Flowspec
    } else {
        pb::AddressFamily::Ipv6Flowspec
    };
    Ok((family as i32, components))
}

fn encode(rule: &FlowSpecRule) -> Result<pb::AddFlowSpecRequest> {
    let (afi_safi, components) = encode_match(&rule.nlri)?;
    if rule.actions.len() != 1 {
        return Err(invalid("exactly one traffic rate action is required"));
    }
    let action = &rule.actions[0];
    let rate = match action.action_type {
        ActionType::Discard if action.rate_bps.is_none() => 0.0,
        ActionType::Police => {
            let bps = action
                .rate_bps
                .filter(|bps| *bps > 0)
                .ok_or_else(|| invalid("police requires a positive rate"))?;
            let rate = (bps as f64 / 8.0) as f32;
            if rate as f64 * 8.0 >= u64::MAX as f64 || (rate as f64 * 8.0) as u64 != bps {
                return Err(invalid("police rate cannot be represented exactly"));
            }
            rate
        }
        _ => return Err(invalid("unsupported traffic action")),
    };
    Ok(pb::AddFlowSpecRequest {
        afi_safi,
        components,
        actions: vec![pb::FlowSpecAction {
            action: Some(pb::flow_spec_action::Action::TrafficRate(
                pb::FlowSpecTrafficRate { rate },
            )),
        }],
        ..Default::default()
    })
}

fn numbers(value: &str) -> Result<Vec<u16>> {
    value
        .split(',')
        .map(|part| {
            let part = part.trim();
            part.strip_prefix("==")
                .or_else(|| part.strip_prefix('='))
                .ok_or_else(|| invalid("unsupported numeric expression"))?
                .parse()
                .map_err(|_| invalid("invalid numeric value"))
        })
        .collect()
}

fn decode(route: pb::FlowSpecRouteEntry, family: i32) -> Result<FlowSpecRule> {
    if route.peer_address != "0.0.0.0"
        || route.afi_safi != family
        || !route.communities.is_empty()
        || !route.as_path.is_empty()
    {
        return Err(invalid("unsupported local route attributes"));
    }
    let mut nlri = FlowSpecNlri {
        dst_prefix: String::new(),
        protocol: None,
        dst_ports: vec![],
    };
    let mut previous = 0;
    for component in &route.components {
        if component.r#type <= previous || component.offset != 0 {
            return Err(invalid("invalid component order or offset"));
        }
        previous = component.r#type;
        match component.r#type {
            1 if component.value.is_empty() => {
                let prefix: ipnet::IpNet = component
                    .prefix
                    .parse()
                    .map_err(|_| invalid("invalid destination prefix"))?;
                if prefix != prefix.trunc() || (prefix.addr().is_ipv4() != (family == 3)) {
                    return Err(invalid("invalid prefix family or host bits"));
                }
                nlri.dst_prefix = prefix.to_string();
            }
            3 if component.prefix.is_empty() => {
                let values = numbers(&component.value)?;
                if values.len() != 1 || values[0] > 255 {
                    return Err(invalid("unsupported protocol"));
                }
                nlri.protocol = Some(values[0] as u8);
            }
            5 if component.prefix.is_empty() => {
                nlri.dst_ports = numbers(&component.value)?;
                nlri.dst_ports.sort_unstable();
            }
            _ => return Err(invalid("unsupported component")),
        }
    }
    if nlri.dst_prefix.is_empty() || route.actions.len() != 1 {
        return Err(invalid("missing destination or unsupported actions"));
    }
    let Some(pb::flow_spec_action::Action::TrafficRate(rate)) = &route.actions[0].action else {
        return Err(invalid("unsupported action"));
    };
    let bps = rate.rate as f64 * 8.0;
    if !bps.is_finite() || bps < 0.0 || bps >= u64::MAX as f64 || bps.fract() != 0.0 {
        return Err(invalid("invalid traffic rate"));
    }
    // rustbgpd exposes each traffic-rate both as a typed action and a raw EC.
    let expected_ec = (0x8006_u64 << 48) | u64::from(rate.rate.to_bits());
    if route.extended_communities.as_slice() != [expected_ec] {
        return Err(invalid("unsupported or inconsistent extended communities"));
    }
    let action = if bps == 0.0 {
        FlowSpecAction::discard()
    } else {
        FlowSpecAction::police(bps as u64)
    };
    let rule = FlowSpecRule::new(nlri, action);
    encode(&rule)?;
    Ok(rule)
}

#[async_trait]
impl FlowSpecAnnouncer for RustBgpdAnnouncer {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        let payload = encode(rule)?;
        let response = self
            .rpc("AddFlowSpec", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .add_flow_spec(self.request(payload.clone()))
                    .await
            })
            .await?;
        match pb::FlowSpecInjectOutcome::try_from(response.outcome) {
            Ok(
                pb::FlowSpecInjectOutcome::Created
                | pb::FlowSpecInjectOutcome::Replaced
                | pb::FlowSpecInjectOutcome::Unchanged,
            ) => {
                tracing::debug!(outcome = response.outcome, "rustbgpd injection accepted");
                Ok(())
            }
            _ => Err(invalid("unsupported rustbgpd injection outcome")),
        }
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let (afi_safi, components) = encode_match(&rule.nlri)?;
        let payload = pb::DeleteFlowSpecRequest {
            afi_safi,
            components,
            allow_missing: true,
        };
        let response = self
            .rpc("DeleteFlowSpec", || {
                let mut client =
                    pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
                let request = self.request(payload.clone());
                async move {
                    match client.delete_flow_spec(request).await {
                        Err(status) if status.code() == Code::NotFound => {
                            Ok(tonic::Response::new(pb::DeleteFlowSpecResponse {
                                outcome: 2,
                            }))
                        }
                        result => result,
                    }
                }
            })
            .await?;
        match pb::FlowSpecDeleteOutcome::try_from(response.outcome) {
            Ok(pb::FlowSpecDeleteOutcome::Deleted | pb::FlowSpecDeleteOutcome::NotPresent) => {
                tracing::debug!(outcome = response.outcome, "rustbgpd withdrawal accepted");
                Ok(())
            }
            _ => Err(invalid("unsupported rustbgpd deletion outcome")),
        }
    }
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        let mut rules = vec![];
        for family in [3, 4] {
            let response = self
                .rpc("ListFlowSpecRoutes", || async {
                    pb::rib_service_client::RibServiceClient::new(self.channel.clone())
                        .list_flow_spec_routes(self.request(pb::ListFlowSpecRequest {
                            afi_safi: family,
                            received_peer_address: "0.0.0.0".into(),
                            advertised_peer_address: String::new(),
                        }))
                        .await
                })
                .await?;
            if !response.received_view || response.advertised_view || !response.routes.is_empty() {
                return Err(invalid("rustbgpd did not acknowledge local intent view"));
            }
            for row in response.received_routes {
                if !matches!(row.validation, 1 | 3) || row.path_id != 0 || !row.reason.is_empty() {
                    return Err(invalid("invalid local intent row"));
                }
                rules.push(decode(
                    row.route.ok_or_else(|| invalid("missing local route"))?,
                    family,
                )?);
            }
        }
        Ok(rules)
    }
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        let response = self
            .rpc("ListNeighbors", || async {
                pb::neighbor_service_client::NeighborServiceClient::new(self.channel.clone())
                    .list_neighbors(self.request(pb::ListNeighborsRequest {}))
                    .await
            })
            .await?;
        response
            .neighbors
            .into_iter()
            .map(|peer| {
                if peer.stale {
                    return Err(invalid("stale rustbgpd peer state"));
                }
                let config = peer
                    .config
                    .ok_or_else(|| invalid("missing peer configuration"))?;
                config
                    .address
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| invalid("invalid peer address"))?;
                let state = match peer.state {
                    1 => SessionState::Idle,
                    2 => SessionState::Connect,
                    3 => SessionState::Active,
                    4 => SessionState::OpenSent,
                    5 => SessionState::OpenConfirm,
                    6 => SessionState::Established,
                    _ => return Err(invalid("unknown peer state")),
                };
                Ok(PeerStatus {
                    name: if config.description.is_empty() {
                        config.address.clone()
                    } else {
                        config.description
                    },
                    address: config.address,
                    state,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_roundtrip_and_rejects_lossy_values() {
        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                protocol: Some(6),
                dst_ports: vec![443, 80],
            },
            FlowSpecAction::police(8000),
        );
        let encoded = encode(&rule).unwrap();
        assert_eq!(
            encoded
                .components
                .iter()
                .map(|c| c.r#type)
                .collect::<Vec<_>>(),
            [1, 3, 5]
        );
        assert_eq!(encoded.components[2].value, "=80, =443");
        let mut route = pb::FlowSpecRouteEntry {
            components: encoded.components,
            actions: encoded.actions,
            peer_address: "0.0.0.0".into(),
            afi_safi: 3,
            extended_communities: vec![(0x8006_u64 << 48) | u64::from(1000.0_f32.to_bits())],
            ..Default::default()
        };
        route.components[2].value = "==80, ==443".into();
        assert_eq!(decode(route.clone(), 3).unwrap().nlri.dst_ports, [80, 443]);
        route.components[2].value = ">80".into();
        assert!(decode(route, 3).is_err());
        let mut bad = rule;
        bad.actions[0].rate_bps = Some(8001);
        assert!(encode(&bad).is_ok());
        bad.actions[0].rate_bps = Some(u64::MAX);
        assert!(encode(&bad).is_err());
    }
}

#[cfg(all(test, feature = "test-utils"))]
#[path = "rustbgpd_tests.rs"]
mod rpc_tests;
