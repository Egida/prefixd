use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering::SeqCst},
};
use tonic::{Response, Status};

#[derive(Clone, Default)]
struct Fake {
    rules: Arc<Mutex<Vec<pb::AddFlowSpecRequest>>>,
    mode: Arc<AtomicUsize>,
    attempts: Arc<AtomicUsize>,
    families: Arc<Mutex<Vec<i32>>>,
}

fn auth<T>(request: &Request<T>) -> std::result::Result<(), Status> {
    if request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some("Bearer test-secret")
    {
        return Err(Status::unauthenticated("denied"));
    }
    assert!(request.metadata().contains_key("grpc-timeout"));
    Ok(())
}

#[tonic::async_trait]
impl pb::injection_service_server::InjectionService for Fake {
    async fn add_flow_spec(
        &self,
        request: Request<pb::AddFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::AddFlowSpecResponse>, Status> {
        let attempt = self.attempts.fetch_add(1, SeqCst);
        auth(&request)?;
        match self.mode.load(SeqCst) {
            1 => return Err(Status::unavailable("temporary")),
            2 => return Err(Status::invalid_argument("bad input")),
            3 => return Ok(Response::new(pb::AddFlowSpecResponse { outcome: 0 })),
            9 if attempt == 0 => return Err(Status::unavailable("once")),
            10 => return Err(Status::deadline_exceeded("deadline")),
            11 => tokio::time::sleep(Duration::from_secs(60)).await,
            _ => {}
        }
        let request = request.into_inner();
        assert!(matches!(request.afi_safi, 3 | 4));
        assert_eq!(
            request
                .components
                .iter()
                .map(|c| c.r#type)
                .collect::<Vec<_>>(),
            [1, 3, 5]
        );
        let mut rules = self.rules.lock().unwrap();
        let existing = rules.iter().position(|old| {
            old.afi_safi == request.afi_safi && old.components == request.components
        });
        let outcome = match existing {
            Some(index) if rules[index] == request => 3,
            Some(index) => {
                rules[index] = request;
                2
            }
            None => {
                rules.push(request);
                1
            }
        };
        Ok(Response::new(pb::AddFlowSpecResponse { outcome }))
    }

    async fn delete_flow_spec(
        &self,
        request: Request<pb::DeleteFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::DeleteFlowSpecResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert!(request.allow_missing);
        match self.mode.load(SeqCst) {
            4 => return Err(Status::not_found("absent")),
            5 => return Ok(Response::new(pb::DeleteFlowSpecResponse { outcome: 0 })),
            _ => {}
        }
        let mut rules = self.rules.lock().unwrap();
        let before = rules.len();
        rules
            .retain(|old| old.afi_safi != request.afi_safi || old.components != request.components);
        Ok(Response::new(pb::DeleteFlowSpecResponse {
            outcome: if rules.len() == before { 2 } else { 1 },
        }))
    }
}

#[tonic::async_trait]
impl pb::rib_service_server::RibService for Fake {
    async fn list_flow_spec_routes(
        &self,
        request: Request<pb::ListFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::ListFlowSpecResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert_eq!(request.received_peer_address, "0.0.0.0");
        assert!(request.advertised_peer_address.is_empty());
        self.families.lock().unwrap().push(request.afi_safi);
        let received_routes = self
            .rules
            .lock()
            .unwrap()
            .iter()
            .filter(|rule| rule.afi_safi == request.afi_safi)
            .map(|rule| {
                let Some(pb::flow_spec_action::Action::TrafficRate(rate)) = &rule.actions[0].action
                else {
                    panic!("expected rate action")
                };
                let mut components = rule.components.clone();
                for component in &mut components {
                    component.value = component.value.replace('=', "==");
                }
                if self.mode.load(SeqCst) == 8 {
                    components.push(pb::FlowSpecComponent {
                        r#type: 10,
                        value: ">80".into(),
                        ..Default::default()
                    });
                }
                pb::ReceivedFlowSpecRouteEntry {
                    route: Some(pb::FlowSpecRouteEntry {
                        components,
                        actions: rule.actions.clone(),
                        peer_address: "0.0.0.0".into(),
                        afi_safi: rule.afi_safi,
                        extended_communities: vec![
                            (0x8006_u64 << 48) | u64::from(rate.rate.to_bits()),
                        ],
                        ..Default::default()
                    }),
                    selected: false,
                    validation: 3,
                    ..Default::default()
                }
            })
            .collect();
        Ok(Response::new(pb::ListFlowSpecResponse {
            received_view: self.mode.load(SeqCst) != 6,
            received_routes,
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl pb::neighbor_service_server::NeighborService for Fake {
    async fn list_neighbors(
        &self,
        request: Request<pb::ListNeighborsRequest>,
    ) -> std::result::Result<Response<pb::ListNeighborsResponse>, Status> {
        auth(&request)?;
        Ok(Response::new(pb::ListNeighborsResponse {
            neighbors: vec![pb::NeighborState {
                config: Some(pb::NeighborConfig {
                    address: "192.0.2.1".into(),
                    ..Default::default()
                }),
                state: 6,
                stale: self.mode.load(SeqCst) == 7,
                ..Default::default()
            }],
        }))
    }
}

fn rule(prefix: &str, rate: u64) -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(6),
            dst_ports: vec![443, 80, 80],
        },
        if rate == 0 {
            FlowSpecAction::discard()
        } else {
            FlowSpecAction::police(rate)
        },
    )
}

#[tokio::test]
async fn authenticated_controller_rpc_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                fake.clone(),
            ))
            .add_service(pb::rib_service_server::RibServiceServer::new(fake.clone()))
            .add_service(pb::neighbor_service_server::NeighborServiceServer::new(
                fake.clone(),
            ))
            .serve_with_incoming(incoming),
    );
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ca_cert_path: None,
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    let v4 = rule("192.0.2.231/32", 0);
    let v6 = rule("2001:0DB8:0:0:0:0:0:231/128", 8_000_000);
    speaker.announce(&v4).await.unwrap();
    speaker.announce(&v4).await.unwrap();
    speaker.announce(&v6).await.unwrap();
    for expected in [&v4, &v6] {
        let active = speaker.list_active().await.unwrap();
        let actual = active
            .iter()
            .find(|r| r.nlri_hash() == expected.nlri_hash())
            .unwrap();
        assert_eq!(actual.actions[0].rate_bps, expected.actions[0].rate_bps);
        assert_eq!(
            actual.actions[0].action_type,
            expected.actions[0].action_type
        );
    }
    assert!(fake.families.lock().unwrap().contains(&3));
    assert!(fake.families.lock().unwrap().contains(&4));
    let replacement = rule("192.0.2.231/32", 8_000);
    speaker.announce(&replacement).await.unwrap();
    let active = speaker.list_active().await.unwrap();
    assert_eq!(
        active
            .iter()
            .find(|r| r.nlri_hash() == replacement.nlri_hash())
            .unwrap()
            .actions[0]
            .rate_bps,
        Some(8_000)
    );
    assert_eq!(speaker.session_status().await.unwrap()[0].name, "192.0.2.1");
    for (mode, expected_attempts) in [(1, 3), (2, 1), (3, 1), (10, 3)] {
        fake.mode.store(mode, SeqCst);
        fake.attempts.store(0, SeqCst);
        assert!(speaker.announce(&v4).await.is_err());
        assert_eq!(fake.attempts.load(SeqCst), expected_attempts);
    }
    fake.mode.store(9, SeqCst);
    fake.attempts.store(0, SeqCst);
    speaker.announce(&v4).await.unwrap();
    assert_eq!(fake.attempts.load(SeqCst), 2);
    fake.mode.store(4, SeqCst);
    speaker.withdraw(&v4).await.unwrap();
    fake.mode.store(5, SeqCst);
    assert!(speaker.withdraw(&v4).await.is_err());
    fake.mode.store(6, SeqCst);
    assert!(speaker.list_active().await.is_err());
    fake.mode.store(7, SeqCst);
    assert!(speaker.session_status().await.is_err());
    fake.mode.store(8, SeqCst);
    assert!(speaker.list_active().await.is_err());
    fake.mode.store(0, SeqCst);
    for rule in [&v4, &v6] {
        speaker.withdraw(rule).await.unwrap();
        speaker.withdraw(rule).await.unwrap();
    }
    assert!(speaker.list_active().await.unwrap().is_empty());
    let wrong_token = RustBgpdAnnouncer::connect_with_token(&config, "incorrect")
        .await
        .unwrap();
    fake.attempts.store(0, SeqCst);
    assert!(wrong_token.announce(&v4).await.is_err());
    assert_eq!(fake.attempts.load(SeqCst), 1);
    fake.mode.store(11, SeqCst);
    fake.attempts.store(0, SeqCst);
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    assert!(speaker.announce(&v4).await.is_err());
    assert!(start.elapsed() >= Duration::from_secs(30));
    assert!(start.elapsed() <= Duration::from_secs(95));
    assert!((1..=3).contains(&fake.attempts.load(SeqCst)));
    tokio::time::resume();
    server.abort();
}

#[tokio::test]
async fn tls_verifies_the_server_certificate() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    // This key belongs only to the local test server.
    let identity = tonic::transport::Identity::from_pem(
        include_bytes!("testdata/server-cert.pem"),
        include_bytes!("testdata/server-key.pem"),
    );
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
            .unwrap()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                Fake::default(),
            ))
            .serve_with_incoming(incoming),
    );
    let mut config = RustBgpdConfig {
        endpoint: format!("https://{address}"),
        bearer_token_env: "unused".into(),
        ca_cert_path: None,
    };
    assert!(
        RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
            .await
            .is_err()
    );
    config.ca_cert_path = Some(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bgp/testdata/server-cert.pem"
        )
        .into(),
    );
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    speaker.announce(&rule("192.0.2.231/32", 0)).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rejects_unsafe_transport_and_credentials() {
    for endpoint in [
        "http://192.0.2.1:50051",
        "http://localhost:50051",
        "ftp://127.0.0.1:50051",
        "http://user@127.0.0.1:50051",
    ] {
        let config = RustBgpdConfig {
            endpoint: endpoint.into(),
            bearer_token_env: "unused".into(),
            ca_cert_path: None,
        };
        assert!(
            RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
                .await
                .is_err()
        );
    }
    let config = RustBgpdConfig {
        endpoint: "http://127.0.0.1:1".into(),
        bearer_token_env: "PREFIXD_UNSET_TEST_TOKEN_7CA4".into(),
        ca_cert_path: None,
    };
    for token in ["", "secret\n", "two words"] {
        assert!(
            RustBgpdAnnouncer::connect_with_token(&config, token)
                .await
                .is_err()
        );
    }
    assert!(RustBgpdAnnouncer::connect(&config).await.is_err());
}

#[tokio::test]
async fn complete_rpc_deadline_bounds_stalled_response_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let headers_sent = Arc::new(AtomicUsize::new(0));
    let observed = headers_sent.clone();
    // The real HTTP/2 response sends headers, then never sends body frames or trailers.
    let stall_body = tower::util::MapResponseLayer::new(
        move |mut response: tonic::codegen::http::Response<tonic::body::Body>| {
            observed.fetch_add(1, SeqCst);
            *response.body_mut() = tonic::body::Body::new(axum::body::Body::from_stream(
                futures_util::stream::pending::<
                    std::result::Result<axum::body::Bytes, std::io::Error>,
                >(),
            ));
            response
        },
    );
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .layer(stall_body)
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                Fake::default(),
            ))
            .serve_with_incoming(incoming),
    );
    // Omit the transport's header timeout so only the complete-RPC bound can end this call.
    let speaker = RustBgpdAnnouncer {
        channel: Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
        token: "Bearer test-secret".parse().unwrap(),
    };
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(95),
        speaker.announce(&rule("192.0.2.231/32", 0)),
    )
    .await
    .expect("a stalled body must not outlive all three RPC deadlines");
    assert!(result.unwrap_err().to_string().contains("DeadlineExceeded"));
    assert_eq!(headers_sent.load(SeqCst), 3);
    assert!(start.elapsed() >= Duration::from_secs(90));
    assert!(start.elapsed() < Duration::from_secs(91));
    tokio::time::resume();
    server.abort();
}
