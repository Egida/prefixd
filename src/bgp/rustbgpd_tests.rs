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
        let mut neighbors = vec![pb::NeighborState {
            config: Some(pb::NeighborConfig {
                address: "192.0.2.1".into(),
                description: "shared edge".into(),
                ..Default::default()
            }),
            state: 6,
            stale: self.mode.load(SeqCst) == 7,
            ..Default::default()
        }];
        if self.mode.load(SeqCst) == 12 {
            neighbors.insert(
                0,
                pb::NeighborState {
                    config: Some(pb::NeighborConfig {
                        address: "192.0.2.2".into(),
                        description: "shared edge".into(),
                        ..Default::default()
                    }),
                    state: 1,
                    ..Default::default()
                },
            );
        }
        Ok(Response::new(pb::ListNeighborsResponse { neighbors }))
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
        ..Default::default()
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
    fake.mode.store(12, SeqCst);
    let peers = speaker.session_status().await.unwrap();
    // Match the scheduler's peer-name label without sharing global test metrics.
    let sessions = prometheus::GaugeVec::new(
        prometheus::Opts::new("test_bgp_session_up", "Session state"),
        &["peer"],
    )
    .unwrap();
    for peer in peers {
        assert_eq!(peer.name, peer.address);
        sessions
            .with_label_values(&[&peer.name])
            .set(if peer.state.is_established() {
                1.0
            } else {
                0.0
            });
    }
    assert_eq!(sessions.with_label_values(&["192.0.2.2"]).get(), 0.0);
    assert_eq!(sessions.with_label_values(&["192.0.2.1"]).get(), 1.0);
    use prometheus::core::Collector;
    assert_eq!(sessions.collect()[0].get_metric().len(), 2);
    fake.mode.store(0, SeqCst);
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
        ..Default::default()
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
            ..Default::default()
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
        ..Default::default()
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
        token: Some("Bearer test-secret".parse().unwrap()),
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

#[tokio::test]
async fn secure_transport_configuration_rejects_partial_identity_without_leaking_paths() {
    for endpoint in [
        "https://127.0.0.1:1",
        "http://127.0.0.1:1",
        "unix:///private/socket",
    ] {
        for (cert, key) in [(Some("private-cert"), None), (None, Some("private-key"))] {
            let config = RustBgpdConfig {
                endpoint: endpoint.into(),
                client_cert_path: cert.map(str::to_owned),
                client_key_path: key.map(str::to_owned),
                ..Default::default()
            };
            let error = RustBgpdAnnouncer::connect(&config)
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("configured together"));
            assert!(!error.contains("private-"));
        }
    }
    let config = RustBgpdConfig {
        endpoint: "https://127.0.0.1:1".into(),
        client_cert_path: Some("private-cert".into()),
        client_key_path: Some("private-key".into()),
        ..Default::default()
    };
    let error = RustBgpdAnnouncer::connect(&config)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains("private-"));
}

#[cfg(unix)]
#[tokio::test]
async fn owner_socket_rejects_permissive_directory_socket_and_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = directory.path().join("grpc.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(connect_owner_socket(&path).await.is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(connect_owner_socket(&path).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(connect_owner_socket(&path).await.is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = directory.path().join("link.sock");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(connect_owner_socket(&link).await.is_err());
    drop(listener);
}

#[tokio::test]
async fn native_mtls_presents_the_client_certificate() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            include_bytes!("testdata/transport-server-cert.pem"),
            include_bytes!("testdata/transport-server-key.pem"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(include_bytes!(
            "testdata/transport-ca.pem"
        )));
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                Fake::default(),
            ))
            .serve_with_incoming(incoming),
    );
    let path = |name: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bgp/testdata")
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    };
    let mut config = RustBgpdConfig {
        endpoint: format!("https://{address}"),
        ca_cert_path: Some(path("transport-ca.pem")),
        ..Default::default()
    };
    if let Ok(client) = RustBgpdAnnouncer::connect_with_token(&config, "test-secret").await {
        assert!(client.announce(&rule("192.0.2.231/32", 0)).await.is_err());
    }
    config.client_cert_path = Some(path("transport-client-cert.pem"));
    config.client_key_path = Some(path("transport-client-key.pem"));
    let client = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    client.announce(&rule("192.0.2.231/32", 0)).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn initial_connection_bounds_a_stalled_tls_handshake() {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (hello_sent, hello_seen) = tokio::sync::oneshot::channel();
    let (release, hold) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 22, "TLS handshake record");
        let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello[0], 1, "TLS ClientHello");
        hello_sent.send(()).unwrap();
        let _ = hold.await;
    });
    let config = RustBgpdConfig {
        endpoint: format!("https://{address}"),
        ..Default::default()
    };
    let mut connection =
        tokio::spawn(
            async move { RustBgpdAnnouncer::connect_with_token(&config, "test-secret").await },
        );
    tokio::time::timeout(Duration::from_secs(5), hello_seen)
        .await
        .expect("server must receive ClientHello before checking the TLS deadline")
        .unwrap();
    assert!(!connection.is_finished());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), &mut connection).await;
    tokio::time::resume();
    release.send(()).unwrap();
    server.await.unwrap();
    assert!(
        result.is_ok(),
        "stalled TLS negotiation exceeded the connection budget"
    );
    assert!(result.unwrap().unwrap().is_err());
}
