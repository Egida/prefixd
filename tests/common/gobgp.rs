//! Owned Linux fixtures. Never connect these tests to an operator's speaker.
use prefixd::bgp::{
    GoBgpAnnouncer,
    apipb::{self as pb, go_bgp_service_client::GoBgpServiceClient},
};
use std::{net::TcpListener, time::Duration};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ExecCommand, logs::LogFrame},
    runners::AsyncRunner,
};
use tonic::transport::{Channel, Endpoint};

const IMAGE_TAG: &str =
    "latest@sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2";

pub struct Speaker {
    pub container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    pub bgp_port: u16,
    router_id: String,
}

impl Speaker {
    pub async fn start() -> Self {
        Self::with_router_id("192.0.2.10").await
    }

    pub async fn with_router_id(router_id: &str) -> Self {
        let sockets: Vec<_> = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = sockets
            .iter()
            .map(|socket| socket.local_addr().unwrap().port())
            .collect();
        let api_hosts = format!("--api-hosts=127.0.0.1:{}", ports[0]);
        drop(sockets);
        let container = GenericImage::new("jauderho/gobgp", IMAGE_TAG)
            .with_network("host")
            .with_host_config_modifier(|host| {
                host.cpuset_cpus = std::env::var("PREFIXD_TEST_CPUSET").ok();
            })
            .with_log_consumer(|frame: &LogFrame| {
                eprint!("GoBGP fixture: {}", String::from_utf8_lossy(frame.bytes()));
            })
            .with_startup_timeout(Duration::from_secs(20))
            .with_cmd([
                "/usr/local/bin/gobgpd",
                "-p",
                "--pprof-disable",
                "--metrics-path=",
                "--cpus=2",
                &api_hosts,
            ])
            .start()
            .await
            .expect("start pinned GoBGP fixture");
        let fixture = Self {
            container,
            endpoint: format!("http://127.0.0.1:{}", ports[0]),
            bgp_port: ports[1],
            router_id: router_id.into(),
        };
        let mut version = fixture
            .container
            .exec(ExecCommand::new(["/usr/local/bin/gobgpd", "--version"]))
            .await
            .unwrap();
        let output = version.stdout_to_vec().await.unwrap();
        assert_eq!(version.exit_code().await.unwrap(), Some(0));
        let version = String::from_utf8_lossy(&output);
        assert!(
            version.contains("version 4.10.0"),
            "unexpected pinned binary: {version}"
        );
        eprintln!("GoBGP fixture: image=jauderho/gobgp:{IMAGE_TAG}, {version}");
        fixture.configure().await;
        fixture
    }

    pub async fn client(&self) -> GoBgpServiceClient<Channel> {
        let endpoint = Endpoint::from_shared(self.endpoint.clone())
            .unwrap()
            .connect_timeout(Duration::from_millis(250))
            .timeout(Duration::from_secs(2));
        GoBgpServiceClient::new(endpoint.connect().await.expect("owned GoBGP endpoint"))
    }

    pub async fn configure(&self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let endpoint = Endpoint::from_shared(self.endpoint.clone())
                    .unwrap()
                    .connect_timeout(Duration::from_millis(250))
                    .timeout(Duration::from_secs(1));
                if let Ok(channel) = endpoint.connect().await {
                    let mut client = GoBgpServiceClient::new(channel);
                    if let Ok(response) = client.get_bgp(pb::GetBgpRequest {}).await {
                        let global = response.into_inner().global.expect("GoBGP global state");
                        if global.asn != 0 {
                            assert_eq!(global.asn, 65010, "unexpected existing fixture ASN");
                            assert_eq!(
                                global.router_id, self.router_id,
                                "unexpected existing fixture router ID"
                            );
                            assert_eq!(
                                global.listen_port,
                                i32::from(self.bgp_port),
                                "unexpected existing fixture BGP port"
                            );
                            assert_eq!(
                                global.listen_addresses,
                                ["127.0.0.1"],
                                "unexpected existing fixture listen addresses"
                            );
                            return;
                        }
                        // GoBGP defines ASN zero as not started; a lost StartBgp reply is read back next poll.
                        let request = pb::StartBgpRequest {
                            global: Some(pb::Global {
                                asn: 65010,
                                router_id: self.router_id.clone(),
                                listen_port: self.bgp_port.into(),
                                listen_addresses: vec!["127.0.0.1".into()],
                                ..Default::default()
                            }),
                        };
                        let _ = client.start_bgp(request).await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bounded GoBGP StartBgp readiness");
    }

    pub async fn connect(&self) -> GoBgpAnnouncer {
        let mut announcer = GoBgpAnnouncer::new(self.endpoint.clone());
        announcer
            .connect()
            .await
            .expect("connect owned GoBGP fixture");
        announcer
    }

    pub async fn paths(&self, afi: i32, table: pb::TableType) -> Vec<pb::Path> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = self
                .client()
                .await
                .list_path(pb::ListPathRequest {
                    table_type: table as i32,
                    name: if table == pb::TableType::AdjIn {
                        "127.0.0.1".into()
                    } else {
                        String::new()
                    },
                    family: Some(pb::Family { afi, safi: 133 }),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            let mut paths = Vec::new();
            while let Some(response) = stream.message().await.unwrap() {
                paths.extend(response.destination.expect("GoBGP destination").paths);
            }
            paths
        })
        .await
        .expect("bounded complete raw GoBGP inventory")
    }

    pub async fn peer_uptime(&self) -> (i64, i32) {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = self
                .client()
                .await
                .list_peer(pb::ListPeerRequest {
                    address: "127.0.0.1".into(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            let peer = stream.message().await.unwrap().unwrap().peer.unwrap();
            assert!(stream.message().await.unwrap().is_none());
            let uptime = peer.timers.unwrap().state.unwrap().uptime.unwrap();
            (uptime.seconds, uptime.nanos)
        })
        .await
        .expect("bounded actual peer uptime")
    }

    pub async fn add_peer(&self, remote_port: u16, passive: bool) {
        self.client()
            .await
            .add_peer(pb::AddPeerRequest {
                peer: Some(pb::Peer {
                    conf: Some(pb::PeerConf {
                        neighbor_address: "127.0.0.1".into(),
                        peer_asn: 65010,
                        ..Default::default()
                    }),
                    transport: Some(pb::Transport {
                        local_address: "127.0.0.1".into(),
                        remote_port: remote_port.into(),
                        passive_mode: passive,
                        ..Default::default()
                    }),
                    timers: Some(pb::Timers {
                        config: Some(pb::TimersConfig {
                            connect_retry: 1,
                            hold_time: 9,
                            keepalive_interval: 3,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    afi_safis: [1, 2]
                        .into_iter()
                        .map(|afi| pb::AfiSafi {
                            config: Some(pb::AfiSafiConfig {
                                family: Some(pb::Family { afi, safi: 133 }),
                                enabled: true,
                            }),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }),
            })
            .await
            .expect("configure isolated FlowSpec peer");
    }
}
