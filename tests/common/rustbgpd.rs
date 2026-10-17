use prefixd::{
    bgp::{RustBgpdAnnouncer, rustbgpd_pb as pb},
    config::RustBgpdConfig,
};
use std::{
    net::TcpListener,
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{AccessMode, ExecCommand, Mount},
    runners::AsyncRunner,
};

pub struct Speaker {
    pub container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    version: String,
    // Keep the owner-only configuration/token mount alive until container removal.
    _files: tempfile::TempDir,
}

impl Speaker {
    pub async fn start() -> Self {
        let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.77.0".into());
        let releases: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/rustbgpd/releases.json")).unwrap();
        let release = &releases[&version];
        let image = release["image"].as_str().expect("unknown test release");
        let (name, tag) = image.split_once(':').unwrap();
        eprintln!(
            "rustbgpd fixture: image={image}, source={}, host={}",
            release["source_commit"],
            std::env::consts::ARCH
        );
        let files = tempfile::tempdir().unwrap();
        let metadata = files.path().metadata().unwrap();
        let sockets: Vec<_> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = sockets
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        let token =
            std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").expect("run scripts/test-rustbgpd.sh");
        let token_path = files.path().join("token");
        std::fs::write(&token_path, token).unwrap();
        std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            files.path().join("config.toml"),
            format!(
                r#"config_epoch = 2
[global]
asn = 64512
router_id = "192.0.2.1"
listen_addresses = ["127.0.0.1"]
listen_port = {}
runtime_state_dir = "/tmp/prefixd-test-runtime"
worker_threads = 2
ebgp_requires_policy = true
[global.telemetry]
prometheus_addr = "127.0.0.1:{}"
log_format = "text"
[global.telemetry.grpc_uds]
enabled = false
[global.telemetry.grpc_tcp]
address = "127.0.0.1:{}"
access_mode = "read_write"
token_file = "/fixture/token"
principal = "prefixd-test"
[security.grpc.roles]
prefixd-test = "operator"
"#,
                ports[0], ports[1], ports[2]
            ),
        )
        .unwrap();
        drop(sockets);
        let container = GenericImage::new(name, tag)
            .with_host_config_modifier(|host| {
                host.cpuset_cpus = std::env::var("PREFIXD_TEST_CPUSET").ok();
            })
            .with_network("host")
            .with_user(format!("{}:{}", metadata.uid(), metadata.gid()))
            .with_mount(
                Mount::bind_mount(files.path().to_str().unwrap(), "/fixture")
                    .with_access_mode(AccessMode::ReadOnly),
            )
            .with_cmd(["rustbgpd", "/fixture/config.toml"])
            .start()
            .await
            .expect("start pinned rustbgpd container");
        let mut check = container
            .exec(ExecCommand::new([
                "rustbgpd",
                "--check",
                "--strict",
                "/fixture/config.toml",
            ]))
            .await
            .unwrap();
        let output = check.stdout_to_vec().await.unwrap();
        assert_eq!(
            check.exit_code().await.unwrap(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output)
        );
        let fixture = Self {
            container,
            endpoint: format!("http://127.0.0.1:{}", ports[2]),
            version,
            _files: files,
        };
        fixture.ready().await;
        fixture
    }

    pub async fn ready(&self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let endpoint = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
                    .unwrap()
                    .connect_timeout(Duration::from_millis(250))
                    .timeout(Duration::from_secs(1));
                if let Ok(channel) = endpoint.connect().await {
                    let mut client = pb::control_service_client::ControlServiceClient::new(channel);
                    let mut request = tonic::Request::new(pb::HealthRequest {});
                    let token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
                    request
                        .metadata_mut()
                        .insert("authorization", format!("Bearer {token}").parse().unwrap());
                    if let Ok(response) = client.get_health(request).await {
                        let health = response.into_inner();
                        assert_eq!(health.daemon_version, self.version);
                        if health.healthy {
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bounded authenticated daemon readiness");
    }

    pub async fn connect(&self) -> RustBgpdAnnouncer {
        RustBgpdAnnouncer::connect(&RustBgpdConfig {
            endpoint: self.endpoint.clone(),
            bearer_token_env: "PREFIXD_RUSTBGPD_TEST_TOKEN".into(),
            ca_cert_path: None,
        })
        .await
        .unwrap()
    }
}
