#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
mod common;
#[path = "common/rustbgpd.rs"]
mod fixture;
use prefixd::{
    bgp::FlowSpecAnnouncer,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};

use prefixd::bgp::{FlowSpecReader, FlowSpecWriter, PeerObserver};
fn fixture_settings(fixture: &fixture::Speaker, pop: &str) -> prefixd::config::Settings {
    let mut settings = common::test_settings();
    settings.pop = pop.into();
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.bgp.mode = prefixd::config::BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(prefixd::config::RustBgpdConfig {
        endpoint: fixture.endpoint.clone(),
        bearer_token_env: "PREFIXD_RUSTBGPD_TEST_TOKEN".into(),
        ca_cert_path: None,
    });
    settings
}

fn rule() -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "192.0.2.231/32".into(),
            protocol: Some(6),
            dst_ports: vec![443, 80],
        },
        FlowSpecAction::discard(),
    )
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_controller_roundtrip() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    for prefix in ["192.0.2.231/32", "2001:0DB8:0:0:0:0:0:231/128"] {
        let mut rule = rule();
        rule.nlri.dst_prefix = prefix.into();
        for action in [FlowSpecAction::discard(), FlowSpecAction::police(8_000_000)] {
            rule.actions = vec![action];
            speaker.announce(&rule).await.unwrap();
            speaker.announce(&rule).await.unwrap();
            let active = speaker.list_active().await.unwrap();
            let actual = active
                .iter()
                .find(|r| r.nlri_hash() == rule.nlri_hash())
                .expect("injected local intent");
            assert_eq!(actual.actions[0].action_type, rule.actions[0].action_type);
            assert_eq!(actual.actions[0].rate_bps, rule.actions[0].rate_bps);
        }
        speaker.withdraw(&rule).await.unwrap();
        speaker.withdraw(&rule).await.unwrap();
        assert!(
            !speaker
                .list_active()
                .await
                .unwrap()
                .iter()
                .any(|r| r.nlri_hash() == rule.nlri_hash())
        );
    }
    speaker.session_status().await.unwrap();
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_ttl_reconciliation() {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            MitigationStatus,
        },
        scheduler::ReconciliationLoop,
    };
    use std::sync::Arc;

    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let repo = Arc::new(MockRepository::new());
    let settings = fixture_settings(&fixture, "live-test");
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_speaker_binding(binding);
    for (ip, length) in [("192.0.2.232", 32), ("2001:db8::232", 128)] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "live-test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/{length}"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 30,
                reason: "live TTL test".into(),
            },
            ip.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        repo.insert_mitigation(&mitigation).await.unwrap();
        let rule = FlowSpecRule::new(
            (&mitigation.match_criteria).into(),
            FlowSpecAction::discard(),
        );
        speaker.announce(&rule).await.unwrap();
        assert!(
            speaker
                .list_active()
                .await
                .unwrap()
                .iter()
                .any(|r| r.nlri_hash() == rule.nlri_hash())
        );
        reconciler.reconcile().await.unwrap();
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
        assert!(
            !speaker
                .list_active()
                .await
                .unwrap()
                .iter()
                .any(|r| r.nlri_hash() == rule.nlri_hash())
        );
    }
}

struct PollingSpeaker {
    inner: std::sync::Arc<prefixd::bgp::RustBgpdAnnouncer>,
    inventory_gate: tokio::sync::RwLock<()>,
    observed: tokio::sync::Notify,
}

impl FlowSpecAnnouncer for PollingSpeaker {
    fn backend(&self) -> &'static str {
        "rustbgpd"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl FlowSpecWriter for PollingSpeaker {
    async fn announce(&self, rule: &FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl FlowSpecReader for PollingSpeaker {
    async fn list_active(&self) -> prefixd::error::Result<Vec<FlowSpecRule>> {
        let _gate = self.inventory_gate.read().await;
        self.inner.list_active().await
    }
}
#[async_trait::async_trait]
impl PeerObserver for PollingSpeaker {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        let result = self.inner.session_status().await;
        self.observed.notify_one();
        result
    }
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_restart_recovers_with_the_same_client_and_desired_state() {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            MitigationStatus,
        },
        observability::metrics,
        scheduler::ReconciliationLoop,
    };
    use std::{sync::Arc, time::Duration};
    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let repo = Arc::new(MockRepository::new());
    let settings = fixture_settings(&fixture, "restart-test");
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let mut desired = Vec::new();
    for (ip, length, action_type, rate_bps) in [
        ("192.0.2.233", 32, ActionType::Discard, None),
        ("2001:db8::233", 128, ActionType::Police, Some(8_000_000)),
    ] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "restart-test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/{length}"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type,
                action_params: ActionParams { rate_bps },
                ttl_seconds: 300,
                reason: "restart test".into(),
            },
            ip.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        repo.insert_mitigation(&mitigation).await.unwrap();
        let rule = FlowSpecRule::new(
            (&mitigation.match_criteria).into(),
            FlowSpecAction {
                action_type,
                rate_bps,
            },
        );
        speaker.announce(&rule).await.unwrap();
        desired.push((mitigation, rule));
    }
    let mut foreign = rule();
    foreign.nlri.dst_prefix = "198.51.100.233/32".into();
    speaker.announce(&foreign).await.unwrap();
    let observed = Arc::new(PollingSpeaker {
        inner: speaker.clone(),
        inventory_gate: tokio::sync::RwLock::new(()),
        observed: tokio::sync::Notify::new(),
    });
    let interval = Duration::from_secs(3);
    let reconciler = ReconciliationLoop::new(
        repo.clone(),
        observed.clone(),
        interval.as_secs() as u32,
        false,
    )
    .with_speaker_binding(binding.clone());
    let (shutdown, rx) = tokio::sync::broadcast::channel(1);
    let task = tokio::spawn(async move { reconciler.run(rx).await });
    tokio::time::timeout(interval, observed.observed.notified())
        .await
        .unwrap();
    assert_eq!(speaker.list_active().await.unwrap().len(), 3);

    // Hold only the poller while proving lost intent directly through the same channel.
    let gate = observed.inventory_gate.write().await;
    fixture.container.stop_with_timeout(Some(0)).await.unwrap();
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(2), speaker.list_active()).await,
        Ok(Ok(_))
    ));
    fixture.container.start().await.unwrap();
    fixture.ready().await;
    assert!(speaker.list_active().await.unwrap().is_empty());
    for (mitigation, _) in &desired {
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
    speaker.announce(&foreign).await.unwrap();
    let before = metrics::RECONCILIATION_REPAIRS
        .with_label_values(&["success"])
        .get();
    drop(gate);
    tokio::time::timeout(interval, async {
        loop {
            let actual = speaker.list_active().await.unwrap();
            if actual.len() == 3 {
                for (_, expected) in &desired {
                    let restored = actual
                        .iter()
                        .find(|r| r.nlri_hash() == expected.nlri_hash())
                        .unwrap();
                    assert_eq!(restored.actions.len(), expected.actions.len());
                    for (actual, wanted) in restored.actions.iter().zip(&expected.actions) {
                        assert_eq!(actual.action_type, wanted.action_type);
                        assert_eq!(actual.rate_bps, wanted.rate_bps);
                    }
                }
                assert!(actual.iter().any(|r| r.nlri_hash() == foreign.nlri_hash()
                    && r.actions.len() == 1
                    && r.actions[0].action_type == foreign.actions[0].action_type
                    && r.actions[0].rate_bps == foreign.actions[0].rate_bps));
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("recovery within one configured interval after readiness");
    tokio::time::timeout(
        interval + Duration::from_secs(1),
        observed.observed.notified(),
    )
    .await
    .unwrap();
    // The following converged poll must not inject or withdraw anything.
    tokio::time::timeout(
        interval + Duration::from_secs(1),
        observed.observed.notified(),
    )
    .await
    .unwrap();
    assert_eq!(
        metrics::RECONCILIATION_REPAIRS
            .with_label_values(&["success"])
            .get(),
        before + 2.0
    );
    assert_eq!(speaker.list_active().await.unwrap().len(), 3);

    metrics::init_metrics();
    let state = prefixd::AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        repo,
        speaker,
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, prefixd::api::create_test_router(state))
            .await
            .unwrap()
    });
    let scrape = reqwest::get(format!("http://{address}/metrics"))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    for metric in [
        "prefixd_reconciliation_runs_total",
        "prefixd_reconciliation_repairs_total",
    ] {
        for status in ["success", "error"] {
            assert!(
                scrape.contains(&format!("{metric}{{status=\"{status}\"}}")),
                "missing actual status-labelled sample"
            );
        }
    }
    server.abort();
    shutdown.send(()).unwrap();
    task.await.unwrap();
}
