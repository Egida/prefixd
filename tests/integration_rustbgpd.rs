#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils"))]
use prefixd::{
    bgp::{FlowSpecAnnouncer, RustBgpdAnnouncer},
    config::RustBgpdConfig,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};

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
#[ignore = "requires an explicitly configured isolated rustbgpd controller"]
async fn live_rustbgpd_controller_roundtrip() {
    let speaker = RustBgpdAnnouncer::connect(&RustBgpdConfig {
        endpoint: std::env::var("PREFIXD_RUSTBGPD_TEST_ENDPOINT").unwrap(),
        bearer_token_env: "PREFIXD_RUSTBGPD_TEST_TOKEN".into(),
        ca_cert_path: None,
    })
    .await
    .unwrap();
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
#[ignore = "requires an explicitly configured isolated rustbgpd controller"]
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

    let speaker = Arc::new(
        RustBgpdAnnouncer::connect(&RustBgpdConfig {
            endpoint: std::env::var("PREFIXD_RUSTBGPD_TEST_ENDPOINT").unwrap(),
            bearer_token_env: "PREFIXD_RUSTBGPD_TEST_TOKEN".into(),
            ca_cert_path: None,
        })
        .await
        .unwrap(),
    );
    let repo = Arc::new(MockRepository::new());
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
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
