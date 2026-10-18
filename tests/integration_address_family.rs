mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    bgp::{FlowSpecReader, MockAnnouncer},
    config::{Customer, Inventory, OperationMode, PolicyProfile},
    db::{MockRepository, RepositoryTrait},
    domain::AttackVector,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

fn state(
    vector: AttackVector,
    relaxed_v6: bool,
) -> (Arc<AppState>, Arc<MockRepository>, Arc<MockAnnouncer>) {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    if relaxed_v6 {
        settings.guardrails.dst_prefix_minlen_v6 = Some(32);
    }
    let inventory = Inventory::new(vec![Customer {
        customer_id: "family-test".into(),
        name: "Address family test".into(),
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8::/32".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let mut playbooks = common::test_playbooks();
    playbooks.playbooks[0].match_criteria.vector = vector;
    let state = AppState::new(
        settings,
        inventory,
        playbooks,
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    (state, repo, speaker)
}

async fn ingest(
    state: Arc<AppState>,
    ip: &str,
    vector: AttackVector,
    event_id: &str,
) -> (StatusCode, Value) {
    let response = create_test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "event_id": event_id,
                        "timestamp": "2026-10-17T00:00:00Z",
                        "source": "family-test",
                        "victim_ip": ip,
                        "vector": vector,
                        "confidence": 0.99,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn assert_automatic_host_rules(addresses: &[(&str, &str)], ipv6: bool) {
    for (vector, v4_protocol, v6_protocol) in [
        (AttackVector::UdpFlood, 17, 17),
        (AttackVector::SynFlood, 6, 6),
        (AttackVector::AckFlood, 6, 6),
        (AttackVector::IcmpFlood, 1, 58),
    ] {
        let protocol = if ipv6 { v6_protocol } else { v4_protocol };
        for &(ip, prefix) in addresses {
            let (state, repo, speaker) = state(vector, false);
            let (status, body) = ingest(state, ip, vector, "host").await;
            assert_eq!(status, StatusCode::ACCEPTED, "{vector} {ip}: {body}");
            let id: Uuid = body["mitigation_id"]
                .as_str()
                .expect("created mitigation")
                .parse()
                .unwrap();
            let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
            assert_eq!(mitigation.match_criteria.dst_prefix, prefix);
            assert_eq!(mitigation.match_criteria.protocol, Some(protocol));
            let event = repo
                .find_ban_event_by_external_id("family-test", "host")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(event.protocol, Some(i32::from(protocol)));
            let rules = speaker.list_active().await.unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].nlri.dst_prefix, prefix);
            assert_eq!(rules[0].nlri.protocol, Some(protocol));
        }
    }
}

#[tokio::test]
async fn automatic_ipv4_controls_remain_host_scoped() {
    assert_automatic_host_rules(&[("203.0.113.10", "203.0.113.10/32")], false).await;
}

#[tokio::test]
async fn automatic_ipv6_events_announce_only_family_correct_hosts() {
    assert_automatic_host_rules(
        &[
            ("2001:db8::10", "2001:db8::10/128"),
            (
                "2001:0DB8:0000:0000:0000:0000:0000:0010",
                "2001:db8::10/128",
            ),
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn expanded_ipv6_extends_one_host_even_with_relaxed_prefix_guardrails() {
    let (state, repo, speaker) = state(AttackVector::IcmpFlood, true);
    let (first_status, first) = ingest(
        state.clone(),
        "2001:db8::10",
        AttackVector::IcmpFlood,
        "first",
    )
    .await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    let (second_status, second) = ingest(
        state,
        "2001:0DB8:0000:0000:0000:0000:0000:0010",
        AttackVector::IcmpFlood,
        "second",
    )
    .await;
    assert_eq!(second_status, StatusCode::ACCEPTED);
    assert_eq!(second["status"], "extended");
    assert_eq!(first["mitigation_id"], second["mitigation_id"]);
    assert_eq!(repo.count_active_global().await.unwrap(), 1);
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].nlri.dst_prefix, "2001:db8::10/128");
    assert_eq!(rules[0].nlri.protocol, Some(58));
}

#[tokio::test]
async fn invalid_destinations_are_rejected_before_event_or_speaker_mutation() {
    let (state, repo, speaker) = state(AttackVector::UdpFlood, false);
    for ip in [
        "invalid",
        "203.0.113.10/24",
        "2001:db8::10/32",
        "fe80::1%eth0",
    ] {
        let (status, _) = ingest(state.clone(), ip, AttackVector::UdpFlood, ip).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ip}");
        assert!(
            repo.find_ban_event_by_external_id("family-test", ip)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(repo.count_active_global().await.unwrap(), 0);
    assert!(speaker.list_active().await.unwrap().is_empty());
}
