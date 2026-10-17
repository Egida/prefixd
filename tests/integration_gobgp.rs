//! Integration tests for GoBGP reconciliation.
//!
//! These tests require a running GoBGP v4.x instance with gRPC API enabled.
//!
//! To run:
//!   docker compose up -d gobgp
//!   cargo test --test integration_gobgp -- --ignored --test-threads=1
//! Set PREFIXD_GOBGP_TEST_ENDPOINT for an isolated non-default listener.

use prefixd::bgp::{FlowSpecAnnouncer, GoBgpAnnouncer};
use prefixd::domain::{ActionType, FlowSpecAction, FlowSpecNlri, FlowSpecRule};
use std::time::Duration;

const GOBGP_ENDPOINT: &str = "127.0.0.1:50051";

/// Helper to create and connect a GoBGP announcer
async fn connect_gobgp() -> GoBgpAnnouncer {
    let endpoint =
        std::env::var("PREFIXD_GOBGP_TEST_ENDPOINT").unwrap_or_else(|_| GOBGP_ENDPOINT.into());
    let mut announcer = GoBgpAnnouncer::new(endpoint);
    announcer
        .connect()
        .await
        .expect("Failed to connect to GoBGP");
    announcer
}

/// Test: Announce a rule, verify it appears in list_active()
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_announce_and_list_active() {
    let announcer = connect_gobgp().await;

    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.1/32".to_string(),
            protocol: Some(17), // UDP
            dst_ports: vec![53],
        },
        FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: None,
        },
    );

    // Announce
    announcer.announce(&rule).await.expect("Failed to announce");

    // Small delay for GoBGP to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // List active rules
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");

    // Find our rule by NLRI hash
    let found = active.iter().find(|r| r.nlri_hash() == rule.nlri_hash());
    assert!(found.is_some(), "Announced rule not found in RIB");

    // Verify parsed rule matches original
    let parsed = found.unwrap();
    assert_eq!(parsed.nlri.dst_prefix, rule.nlri.dst_prefix);
    assert_eq!(parsed.nlri.protocol, rule.nlri.protocol);
    assert_eq!(parsed.nlri.dst_ports, rule.nlri.dst_ports);

    // Cleanup: withdraw the rule
    announcer.withdraw(&rule).await.expect("Failed to withdraw");
}

/// Test: Announce, withdraw, verify it's gone from list_active()
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_announce_withdraw_cycle() {
    let announcer = connect_gobgp().await;

    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.2/32".to_string(),
            protocol: Some(6), // TCP
            dst_ports: vec![80, 443],
        },
        FlowSpecAction {
            action_type: ActionType::Police,
            rate_bps: Some(100_000_000),
        },
    );

    // Announce
    announcer.announce(&rule).await.expect("Failed to announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify present
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    assert!(
        active.iter().any(|r| r.nlri_hash() == rule.nlri_hash()),
        "Rule should be in RIB after announce"
    );

    // Withdraw
    announcer.withdraw(&rule).await.expect("Failed to withdraw");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify gone
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    assert!(
        !active.iter().any(|r| r.nlri_hash() == rule.nlri_hash()),
        "Rule should NOT be in RIB after withdraw"
    );
}

/// Test: Multiple rules with different characteristics
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_multiple_rules_roundtrip() {
    let announcer = connect_gobgp().await;

    let rules = vec![
        // UDP discard
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "198.51.100.10/32".to_string(),
                protocol: Some(17),
                dst_ports: vec![53, 123],
            },
            FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            },
        ),
        // TCP police
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "198.51.100.11/32".to_string(),
                protocol: Some(6),
                dst_ports: vec![80],
            },
            FlowSpecAction {
                action_type: ActionType::Police,
                rate_bps: Some(50_000_000),
            },
        ),
        // ICMP discard (no ports)
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "198.51.100.12/32".to_string(),
                protocol: Some(1),
                dst_ports: vec![],
            },
            FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            },
        ),
        // Any protocol (no protocol specified)
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "198.51.100.13/32".to_string(),
                protocol: None,
                dst_ports: vec![],
            },
            FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            },
        ),
    ];

    // Announce all
    for rule in &rules {
        announcer.announce(rule).await.expect("Failed to announce");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // List and verify all present
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");

    for rule in &rules {
        let found = active.iter().find(|r| r.nlri_hash() == rule.nlri_hash());
        assert!(
            found.is_some(),
            "Rule {} not found in RIB",
            rule.nlri.dst_prefix
        );

        let parsed = found.unwrap();
        assert_eq!(parsed.nlri.dst_prefix, rule.nlri.dst_prefix);
        assert_eq!(parsed.nlri.protocol, rule.nlri.protocol);
        assert_eq!(parsed.nlri.dst_ports, rule.nlri.dst_ports);
    }

    // Cleanup: withdraw all
    for rule in &rules {
        announcer.withdraw(rule).await.expect("Failed to withdraw");
    }
}

/// Test: Reconciliation scenario - detect missing rule
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_reconciliation_detects_missing_rule() {
    let announcer = connect_gobgp().await;

    // Create two rules representing "desired state"
    let rule1 = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.20/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: None,
        },
    );

    let rule2 = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.21/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![123],
        },
        FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: None,
        },
    );

    // Announce only rule1 (simulating partial state)
    announcer
        .announce(&rule1)
        .await
        .expect("Failed to announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // List active (simulating reconciliation check)
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    let active_hashes: std::collections::HashSet<_> =
        active.iter().map(|r| r.nlri_hash()).collect();

    // Check which "desired" rules are missing
    let desired = [&rule1, &rule2];
    let missing: Vec<_> = desired
        .iter()
        .filter(|r| !active_hashes.contains(&r.nlri_hash()))
        .collect();

    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].nlri.dst_prefix, "198.51.100.21/32");

    // Reconciliation would re-announce missing rule
    announcer
        .announce(&rule2)
        .await
        .expect("Failed to re-announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify both now present
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    assert!(active.iter().any(|r| r.nlri_hash() == rule1.nlri_hash()));
    assert!(active.iter().any(|r| r.nlri_hash() == rule2.nlri_hash()));

    // Cleanup
    announcer.withdraw(&rule1).await.ok();
    announcer.withdraw(&rule2).await.ok();
}

/// Test: Reconciliation scenario - detect orphan rule
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_reconciliation_detects_orphan_rule() {
    let announcer = connect_gobgp().await;

    // Announce a rule that will become "orphan" (in BGP but not in desired state)
    let orphan_rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.30/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: None,
        },
    );

    // Announce a rule that is in desired state
    let desired_rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.31/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![123],
        },
        FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: None,
        },
    );

    announcer
        .announce(&orphan_rule)
        .await
        .expect("Failed to announce orphan");
    announcer
        .announce(&desired_rule)
        .await
        .expect("Failed to announce desired");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Simulate desired state (only desired_rule)
    let desired_hashes: std::collections::HashSet<_> =
        vec![desired_rule.nlri_hash()].into_iter().collect();

    // List active and find orphans
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    let orphans: Vec<_> = active
        .iter()
        .filter(|r| !desired_hashes.contains(&r.nlri_hash()))
        .filter(|r| r.nlri.dst_prefix.starts_with("198.51.100.3")) // Filter to our test prefixes
        .collect();

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].nlri.dst_prefix, "198.51.100.30/32");

    // In real reconciliation, we'd log warning about orphan
    // For cleanup in test, we withdraw it
    announcer.withdraw(&orphan_rule).await.ok();
    announcer.withdraw(&desired_rule).await.ok();
}

/// Test: IPv6 FlowSpec roundtrip through GoBGP
#[tokio::test]
#[ignore] // Requires running GoBGP with IPv6 FlowSpec support
async fn test_ipv6_flowspec_roundtrip() {
    let announcer = connect_gobgp().await;

    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "2001:db8:1::1/128".to_string(),
            protocol: Some(17), // UDP
            dst_ports: vec![53],
        },
        FlowSpecAction {
            action_type: ActionType::Police,
            rate_bps: Some(1_000_000_000), // 1 Gbps
        },
    );

    // Announce
    announcer
        .announce(&rule)
        .await
        .expect("Failed to announce IPv6 rule");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let active = announcer
        .list_active()
        .await
        .expect("Failed to list dual-family inventory");
    let parsed = active
        .iter()
        .find(|candidate| candidate.nlri_hash() == rule.nlri_hash())
        .expect("IPv6 rule missing from local inventory");
    assert_eq!(parsed.actions[0].action_type, ActionType::Police);
    assert_eq!(parsed.actions[0].rate_bps, Some(1_000_000_000));

    // Cleanup
    announcer
        .withdraw(&rule)
        .await
        .expect("Failed to withdraw IPv6 rule");
}

/// Test: Session status check
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_session_status() {
    let announcer = connect_gobgp().await;

    let peers = announcer
        .session_status()
        .await
        .expect("Failed to get session status");

    // In docker-compose setup, GoBGP may have no configured peers
    // Just verify the call succeeds and returns a list
    println!("GoBGP peers: {:?}", peers);
}

/// Test: End-to-end reconciliation - manually delete from GoBGP, verify re-announcement
///
/// This simulates what happens when GoBGP loses state (restart, etc.) and the
/// reconciliation loop detects drift and re-announces missing rules.
#[tokio::test]
#[ignore] // Requires running GoBGP
async fn test_reconciliation_reannounces_after_manual_delete() {
    let announcer = connect_gobgp().await;

    // 1. Announce a rule (simulating what prefixd would do after event ingestion)
    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53, 123],
        },
        FlowSpecAction {
            action_type: ActionType::Police,
            rate_bps: Some(100_000_000), // 100 Mbps
        },
    );

    announcer.announce(&rule).await.expect("Failed to announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Verify it's in the RIB
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    assert!(
        active.iter().any(|r| r.nlri_hash() == rule.nlri_hash()),
        "Rule should be in RIB after initial announce"
    );

    // 3. Manually withdraw (simulating GoBGP restart or external deletion)
    announcer.withdraw(&rule).await.expect("Failed to withdraw");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Verify it's gone
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    assert!(
        !active.iter().any(|r| r.nlri_hash() == rule.nlri_hash()),
        "Rule should NOT be in RIB after manual delete"
    );

    // 5. Simulate reconciliation: detect missing and re-announce
    // In real prefixd, this would be sync_announcements() comparing DB vs RIB
    let desired_hashes: std::collections::HashSet<_> = vec![rule.nlri_hash()].into_iter().collect();
    let active_hashes: std::collections::HashSet<_> =
        active.iter().map(|r| r.nlri_hash()).collect();

    let missing: Vec<_> = desired_hashes.difference(&active_hashes).collect();

    assert_eq!(missing.len(), 1, "Should detect one missing rule");

    // Re-announce the missing rule
    announcer
        .announce(&rule)
        .await
        .expect("Failed to re-announce");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Verify it's back
    let active = announcer
        .list_active()
        .await
        .expect("Failed to list active");
    assert!(
        active.iter().any(|r| r.nlri_hash() == rule.nlri_hash()),
        "Rule should be back in RIB after reconciliation re-announce"
    );

    // 7. Verify the parsed rule matches original
    let parsed = active
        .iter()
        .find(|r| r.nlri_hash() == rule.nlri_hash())
        .unwrap();
    assert_eq!(parsed.nlri.dst_prefix, rule.nlri.dst_prefix);
    assert_eq!(parsed.nlri.protocol, rule.nlri.protocol);
    assert_eq!(parsed.nlri.dst_ports, rule.nlri.dst_ports);
    assert_eq!(parsed.actions[0].action_type, ActionType::Police);
    assert!(parsed.actions[0].rate_bps.is_some());

    // Cleanup
    announcer.withdraw(&rule).await.ok();
}

/// Use an isolated speaker: the unsupported local row deliberately blocks strict inventory.
#[tokio::test]
#[ignore] // Requires isolated GoBGP; run this file with --test-threads=1.
async fn test_local_provenance_and_unsupported_local_rule() {
    use prefixd::bgp::apipb::{
        self, flow_spec_rule, go_bgp_service_client::GoBgpServiceClient, nlri,
    };
    let announcer = connect_gobgp().await;
    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.211/32".into(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction::discard(),
    );
    announcer.announce(&rule).await.unwrap();
    let endpoint =
        std::env::var("PREFIXD_GOBGP_TEST_ENDPOINT").unwrap_or_else(|_| GOBGP_ENDPOINT.into());
    let mut client = GoBgpServiceClient::connect(format!("http://{endpoint}"))
        .await
        .unwrap();
    let family = apipb::Family { afi: 1, safi: 133 };
    let mut stream = client
        .list_path(apipb::ListPathRequest {
            table_type: apipb::TableType::Global as i32,
            family: Some(family),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut local_path = None;
    while let Some(response) = stream.message().await.unwrap() {
        for path in response.destination.unwrap().paths {
            if path
                .nlri
                .as_ref()
                .and_then(|nlri| announcer.decode_flowspec_nlri(nlri).ok())
                .is_some_and(|nlri| nlri.compute_hash() == rule.nlri_hash())
            {
                local_path = Some(path);
            }
        }
    }
    let mut local_path = local_path.expect("injected path must appear in GLOBAL RIB");
    assert!(
        local_path.neighbor_ip.is_empty(),
        "GoBGP-local provenance uses an empty neighbor address"
    );
    assert!(
        local_path.uuid.is_empty(),
        "ListPath does not serialize injection UUIDs"
    );
    let Some(nlri::Nlri::FlowSpec(nlri)) = &mut local_path.nlri.as_mut().unwrap().nlri else {
        panic!("expected FlowSpec");
    };
    nlri.rules.push(apipb::FlowSpecRule {
        rule: Some(flow_spec_rule::Rule::Component(apipb::FlowSpecComponent {
            r#type: 6,
            items: vec![apipb::FlowSpecComponentItem {
                op: 0x81,
                value: 123,
            }],
        })),
    });
    let added = client
        .add_path(apipb::AddPathRequest {
            table_type: apipb::TableType::Global as i32,
            path: Some(local_path),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let observed = announcer.list_active().await;
    client
        .delete_path(apipb::DeletePathRequest {
            table_type: apipb::TableType::Global as i32,
            family: Some(family),
            uuid: added.uuid,
            ..Default::default()
        })
        .await
        .unwrap();
    announcer.withdraw(&rule).await.unwrap();
    assert!(observed.unwrap_err().to_string().contains("unsupported"));
    announcer
        .list_active()
        .await
        .expect("observation recovers once unsupported local rule is removed");
}
