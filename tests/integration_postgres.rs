mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::TestContext;
use prefixd::domain::MitigationStatus;

#[tokio::test]
async fn test_full_event_to_mitigation_flow() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // Ingest an event for a known IP
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "top_dst_ports": [53, 123],
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Verify mitigation was created in the database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    assert_eq!(mitigations[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations[0].status, MitigationStatus::Active);
}

#[tokio::test]
async fn test_mitigation_withdrawal() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // First, create a mitigation via event
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "syn_flood",
        "bps": 100000000,
        "pps": 50000,
        "confidence": 0.9
    }"#;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Get the mitigation ID from the database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    let mitigation_id = mitigations[0].mitigation_id;

    // Withdraw the mitigation
    let withdraw_json = r#"{
        "operator_id": "test_operator",
        "reason": "Integration test withdrawal"
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/mitigations/{}/withdraw", mitigation_id))
                .header("content-type", "application/json")
                .body(Body::from(withdraw_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify mitigation status changed
    let mitigation = ctx
        .repo
        .get_mitigation(mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation not found");

    assert_eq!(mitigation.status, MitigationStatus::Withdrawn);
}

#[tokio::test]
async fn test_pagination() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // Create multiple mitigations by sending events for different IPs
    for i in 10..20 {
        let event_json = format!(
            r#"{{
                "timestamp": "2026-01-17T10:00:00Z",
                "source": "integration_test",
                "victim_ip": "203.0.113.{}",
                "vector": "udp_flood",
                "bps": 100000000,
                "pps": 50000,
                "top_dst_ports": [53],
                "confidence": 0.9
            }}"#,
            i
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(event_json))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Test pagination - get first page
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=5&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 5);

    // Test pagination - get second page
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=5&offset=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 5);
}

#[tokio::test]
async fn test_safelist_blocks_mitigation() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // Add an IP to safelist
    ctx.repo
        .insert_safelist("203.0.113.10/32", "test", Some("Integration test"))
        .await
        .expect("Failed to add safelist entry");

    // Try to create mitigation for safelisted IP
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected due to safelist (422 Unprocessable Entity for guardrail violations)
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Verify no mitigation was created
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 0);
}

#[tokio::test]
async fn test_duplicate_event_extends_ttl() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "top_dst_ports": [53],
        "confidence": 0.95
    }"#;

    // First event creates mitigation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_mitigation_id = json["mitigation_id"].as_str().unwrap();

    // Get original expiry time
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");
    let original_expires_at = mitigations[0].expires_at;

    // Small delay to ensure time difference
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Second event should extend TTL
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Same mitigation should be returned
    assert_eq!(json["mitigation_id"].as_str().unwrap(), first_mitigation_id);
    assert_eq!(json["status"], "extended");

    // Verify TTL was extended
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    assert!(mitigations[0].expires_at > original_expires_at);
}

#[tokio::test]
async fn test_migration_applies_cleanly() {
    // This test verifies that migrations apply cleanly to a fresh database
    // The TestContext::new() already runs migrations, so if we get here without panic, it worked
    let _ctx = TestContext::new().await;

    // Additional verification: ensure all expected tables exist
    // (implicit - we can query mitigations, safelist, etc.)
}

#[tokio::test]
async fn test_timeseries_non_hour_bucket_alignment() {
    use chrono::{Duration, Timelike, Utc};
    use prefixd::domain::{
        ActionParams, ActionType, AttackEvent, AttackVector, MatchCriteria, Mitigation,
        MitigationStatus,
    };
    use uuid::Uuid;

    let ctx = TestContext::new().await;

    let now = Utc::now();
    let base = (now - Duration::minutes(30))
        .with_minute(17)
        .and_then(|dt| dt.with_second(0))
        .and_then(|dt| dt.with_nanosecond(0))
        .unwrap_or(now - Duration::minutes(30));

    let event_one = AttackEvent {
        event_id: Uuid::new_v4(),
        external_event_id: Some("evt-timeseries-1".to_string()),
        source: "integration_test".to_string(),
        event_timestamp: base,
        ingested_at: base,
        victim_ip: "203.0.113.200".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: Some(100_000_000),
        pps: Some(50_000),
        top_dst_ports_json: "[53]".to_string(),
        confidence: Some(0.9),
        action: "ban".to_string(),
        raw_details: None,
    };

    let event_two = AttackEvent {
        event_id: Uuid::new_v4(),
        external_event_id: Some("evt-timeseries-2".to_string()),
        source: "integration_test".to_string(),
        event_timestamp: base + Duration::minutes(6),
        ingested_at: base + Duration::minutes(6),
        victim_ip: "203.0.113.200".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: Some(120_000_000),
        pps: Some(60_000),
        top_dst_ports_json: "[53]".to_string(),
        confidence: Some(0.92),
        action: "ban".to_string(),
        raw_details: None,
    };

    ctx.repo
        .insert_event(&event_one)
        .await
        .expect("failed to insert first event");
    ctx.repo
        .insert_event(&event_two)
        .await
        .expect("failed to insert second event");

    let match_criteria = MatchCriteria {
        dst_prefix: "203.0.113.200/32".to_string(),
        protocol: Some(17),
        dst_ports: vec![53],
    };

    let mitigation = Mitigation {
        mitigation_id: Uuid::new_v4(),
        scope_hash: match_criteria.compute_scope_hash(),
        pop: "test-pop".to_string(),
        customer_id: Some("cust_integration".to_string()),
        service_id: Some("svc_web".to_string()),
        victim_ip: "203.0.113.200".to_string(),
        vector: AttackVector::UdpFlood,
        match_criteria,
        action_type: ActionType::Police,
        action_params: ActionParams {
            rate_bps: Some(10_000_000),
        },
        status: MitigationStatus::Active,
        created_at: base + Duration::minutes(4),
        updated_at: base + Duration::minutes(4),
        expires_at: base + Duration::minutes(64),
        withdrawn_at: None,
        triggering_event_id: event_one.event_id,
        last_event_id: event_two.event_id,
        escalated_from_id: None,
        reason: "timeseries alignment test".to_string(),
        rejection_reason: None,
        acknowledged_at: None,
        acknowledged_by: None,
        signal_group_id: None,
    };

    ctx.repo
        .insert_mitigation(&mitigation)
        .await
        .expect("failed to insert mitigation");

    let event_buckets = ctx
        .repo
        .timeseries_events(2, 5)
        .await
        .expect("failed to query event timeseries");
    let mitigation_buckets = ctx
        .repo
        .timeseries_mitigations(2, 5)
        .await
        .expect("failed to query mitigation timeseries");

    let event_total: i64 = event_buckets.iter().map(|b| b.count).sum();
    let mitigation_total: i64 = mitigation_buckets.iter().map(|b| b.count).sum();
    assert_eq!(event_total, 2);
    assert_eq!(mitigation_total, 1);

    assert!(
        event_buckets
            .iter()
            .any(|b| b.count > 0 && b.bucket.minute() != 0),
        "expected event counts in non-hour buckets"
    );
    assert!(
        mitigation_buckets
            .iter()
            .any(|b| b.count > 0 && b.bucket.minute() != 0),
        "expected mitigation counts in non-hour buckets"
    );
}

#[tokio::test]
async fn test_ttl_expiry() {
    use chrono::{Duration, Utc};
    use prefixd::bgp::{FlowSpecAnnouncer, MockAnnouncer};
    use prefixd::domain::{
        ActionParams, ActionType, AttackVector, FlowSpecAction, FlowSpecNlri, FlowSpecRule,
        MatchCriteria, Mitigation, MitigationStatus,
    };
    use prefixd::scheduler::ReconciliationLoop;
    use std::sync::Arc;
    use uuid::Uuid;

    let ctx = TestContext::new().await;

    // Create a shared MockAnnouncer so we can check withdrawals
    let announcer = Arc::new(MockAnnouncer::new());

    // Pre-announce a rule so we can verify it gets withdrawn
    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "203.0.113.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction::police(10_000_000),
    );
    announcer.announce(&rule).await.expect("Failed to announce");
    assert_eq!(
        announcer.announced_count().await,
        1,
        "Should have 1 announced rule"
    );

    // Create a mitigation with expires_at in the past (already expired)
    let now = Utc::now();
    let expired_at = now - Duration::seconds(60); // 1 minute ago

    let mitigation = Mitigation {
        mitigation_id: Uuid::new_v4(),
        scope_hash: "test_expiry_hash".to_string(),
        pop: "test-pop".to_string(),
        customer_id: Some("cust_test".to_string()),
        service_id: None,
        victim_ip: "203.0.113.99".to_string(),
        vector: AttackVector::UdpFlood,
        match_criteria: MatchCriteria {
            dst_prefix: "203.0.113.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        action_type: ActionType::Police,
        action_params: ActionParams {
            rate_bps: Some(10_000_000),
        },
        status: MitigationStatus::Active, // Active but expired
        created_at: now - Duration::seconds(120),
        updated_at: now - Duration::seconds(60),
        expires_at: expired_at, // Already expired
        withdrawn_at: None,
        triggering_event_id: Uuid::new_v4(),
        last_event_id: Uuid::new_v4(),
        escalated_from_id: None,
        reason: "TTL expiry test".to_string(),
        rejection_reason: None,
        acknowledged_at: None,
        acknowledged_by: None,
        signal_group_id: None,
    };

    // Insert the expired mitigation
    ctx.repo
        .insert_mitigation(&mitigation)
        .await
        .expect("Failed to insert mitigation");

    // Create reconciliation loop and run it (dry_run=false to test withdrawals)
    let reconciler = ReconciliationLoop::new(
        ctx.repo.clone(),
        announcer.clone(),
        30,    // interval doesn't matter, we call reconcile() directly
        false, // NOT dry-run, so withdrawals happen
    );

    // Run reconciliation
    reconciler.reconcile().await.expect("Reconciliation failed");

    // Verify status changed
    let updated = ctx
        .repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation should exist");

    assert_eq!(updated.status, MitigationStatus::Expired);
    assert!(updated.withdrawn_at.is_some());

    // Verify BGP withdrawal happened
    assert_eq!(
        announcer.announced_count().await,
        0,
        "Rule should be withdrawn from announcer"
    );

    // Verify it no longer shows in find_expired (since it's now Expired, not Active)
    let expired_after = ctx
        .repo
        .find_expired_mitigations()
        .await
        .expect("Failed to find expired mitigations");

    assert_eq!(
        expired_after.len(),
        0,
        "Should find 0 expired mitigations after expiry"
    );
}

#[tokio::test]
async fn test_config_hot_reload() {
    use common::write_yaml;

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Write initial inventory with 1 customer
    let initial_inventory = r#"
customers:
  - customer_id: cust_initial
    name: Initial Customer
    prefixes:
      - 10.0.0.0/24
    policy_profile: normal
    services: []
"#;
    write_yaml(temp_dir.path(), "inventory.yaml", initial_inventory);

    // Write initial playbooks with 1 playbook
    let initial_playbooks = r#"
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
      require_top_ports: false
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 60
"#;
    write_yaml(temp_dir.path(), "playbooks.yaml", initial_playbooks);

    // Create context with our config dir
    let ctx = TestContext::with_config_dir(temp_dir.path()).await;

    // Verify initial state
    {
        let inv = ctx.state.inventory.read().await;
        assert_eq!(inv.customers.len(), 1);
        assert_eq!(inv.customers[0].customer_id, "cust_initial");
    }
    {
        let pb = ctx.state.playbooks.read().await;
        assert_eq!(pb.playbooks.len(), 1);
        assert_eq!(pb.playbooks[0].name, "udp_flood");
    }

    // Update inventory with 2 customers
    let updated_inventory = r#"
customers:
  - customer_id: cust_initial
    name: Initial Customer
    prefixes:
      - 10.0.0.0/24
    policy_profile: normal
    services: []
  - customer_id: cust_added
    name: Added Customer
    prefixes:
      - 10.1.0.0/24
    policy_profile: strict
    services: []
"#;
    write_yaml(temp_dir.path(), "inventory.yaml", updated_inventory);

    // Update playbooks with 2 playbooks
    let updated_playbooks = r#"
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
      require_top_ports: false
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 60
  - name: syn_flood
    match:
      vector: syn_flood
      require_top_ports: false
    steps:
      - action: discard
        ttl_seconds: 120
"#;
    write_yaml(temp_dir.path(), "playbooks.yaml", updated_playbooks);

    // Call reload endpoint
    let app = ctx.router().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/config/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Parse response to verify what was reloaded
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let reload_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reloaded = reload_resp["reloaded"].as_array().unwrap();
    assert!(reloaded.iter().any(|v| v == "inventory"));
    assert!(reloaded.iter().any(|v| v == "playbooks"));

    // Verify new config is loaded
    {
        let inv = ctx.state.inventory.read().await;
        assert_eq!(
            inv.customers.len(),
            2,
            "Should have 2 customers after reload"
        );
        assert!(inv.customers.iter().any(|c| c.customer_id == "cust_added"));
    }
    {
        let pb = ctx.state.playbooks.read().await;
        assert_eq!(
            pb.playbooks.len(),
            2,
            "Should have 2 playbooks after reload"
        );
        assert!(pb.playbooks.iter().any(|p| p.name == "syn_flood"));
    }
}

// =============================================================================
// Signal Group Tests (Postgres-backed)
// =============================================================================

#[tokio::test]
async fn test_signal_group_insert_and_find() {
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupStatus};

    let ctx = TestContext::new().await;

    // Create a signal group
    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let inserted = ctx
        .repo
        .insert_signal_group(&group)
        .await
        .expect("Failed to insert signal group");

    assert_eq!(inserted.group_id, group.group_id);
    assert_eq!(inserted.victim_ip, "203.0.113.10");
    assert_eq!(inserted.vector, "udp_flood");
    assert_eq!(inserted.status, SignalGroupStatus::Open);

    // Find the open group
    let found = ctx
        .repo
        .find_open_group("203.0.113.10", "udp_flood")
        .await
        .expect("Failed to find open group");
    assert!(found.is_some());
    assert_eq!(found.unwrap().group_id, group.group_id);

    // Different vector should not find anything
    let not_found = ctx
        .repo
        .find_open_group("203.0.113.10", "syn_flood")
        .await
        .expect("Failed to find open group");
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_signal_group_concurrent_insert_returns_existing() {
    use prefixd::correlation::engine::CorrelationEngine;

    let ctx = TestContext::new().await;

    // Create two groups for the same (victim_ip, vector)
    let group1 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let group2 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);

    let inserted1 = ctx
        .repo
        .insert_signal_group(&group1)
        .await
        .expect("Failed to insert group 1");

    let inserted2 = ctx
        .repo
        .insert_signal_group(&group2)
        .await
        .expect("Failed to insert group 2");

    // Both should return the same group ID (the first one)
    assert_eq!(inserted1.group_id, inserted2.group_id);

    // Count should be 1
    let count = ctx
        .repo
        .count_open_groups()
        .await
        .expect("Failed to count open groups");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_signal_group_truly_concurrent_insert_no_500() {
    use prefixd::correlation::engine::CorrelationEngine;

    let ctx = TestContext::new().await;
    let repo = ctx.repo.clone();

    // Spawn multiple concurrent inserts for the same (victim_ip, vector).
    // This tests the retry-on-conflict logic when the unique index
    // (idx_signal_groups_open_unique) causes a unique violation under true
    // concurrency. All inserts should succeed (return the same group), not 500.
    let mut handles = Vec::new();
    for _ in 0..10 {
        let repo = repo.clone();
        handles.push(tokio::spawn(async move {
            let group = CorrelationEngine::create_group("203.0.113.99", "udp_flood", 300);
            repo.insert_signal_group(&group).await
        }));
    }

    let mut group_ids = Vec::new();
    for handle in handles {
        let result = handle.await.expect("task panicked");
        let group = result.expect("insert_signal_group should not fail (no 500)");
        group_ids.push(group.group_id);
    }

    // All should return the same group ID
    let first = group_ids[0];
    for gid in &group_ids {
        assert_eq!(
            *gid, first,
            "all concurrent inserts should return the same group"
        );
    }

    // Only one open group should exist
    let count = ctx
        .repo
        .count_open_groups()
        .await
        .expect("Failed to count open groups");
    assert_eq!(count, 1, "exactly one open group should exist");
}

#[tokio::test]
async fn test_signal_group_add_events_and_list() {
    use prefixd::correlation::engine::CorrelationEngine;
    use prefixd::domain::AttackEvent;

    let ctx = TestContext::new().await;

    // Create events first
    let event1 = AttackEvent {
        event_id: uuid::Uuid::new_v4(),
        external_event_id: None,
        source: "fastnetmon".to_string(),
        event_timestamp: chrono::Utc::now(),
        ingested_at: chrono::Utc::now(),
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: Some(500_000_000),
        pps: Some(100_000),
        top_dst_ports_json: "[53]".to_string(),
        confidence: Some(0.9),
        action: "ban".to_string(),
        raw_details: None,
    };
    let event2 = AttackEvent {
        event_id: uuid::Uuid::new_v4(),
        external_event_id: None,
        source: "alertmanager".to_string(),
        event_timestamp: chrono::Utc::now(),
        ingested_at: chrono::Utc::now(),
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.7),
        action: "ban".to_string(),
        raw_details: None,
    };

    ctx.repo.insert_event(&event1).await.unwrap();
    ctx.repo.insert_event(&event2).await.unwrap();

    // Create signal group
    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let group = ctx.repo.insert_signal_group(&group).await.unwrap();

    // Add events to group
    let added1 = ctx
        .repo
        .add_event_to_group(group.group_id, event1.event_id, 1.0)
        .await
        .unwrap();
    assert!(added1);

    let added2 = ctx
        .repo
        .add_event_to_group(group.group_id, event2.event_id, 0.8)
        .await
        .unwrap();
    assert!(added2);

    // Duplicate add should return false
    let dup = ctx
        .repo
        .add_event_to_group(group.group_id, event1.event_id, 1.0)
        .await
        .unwrap();
    assert!(!dup);

    // List events in group
    let events = ctx
        .repo
        .list_signal_group_events(group.group_id)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    // Verify denormalized fields
    assert!(
        events
            .iter()
            .any(|e| e.source.as_deref() == Some("fastnetmon"))
    );
    assert!(
        events
            .iter()
            .any(|e| e.source.as_deref() == Some("alertmanager"))
    );
}

#[tokio::test]
async fn test_signal_group_update_and_get() {
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupStatus};

    let ctx = TestContext::new().await;

    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let group = ctx.repo.insert_signal_group(&group).await.unwrap();

    // Update the group
    let mut updated = group.clone();
    updated.derived_confidence = 0.85;
    updated.source_count = 3;
    updated.corroboration_met = true;
    updated.status = SignalGroupStatus::Resolved;

    ctx.repo.update_signal_group(&updated).await.unwrap();

    // Verify via get
    let fetched = ctx
        .repo
        .get_signal_group(group.group_id)
        .await
        .unwrap()
        .expect("Group should exist");

    assert!((fetched.derived_confidence - 0.85).abs() < 0.001);
    assert_eq!(fetched.source_count, 3);
    assert!(fetched.corroboration_met);
    assert_eq!(fetched.status, SignalGroupStatus::Resolved);
}

#[tokio::test]
async fn test_signal_group_list_with_filters() {
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupFilter, SignalGroupStatus};
    use prefixd::db::ListParams;

    let ctx = TestContext::new().await;

    // Create groups with different vectors
    let g1 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    ctx.repo.insert_signal_group(&g1).await.unwrap();

    let g2 = CorrelationEngine::create_group("203.0.113.10", "syn_flood", 300);
    ctx.repo.insert_signal_group(&g2).await.unwrap();

    let g3 = CorrelationEngine::create_group("203.0.113.11", "udp_flood", 300);
    ctx.repo.insert_signal_group(&g3).await.unwrap();

    // List all open groups
    let all = ctx
        .repo
        .list_signal_groups(
            &SignalGroupFilter {
                status: Some(SignalGroupStatus::Open),
                ..Default::default()
            },
            &ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(all.len(), 3);

    // Filter by vector
    let udp = ctx
        .repo
        .list_signal_groups(
            &SignalGroupFilter {
                vector: Some("udp_flood".to_string()),
                ..Default::default()
            },
            &ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(udp.len(), 2);

    // Pagination: limit 2
    let page1 = ctx
        .repo
        .list_signal_groups(
            &SignalGroupFilter::default(),
            &ListParams {
                limit: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    // Count
    let count = ctx.repo.count_open_groups().await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_signal_group_different_vectors_separate() {
    use prefixd::correlation::engine::CorrelationEngine;

    let ctx = TestContext::new().await;

    // Same IP, different vectors → separate groups
    let g1 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let g2 = CorrelationEngine::create_group("203.0.113.10", "syn_flood", 300);

    let inserted1 = ctx.repo.insert_signal_group(&g1).await.unwrap();
    let inserted2 = ctx.repo.insert_signal_group(&g2).await.unwrap();

    // Should be different groups
    assert_ne!(inserted1.group_id, inserted2.group_id);

    let count = ctx.repo.count_open_groups().await.unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_withdrawal_intent_storage_failures_and_controller_restart() {
    use prefixd::{
        AppState,
        bgp::{FlowSpecAnnouncer, MockAnnouncer, PeerStatus},
        db::{Repository, RepositoryTrait, init_postgres_pool},
        domain::{
            ActionParams, ActionType, AttackVector, FlowSpecRule, MatchCriteria, Mitigation,
            MitigationIntent, mitigation_rule, request_withdrawal,
        },
        error::{PrefixdError, Result},
        scheduler::ReconciliationLoop,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    };

    struct Speaker {
        inner: MockAnnouncer,
        mode: AtomicUsize,
        deletes: AtomicUsize,
        adds: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl FlowSpecAnnouncer for Speaker {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.adds.fetch_add(1, SeqCst);
            self.inner.announce(rule).await
        }
        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            self.deletes.fetch_add(1, SeqCst);
            self.inner.withdraw(rule).await?;
            if self.mode.load(SeqCst) == 1 {
                return Err(PrefixdError::BgpWithdrawalFailed(
                    "reply lost after delete".into(),
                ));
            }
            Ok(())
        }
        async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
            self.inner.list_active().await
        }
        async fn session_status(&self) -> Result<Vec<PeerStatus>> {
            Ok(vec![])
        }
    }
    let context = TestContext::new().await;
    let pool = context.pool.clone();
    let connection = context.state.settings.storage.connection_string.clone();
    let repo = Arc::new(Repository::new(pool.clone()));
    let speaker = Arc::new(Speaker {
        inner: MockAnnouncer::new(),
        mode: AtomicUsize::new(0),
        deletes: AtomicUsize::new(0),
        adds: AtomicUsize::new(0),
    });
    let mut mitigation = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test-pop".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            action_type: ActionType::Discard,
            action_params: ActionParams { rate_bps: None },
            ttl_seconds: 600,
            reason: "test".into(),
        },
        "203.0.113.10".into(),
        AttackVector::UdpFlood,
    );
    mitigation.activate();
    repo.insert_mitigation(&mitigation).await.unwrap();
    speaker
        .inner
        .announce(&mitigation_rule(&mitigation))
        .await
        .unwrap();
    let mut settings = common::test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings.clone(),
        common::test_inventory(),
        common::test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let app = prefixd::api::create_test_router(state.clone());
    let withdraw = || {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/mitigations/{}/withdraw",
                mitigation.mitigation_id
            ))
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"operator_id":"forged","reason":"original reason"}"#,
            ))
            .unwrap()
    };
    sqlx::raw_sql("CREATE FUNCTION reject_withdrawal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected storage failure'; END $$; CREATE TRIGGER reject_request BEFORE INSERT ON withdrawal_requests FOR EACH ROW EXECUTE FUNCTION reject_withdrawal();").execute(&pool).await.unwrap();
    assert_eq!(
        app.clone().oneshot(withdraw()).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(speaker.deletes.load(SeqCst), 0);
    assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    sqlx::query("DROP TRIGGER reject_request ON withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    speaker.mode.store(1, SeqCst);
    assert_eq!(
        app.clone().oneshot(withdraw()).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(speaker.deletes.load(SeqCst), 1);
    assert_eq!(speaker.inner.announced_count().await, 0);
    let original = repo.pending_withdrawals(None).await.unwrap().pop().unwrap();
    assert_eq!(original.actor, "anonymous");
    assert_eq!(original.reason, "anonymous: original reason");

    sqlx::query("CREATE TRIGGER reject_completion BEFORE UPDATE ON withdrawal_requests FOR EACH ROW EXECUTE FUNCTION reject_withdrawal()").execute(&pool).await.unwrap();
    speaker.mode.store(0, SeqCst);
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state.clone());
    assert!(reconciler.reconcile().await.is_err());
    assert_eq!(
        repo.get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    assert_eq!(repo.pending_withdrawals(None).await.unwrap().len(), 1);
    let audits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'withdraw'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audits, 0);
    assert_eq!(speaker.adds.load(SeqCst), 0);

    // An unavailable authoritative ledger must fail closed before either cleanup or repair.
    sqlx::query("ALTER TABLE withdrawal_requests RENAME TO hidden_withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    let deletes = speaker.deletes.load(SeqCst);
    assert!(reconciler.reconcile().await.is_err());
    assert_eq!(speaker.deletes.load(SeqCst), deletes);
    assert_eq!(speaker.adds.load(SeqCst), 0);
    sqlx::query("ALTER TABLE hidden_withdrawal_requests RENAME TO withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER reject_completion ON withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    drop(reconciler);
    drop(app);
    drop(state);
    drop(repo);
    pool.close().await;

    // Rebuild the repository and controller with a new pool; no in-memory request is retained.
    let restarted_pool = init_postgres_pool(&connection).await.unwrap();
    let restarted_repo = Arc::new(Repository::new(restarted_pool.clone()));
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        restarted_repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let reconciler = ReconciliationLoop::new(restarted_repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state);
    reconciler.reconcile().await.unwrap();
    let withdrawn = restarted_repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(withdrawn.status, MitigationStatus::Withdrawn);
    assert_eq!(withdrawn.reason, original.reason);
    assert!(
        restarted_repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .is_empty()
    );
    let (actor, details): (String, String) =
        sqlx::query_as("SELECT actor_id, details_json FROM audit_log WHERE action = 'withdraw'")
            .fetch_one(&restarted_pool)
            .await
            .unwrap();
    assert_eq!(actor, "anonymous");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&details).unwrap()["operation_id"],
        original.operation_id.to_string()
    );
    let deletes = speaker.deletes.load(SeqCst);
    reconciler.reconcile().await.unwrap();
    assert_eq!(speaker.deletes.load(SeqCst), deletes);

    // A later lifecycle revision cannot be finalized by an old operation.
    mitigation.mitigation_id = uuid::Uuid::new_v4();
    mitigation.activate();
    restarted_repo.insert_mitigation(&mitigation).await.unwrap();
    let current = restarted_repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    let stale = request_withdrawal(
        restarted_repo.as_ref(),
        &current,
        false,
        "operator",
        "alice",
        "stale".into(),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE mitigations SET updated_at = updated_at + INTERVAL '1 second' WHERE mitigation_id = $1").bind(mitigation.mitigation_id).execute(&restarted_pool).await.unwrap();
    assert!(
        restarted_repo
            .finish_withdrawal(&stale)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restarted_repo
            .get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
}
