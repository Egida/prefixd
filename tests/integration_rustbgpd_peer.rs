//! Released controller/RIB/wire receipt, not router forwarding or enforcement.
#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
#[allow(
    dead_code,
    reason = "this peer target reuses only inventory and session helpers from the shared contract"
)]
#[path = "common/speaker_contract.rs"]
mod contract;
#[path = "common/gobgp.rs"]
mod gobgp;
#[path = "common/peer_receipt.rs"]
mod peer_receipt;
#[path = "common/rustbgpd.rs"]
mod rustbgpd;

use peer_receipt::{wait_go_received, wait_rust_views};
use prefixd::{
    bgp::FlowSpecWriter,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};

fn rules() -> Vec<FlowSpecRule> {
    [
        "192.0.2.240/32",
        "192.0.2.241/32",
        "2001:db8::240/128",
        "2001:db8::241/128",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, prefix)| {
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(if index < 2 { 6 } else { 17 }),
                dst_ports: vec![80, 443],
            },
            if index % 2 == 0 {
                FlowSpecAction::discard()
            } else {
                FlowSpecAction::police(8_000_000)
            },
        )
    })
    .collect()
}

#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn released_peers_receive_exact_routes_and_retain_nonselected_local_intent() {
    let pair = peer_receipt::Pair::start().await;
    let rust = &pair.rust;
    let go = &pair.go;
    let rust_client = rust.connect().await;
    let go_client = go.connect().await;
    contract::wait_peer_state(&rust_client, &rust.peer_address, true)
        .await
        .unwrap();
    contract::wait_peer_state(&go_client, &go.peer_address, true)
        .await
        .unwrap();
    let owned = rules();
    let unrelated = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.250/32".into(),
            protocol: Some(1),
            dst_ports: vec![],
        },
        FlowSpecAction::discard(),
    );
    rust_client.announce(&unrelated).await.unwrap();
    for rule in &owned {
        rust_client.announce(rule).await.unwrap();
    }
    let mut all = owned.clone();
    all.push(unrelated.clone());
    wait_go_received(go, &all).await;
    wait_rust_views(rust, &all, &[]).await;
    for rule in &owned {
        rust_client.withdraw(rule).await.unwrap();
    }
    wait_go_received(go, std::slice::from_ref(&unrelated)).await;
    for rule in &owned {
        rust_client.announce(rule).await.unwrap();
    }
    wait_go_received(go, &all).await;

    // The explicit import policy assigns received routes LOCAL_PREF 200; local injection uses 100.
    let remote: Vec<_> = owned
        .iter()
        .cloned()
        .map(|mut rule| {
            rule.actions = vec![FlowSpecAction::police(32_000_000)];
            rule
        })
        .collect();
    for rule in &remote {
        go_client.announce(rule).await.unwrap();
    }
    wait_rust_views(rust, &all, &remote).await;
    contract::wait_inventory(&rust_client, &all).await.unwrap();
    for rule in &owned {
        rust_client.withdraw(rule).await.unwrap();
    }
    wait_rust_views(rust, std::slice::from_ref(&unrelated), &remote).await;
    for rule in &owned {
        rust_client.announce(rule).await.unwrap();
    }
    wait_rust_views(rust, &all, &remote).await;
    contract::wait_inventory(&rust_client, &all).await.unwrap();
    for rule in &remote {
        go_client.withdraw(rule).await.unwrap();
    }
    wait_rust_views(rust, &all, &[]).await;
    wait_go_received(go, &all).await;
    for rule in &owned {
        rust_client.withdraw(rule).await.unwrap();
    }
    contract::wait_inventory(&rust_client, std::slice::from_ref(&unrelated))
        .await
        .unwrap();
    wait_go_received(go, std::slice::from_ref(&unrelated)).await;
    pair.remove().await;
}

#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn owned_peer_bridge_cleans_up_after_test_failure() {
    let pair = peer_receipt::Pair::start().await;
    let network = pair.network.clone();
    let ids = [
        pair.rust.container.id().to_owned(),
        pair.go.container.id().to_owned(),
    ];
    let result = tokio::spawn(async move {
        let _owned_pair = pair;
        panic!("controlled fixture failure to verify panic-path cleanup");
    })
    .await;
    assert!(result.unwrap_err().is_panic());
    for id in &ids {
        peer_receipt::wait_removed("container", id).await;
    }
    peer_receipt::wait_removed("network", &network).await;
}
