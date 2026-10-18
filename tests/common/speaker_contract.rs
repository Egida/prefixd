//! Shared contract for complete local observation; this is not router enforcement.
use anyhow::{Context, Result, ensure};
use prefixd::{
    bgp::FlowSpecAnnouncer,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};
use std::time::Duration;

pub fn contract_rules() -> Vec<FlowSpecRule> {
    [
        (
            "192.0.2.240/32",
            Some(6),
            vec![443, 80, 53, 22, 123, 8080, 8443, 25],
        ),
        (
            "2001:0DB8:0:0:0:0:0:240/128",
            Some(17),
            vec![443, 80, 53, 22, 123, 8080, 8443, 25],
        ),
        ("192.0.2.241/32", None, vec![]),
        ("2001:db8::241/128", None, vec![]),
        ("192.0.2.242/32", Some(1), vec![]),
        ("2001:db8::242/128", Some(58), vec![]),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (prefix, protocol, dst_ports))| {
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol,
                dst_ports,
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

pub fn exact_inventory(actual: &[FlowSpecRule], expected: &[FlowSpecRule]) -> Result<()> {
    ensure!(
        actual.len() == expected.len(),
        "inventory cardinality: expected {}, observed {}",
        expected.len(),
        actual.len()
    );
    for wanted in expected {
        let matching: Vec<_> = actual
            .iter()
            .filter(|rule| rule.nlri_hash() == wanted.nlri_hash())
            .collect();
        ensure!(
            matching.len() == 1,
            "expected one NLRI {}, observed {}",
            wanted.nlri.dst_prefix,
            matching.len()
        );
        let found = matching[0];
        ensure!(
            found.nlri.dst_prefix.parse::<ipnet::IpNet>()?
                == wanted.nlri.dst_prefix.parse::<ipnet::IpNet>()?,
            "destination prefix mismatch"
        );
        ensure!(
            found.nlri.protocol == wanted.nlri.protocol,
            "protocol mismatch for {}",
            wanted.nlri.dst_prefix
        );
        let mut actual_ports = found.nlri.dst_ports.clone();
        let mut expected_ports = wanted.nlri.dst_ports.clone();
        actual_ports.sort_unstable();
        expected_ports.sort_unstable();
        ensure!(
            actual_ports == expected_ports,
            "destination ports mismatch for {}",
            wanted.nlri.dst_prefix
        );
        ensure!(
            found.actions.len() == wanted.actions.len(),
            "action cardinality mismatch for {}",
            wanted.nlri.dst_prefix
        );
        for (observed, expected) in found.actions.iter().zip(&wanted.actions) {
            ensure!(
                observed.action_type == expected.action_type
                    && observed.rate_bps == expected.rate_bps,
                "actions mismatch for {}: expected {:?}, observed {:?}",
                wanted.nlri.dst_prefix,
                wanted.actions,
                found.actions
            );
        }
    }
    Ok(())
}

pub async fn wait_inventory(
    speaker: &dyn FlowSpecAnnouncer,
    expected: &[FlowSpecRule],
) -> Result<()> {
    let reader = speaker
        .reader()
        .context("readable contract requires a rule reader")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let actual = tokio::time::timeout(Duration::from_secs(5), reader.list_active())
            .await
            .context("complete local inventory deadline")?
            .context("complete local inventory failed")?;
        match exact_inventory(&actual, expected) {
            Ok(()) => return Ok(()),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

pub async fn run_readable_contract(speaker: &dyn FlowSpecAnnouncer) -> Result<()> {
    wait_inventory(speaker, &[])
        .await
        .context("isolated initial inventory")?;
    let mut rules = contract_rules();
    for rule in &rules {
        speaker.announce(rule).await.context("announce")?;
        speaker.announce(rule).await.context("duplicate announce")?;
    }
    wait_inventory(speaker, &rules)
        .await
        .context("dual-family idempotent announce")?;
    for rule in &mut rules {
        rule.actions = match rule.actions[0].action_type {
            prefixd::domain::ActionType::Discard => vec![FlowSpecAction::police(16_000_000)],
            _ => vec![FlowSpecAction::discard()],
        };
        speaker.announce(rule).await.context("replace action")?;
        speaker
            .announce(rule)
            .await
            .context("duplicate replacement")?;
    }
    wait_inventory(speaker, &rules)
        .await
        .context("replacement preserves NLRI and exact actions")?;
    if let Some(observer) = speaker.peer_observer() {
        observer
            .session_status()
            .await
            .context("available peer observation")?;
    }
    for rule in &rules {
        speaker.withdraw(rule).await.context("withdraw")?;
        speaker.withdraw(rule).await.context("duplicate withdraw")?;
    }
    wait_inventory(speaker, &[])
        .await
        .context("idempotent withdrawal")?;
    for rule in &rules {
        speaker
            .announce(rule)
            .await
            .context("re-announce after withdrawal")?;
    }
    wait_inventory(speaker, &rules)
        .await
        .context("re-announcement")?;
    for rule in &rules {
        speaker.withdraw(rule).await?;
    }
    wait_inventory(speaker, &[])
        .await
        .context("final inventory")
}

#[allow(
    dead_code,
    reason = "Only peered backend targets exercise peer state transitions."
)]
pub async fn wait_peer_state(
    speaker: &dyn FlowSpecAnnouncer,
    address: &str,
    established: bool,
) -> Result<()> {
    let observer = speaker
        .peer_observer()
        .context("peer qualification requires observation")?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let peers = observer.session_status().await?;
            if peers.len() == 1
                && peers[0].address == address
                && peers[0].state.is_established() == established
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("bounded peer state transition")?
}
