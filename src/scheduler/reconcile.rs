use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::correlation::{CorrelationEngine, SignalGroupStatus};
use crate::db::RepositoryTrait;
use crate::domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, MitigationStatus};
use crate::state::AppState;
use crate::ws::WsMessage;
use tokio::sync::RwLock;

pub struct ReconciliationLoop {
    repo: Arc<dyn RepositoryTrait>,
    announcer: Arc<dyn FlowSpecAnnouncer>,
    interval: Duration,
    dry_run: bool,
    ws_broadcast: Option<broadcast::Sender<WsMessage>>,
    alerting: Option<Arc<RwLock<Arc<AlertingService>>>>,
    /// Shared application state — used by the ADR 022 confidence-decay
    /// refresh path to read the current correlation config + playbooks
    /// on each tick (so hot-reloads propagate without restart). Optional
    /// so test harnesses can construct the loop standalone.
    state: Option<Arc<AppState>>,
    /// Set of source labels we last set on
    /// `CORROBORATOR_CACHE_SIZE`. Used to zero-out gauges when a
    /// source's cache drains to empty between ticks (Prometheus would
    /// otherwise keep the last non-zero value forever).
    last_cache_sources: tokio::sync::Mutex<std::collections::HashSet<String>>,
}

impl ReconciliationLoop {
    pub fn new(
        repo: Arc<dyn RepositoryTrait>,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        interval_seconds: u32,
        dry_run: bool,
    ) -> Self {
        Self {
            repo,
            announcer,
            interval: Duration::from_secs(interval_seconds as u64),
            dry_run,
            ws_broadcast: None,
            alerting: None,
            state: None,
            last_cache_sources: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Wire the shared `AppState` for paths that need live access to the
    /// correlation config or playbooks (currently: ADR 022 confidence
    /// decay refresh). Without this, decay refresh is a no-op and
    /// `derived_confidence` is only updated on event ingest.
    pub fn with_app_state(mut self, state: Arc<AppState>) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the WebSocket broadcast sender for real-time notifications
    pub fn with_ws_broadcast(mut self, sender: broadcast::Sender<WsMessage>) -> Self {
        self.ws_broadcast = Some(sender);
        self
    }

    pub fn with_alerting(mut self, alerting: Arc<RwLock<Arc<AlertingService>>>) -> Self {
        self.alerting = Some(alerting);
        self
    }

    pub async fn run(&self, mut shutdown: broadcast::Receiver<()>) {
        tracing::info!(
            interval_secs = self.interval.as_secs(),
            dry_run = self.dry_run,
            "starting reconciliation loop"
        );

        // Initial reconciliation
        match self.reconcile().await {
            Ok(()) => {
                crate::observability::metrics::RECONCILIATION_RUNS
                    .with_label_values(&["success"])
                    .inc();
            }
            Err(e) => {
                crate::observability::metrics::RECONCILIATION_RUNS
                    .with_label_values(&["error"])
                    .inc();
                tracing::error!(error = %e, "initial reconciliation failed");
            }
        }

        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + self.interval, self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.reconcile().await {
                        Ok(()) => {
                            crate::observability::metrics::RECONCILIATION_RUNS
                                .with_label_values(&["success"])
                                .inc();
                        }
                        Err(e) => {
                            crate::observability::metrics::RECONCILIATION_RUNS
                                .with_label_values(&["error"])
                                .inc();
                            tracing::error!(error = %e, "reconciliation failed");
                        }
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("reconciliation loop shutting down");
                    break;
                }
            }
        }
    }

    /// Run one reconciliation cycle (for testing)
    pub async fn reconcile(&self) -> anyhow::Result<()> {
        // 1. Expire mitigations past TTL
        self.expire_mitigations().await?;

        // 2. Expire signal groups past window
        self.expire_signal_groups().await?;

        // 2b. Sweep expired corroborating signals from the floating cache (ADR 021)
        self.sweep_corroborator_cache().await?;

        // 2c. Refresh decayed confidence on open signal groups (ADR 022).
        // No-op when confidence decay is disabled or wiring isn't present.
        self.refresh_decayed_confidence().await?;

        // 3. Sync desired vs actual state
        self.sync_announcements().await?;

        // 4. Update BGP session metrics
        self.update_bgp_session_metrics().await;

        Ok(())
    }

    async fn expire_mitigations(&self) -> anyhow::Result<()> {
        let expired = self.repo.find_expired_mitigations().await?;
        let mut withdrawal_error = None;

        for mut mitigation in expired {
            tracing::info!(
                mitigation_id = %mitigation.mitigation_id,
                victim_ip = %mitigation.victim_ip,
                "expiring mitigation"
            );

            // Withdraw BGP announcement
            if !self.dry_run {
                let rule = self.build_flowspec_rule(&mitigation);
                let start = std::time::Instant::now();
                if let Err(e) = self.announcer.withdraw(&rule).await {
                    tracing::warn!(
                        mitigation_id = %mitigation.mitigation_id,
                        error = %e,
                        "failed to withdraw expired mitigation"
                    );
                    withdrawal_error = Some(e);
                    continue;
                } else {
                    crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                        .with_label_values(&["withdrawn"])
                        .inc();
                    crate::observability::metrics::ANNOUNCEMENTS_LATENCY
                        .observe(start.elapsed().as_secs_f64());
                }
            }

            // Update status
            let action_type_str = mitigation.action_type.to_string();
            let pop = mitigation.pop.clone();
            mitigation.expire();
            self.repo.update_mitigation(&mitigation).await?;

            crate::observability::metrics::MITIGATIONS_EXPIRED
                .with_label_values(&[&action_type_str, &pop])
                .inc();

            // Broadcast expiry via WebSocket
            if let Some(ref tx) = self.ws_broadcast {
                let _ = tx.send(WsMessage::MitigationExpired {
                    mitigation_id: mitigation.mitigation_id.to_string(),
                });
            }

            if let Some(ref alerting_lock) = self.alerting {
                let alerting = alerting_lock.read().await.clone();
                alerting.notify(crate::alerting::Alert::mitigation_expired(&mitigation));
            }
        }

        // Retain active state for retry and skip sync so an uncertain delete is not re-announced.
        match withdrawal_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    async fn expire_signal_groups(&self) -> anyhow::Result<()> {
        let expired = self.repo.find_expired_signal_groups().await?;

        for mut group in expired {
            tracing::info!(
                group_id = %group.group_id,
                victim_ip = %group.victim_ip,
                vector = %group.vector,
                source_count = group.source_count,
                "expiring signal group (corroboration timeout)"
            );

            group.status = SignalGroupStatus::Expired;
            self.repo.update_signal_group(&group).await?;

            // Increment timeout metric
            crate::observability::metrics::CORROBORATION_TIMEOUT_TOTAL
                .with_label_values(&[&group.vector])
                .inc();

            // Record source count for expired group
            crate::observability::metrics::SIGNAL_GROUP_SOURCES
                .with_label_values(&[&group.vector])
                .observe(group.source_count as f64);
        }

        Ok(())
    }

    async fn sweep_corroborator_cache(&self) -> anyhow::Result<()> {
        // Clean expired rows from the corroborating_signals cache. The
        // repository splits the delete into unattached (per-source) vs
        // attached: only true cache misses (ingested, never matched any
        // group, timed out) charge `CORROBORATOR_EXPIRED_TOTAL{source}`.
        // Attached rows are GC'd silently — their audit trail already
        // lives on signal_group_events.
        //
        // After the sweep we also refresh `CORROBORATOR_CACHE_SIZE{source}`
        // so operators can alert on caches growing without bound.
        let now = chrono::Utc::now();
        let stats = self.repo.delete_expired_corroborating_signals(now).await?;
        let unattached_total = stats.unattached_total();
        let total = unattached_total + stats.attached_expired;
        if total > 0 {
            tracing::info!(
                unattached_expired = unattached_total,
                attached_expired = stats.attached_expired,
                "swept expired corroborating signals from cache"
            );
            for (source, count) in &stats.unattached_expired {
                crate::observability::metrics::CORROBORATOR_EXPIRED_TOTAL
                    .with_label_values(&[source.as_str()])
                    .inc_by(*count as f64);
            }
        }

        // Refresh the cache_size gauge: zero out previous values for
        // sources that no longer have rows, then set per-source counts.
        let by_source = self.repo.count_cached_corroborators_by_source(now).await?;
        let live_sources: std::collections::HashSet<String> =
            by_source.iter().map(|(s, _)| s.clone()).collect();
        let mut last = self.last_cache_sources.lock().await;
        for stale in last.difference(&live_sources) {
            crate::observability::metrics::CORROBORATOR_CACHE_SIZE
                .with_label_values(&[stale.as_str()])
                .set(0.0);
        }
        for (source, count) in &by_source {
            crate::observability::metrics::CORROBORATOR_CACHE_SIZE
                .with_label_values(&[source.as_str()])
                .set(*count as f64);
        }
        *last = live_sources;
        Ok(())
    }

    /// ADR 022: re-compute and persist `derived_confidence` on every open
    /// signal group using the configured exponential half-life. Skipped
    /// when correlation config / playbooks aren't wired (e.g. in tests)
    /// or when decay is disabled (`half_life_seconds == 0`).
    ///
    /// Enforces one-shot `corroboration_met` semantics: a group whose
    /// flag is already true is never flipped back to false by decay,
    /// even if its decayed confidence drops below threshold. Decay only
    /// affects the stored value.
    async fn refresh_decayed_confidence(&self) -> anyhow::Result<()> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };

        let cfg = state.correlation_config.read().await.clone();
        if cfg.confidence_decay_half_life_seconds == 0 {
            return Ok(());
        }

        let groups = self.repo.list_open_signal_groups().await?;
        if groups.is_empty() {
            crate::observability::metrics::SIGNAL_GROUP_DECAY_REFRESHES_TOTAL.inc();
            return Ok(());
        }

        let playbooks = state.playbooks.read().await.clone();
        let now = chrono::Utc::now();

        for group in groups {
            let events = self.repo.list_signal_group_events(group.group_id).await?;
            if events.is_empty() {
                continue;
            }

            let resolved_playbook = group
                .playbook_name
                .as_deref()
                .and_then(|name| playbooks.playbooks.iter().find(|p| p.name == name));
            let override_ = resolved_playbook.and_then(|p| p.correlation.as_ref());
            let half_life = cfg.effective_decay_half_life(override_);
            if half_life == 0 {
                continue;
            }

            let triples: Vec<crate::correlation::ConfidenceTriple> = events
                .iter()
                .map(|e| (e.confidence, e.source_weight, e.ingested_at))
                .collect();
            let new_derived =
                CorrelationEngine::compute_derived_confidence_decayed(&triples, now, half_life);

            // Skip rewrite when nothing meaningful changed (avoids
            // churning the row + WAL on idle groups).
            if (new_derived - group.derived_confidence).abs() < 0.0005 {
                continue;
            }

            let mut updated = group;
            updated.derived_confidence = new_derived;
            // corroboration_met is sticky once true (ADR 022); the field
            // is left as-is. source_count is unaffected by decay.
            self.repo.update_signal_group(&updated).await?;
        }

        crate::observability::metrics::SIGNAL_GROUP_DECAY_REFRESHES_TOTAL.inc();
        Ok(())
    }

    async fn sync_announcements(&self) -> anyhow::Result<()> {
        // Page through all active mitigations using cursor pagination
        let mut active = Vec::new();
        let page_size: u32 = 500;
        let mut cursor = None;
        loop {
            let params = crate::db::ListParams {
                limit: page_size,
                cursor,
                ..Default::default()
            };
            let page = self
                .repo
                .list_mitigations(
                    Some(&[MitigationStatus::Active, MitigationStatus::Escalated]),
                    None,
                    None,
                    None,
                    &params,
                )
                .await?;
            let done = (page.len() as u32) < page_size;
            if let Some(last) = page.last() {
                cursor = Some(last.created_at);
            }
            active.extend(page);
            if done {
                break;
            }
        }

        crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT
            .with_label_values(&["local"])
            .set(active.len() as f64);

        {
            use std::collections::HashMap;
            let mut counts: HashMap<(String, String), f64> = HashMap::new();
            for m in &active {
                *counts
                    .entry((m.action_type.to_string(), m.pop.clone()))
                    .or_default() += 1.0;
            }
            crate::observability::metrics::MITIGATIONS_ACTIVE.reset();
            for ((action_type, pop), count) in &counts {
                crate::observability::metrics::MITIGATIONS_ACTIVE
                    .with_label_values(&[action_type, pop])
                    .set(*count);
            }
        }

        // Get actual state from BGP
        let announced = self.announcer.list_active().await?;
        let announced_hashes: std::collections::HashSet<_> =
            announced.iter().map(|r| r.nlri_hash()).collect();

        let mut repair_error = None;
        // Sequential RPCs keep recovery from creating a concurrent injection burst.
        for mitigation in &active {
            let rule = self.build_flowspec_rule(mitigation);
            let hash = rule.nlri_hash();

            if !announced_hashes.contains(&hash) {
                tracing::warn!(
                    mitigation_id = %mitigation.mitigation_id,
                    nlri_hash = %hash,
                    "re-announcing missing rule"
                );

                if !self.dry_run {
                    let start = std::time::Instant::now();
                    if let Err(e) = self.announcer.announce(&rule).await {
                        crate::observability::metrics::RECONCILIATION_REPAIRS
                            .with_label_values(&["error"])
                            .inc();
                        tracing::error!(
                            mitigation_id = %mitigation.mitigation_id,
                            error = %e,
                            "failed to re-announce"
                        );
                        repair_error = Some(e);
                    } else {
                        crate::observability::metrics::RECONCILIATION_REPAIRS
                            .with_label_values(&["success"])
                            .inc();
                        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                            .with_label_values(&["announced"])
                            .inc();
                        crate::observability::metrics::ANNOUNCEMENTS_LATENCY
                            .observe(start.elapsed().as_secs_f64());
                    }
                }
            }
        }

        // Alert on unknown routes (routes in BGP not tracked by us)
        let desired_hashes: std::collections::HashSet<_> = active
            .iter()
            .map(|m| self.build_flowspec_rule(m).nlri_hash())
            .collect();

        for rule in &announced {
            if !desired_hashes.contains(&rule.nlri_hash()) {
                tracing::warn!(
                    nlri_hash = %rule.nlri_hash(),
                    dst_prefix = %rule.nlri.dst_prefix,
                    "unknown route in BGP RIB"
                );
            }
        }

        match repair_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    async fn update_bgp_session_metrics(&self) {
        match self.announcer.session_status().await {
            Ok(peers) => {
                for peer in &peers {
                    let value = if peer.state.is_established() {
                        1.0
                    } else {
                        0.0
                    };
                    crate::observability::metrics::BGP_SESSION_UP
                        .with_label_values(&[&peer.name])
                        .set(value);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch BGP session status for metrics");
            }
        }
    }

    fn build_flowspec_rule(&self, m: &crate::domain::Mitigation) -> FlowSpecRule {
        let nlri = FlowSpecNlri::from(&m.match_criteria);
        let action = FlowSpecAction::from((m.action_type, &m.action_params));
        FlowSpecRule::new(nlri, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgp::{MockAnnouncer, PeerStatus},
        db::MockRepository,
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
        },
        error::{PrefixdError, Result},
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    struct FailingWithdrawal {
        inner: MockAnnouncer,
        mode: AtomicUsize,
        announcements: AtomicUsize,
        inventories: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl FlowSpecAnnouncer for FailingWithdrawal {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.announcements.fetch_add(1, SeqCst);
            if self.mode.load(SeqCst) == 3 && rule.nlri.dst_prefix == "192.0.2.1/32" {
                return Err(PrefixdError::BgpAnnouncementFailed(
                    "temporary repair failure".into(),
                ));
            }
            self.inner.announce(rule).await
        }

        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            let mode = self.mode.load(SeqCst);
            if rule.nlri.dst_prefix == "192.0.2.1/32" && mode != 0 {
                if mode == 2 {
                    self.inner.withdraw(rule).await?;
                }
                return Err(PrefixdError::BgpWithdrawalFailed(
                    "temporary failure".into(),
                ));
            }
            self.inner.withdraw(rule).await
        }

        async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
            self.inventories.fetch_add(1, SeqCst);
            self.inner.list_active().await
        }

        async fn session_status(&self) -> Result<Vec<PeerStatus>> {
            self.inner.session_status().await
        }
    }

    fn expired_mitigation(ip: &str) -> Mitigation {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/32"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 30,
                reason: "test".into(),
            },
            ip.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        mitigation
    }

    #[tokio::test]
    async fn expiry_retries_failed_withdrawals_without_false_events_or_reannouncement() {
        // Cover rejection before removal and an ambiguous reply after removal.
        for failure_mode in [1, 2] {
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FailingWithdrawal {
                inner: MockAnnouncer::new(),
                mode: AtomicUsize::new(failure_mode),
                announcements: AtomicUsize::new(0),
                inventories: AtomicUsize::new(0),
            });
            let first = expired_mitigation("192.0.2.1");
            let second = expired_mitigation("192.0.2.2");
            let (tx, mut rx) = broadcast::channel(8);
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
                .with_ws_broadcast(tx);
            for mitigation in [&first, &second] {
                repo.insert_mitigation(mitigation).await.unwrap();
                speaker
                    .inner
                    .announce(&reconciler.build_flowspec_rule(mitigation))
                    .await
                    .unwrap();
            }
            assert!(reconciler.reconcile().await.is_err());
            assert_eq!(
                repo.get_mitigation(first.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Active
            );
            assert_eq!(
                repo.get_mitigation(second.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Expired
            );
            assert!(
                matches!(rx.try_recv().unwrap(), WsMessage::MitigationExpired { mitigation_id } if mitigation_id == second.mitigation_id.to_string())
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(speaker.announcements.load(SeqCst), 0);
            assert_eq!(
                speaker.inner.announced_count().await,
                usize::from(failure_mode == 1)
            );

            speaker.mode.store(0, SeqCst);
            reconciler.reconcile().await.unwrap();
            assert_eq!(
                repo.get_mitigation(first.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Expired
            );
            assert!(speaker.list_active().await.unwrap().is_empty());
            assert!(
                matches!(rx.try_recv().unwrap(), WsMessage::MitigationExpired { mitigation_id } if mitigation_id == first.mitigation_id.to_string())
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(speaker.announcements.load(SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn failed_repair_returns_error_but_other_repairs_progress() {
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(3),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        for ip in ["192.0.2.1", "192.0.2.2"] {
            let mut mitigation = expired_mitigation(ip);
            mitigation.expires_at = chrono::Utc::now() + chrono::Duration::seconds(300);
            repo.insert_mitigation(&mitigation).await.unwrap();
        }
        let metrics = &crate::observability::metrics::RECONCILIATION_REPAIRS;
        let failures = metrics.with_label_values(&["error"]).get();
        let successes = metrics.with_label_values(&["success"]).get();
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.announcements.load(SeqCst), 2);
        let actual = speaker.list_active().await.unwrap();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].nlri.dst_prefix, "192.0.2.2/32");
        assert_eq!(metrics.with_label_values(&["error"]).get(), failures + 1.0);
        assert_eq!(
            metrics.with_label_values(&["success"]).get(),
            successes + 1.0
        );
        speaker.mode.store(0, SeqCst);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.list_active().await.unwrap().len(), 2);
        assert_eq!(speaker.announcements.load(SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn startup_runs_once_then_waits_for_the_interval() {
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(0),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let reconciler =
            ReconciliationLoop::new(Arc::new(MockRepository::new()), speaker.clone(), 30, false);
        let (shutdown, rx) = broadcast::channel(1);
        let task = tokio::spawn(async move { reconciler.run(rx).await });
        tokio::task::yield_now().await;
        assert_eq!(speaker.inventories.load(SeqCst), 1);
        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::task::yield_now().await;
        assert_eq!(speaker.inventories.load(SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(speaker.inventories.load(SeqCst), 2);
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }
}
