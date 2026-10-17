use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::bgp::FlowSpecAnnouncer;
use crate::db::RepositoryTrait;
use crate::error::{PrefixdError, Result};

use super::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, Mitigation, MitigationStatus};

/// Immutable deletion intent; an uncertain RPC must never turn it back into an announcement.
#[derive(Debug, Clone, FromRow)]
pub struct WithdrawalRequest {
    pub operation_id: Uuid,
    pub mitigation_id: Uuid,
    pub pop: String,
    pub nlri_hash: String,
    pub rule_json: String,
    pub mitigation_updated_at: DateTime<Utc>,
    pub terminal_status: String,
    pub actor_type: String,
    pub actor: String,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl WithdrawalRequest {
    pub fn new(
        mitigation: &Mitigation,
        expired: bool,
        actor_type: &str,
        actor: &str,
        reason: String,
    ) -> Result<Self> {
        let rule = mitigation_rule(mitigation);
        Ok(Self {
            operation_id: Uuid::new_v4(),
            mitigation_id: mitigation.mitigation_id,
            pop: mitigation.pop.clone(),
            nlri_hash: rule.nlri_hash(),
            rule_json: serde_json::to_string(&rule)?,
            mitigation_updated_at: mitigation.updated_at,
            terminal_status: if expired { "expired" } else { "withdrawn" }.into(),
            actor_type: actor_type.into(),
            actor: actor.into(),
            reason,
            requested_at: Utc::now(),
            completed_at: None,
        })
    }

    pub fn audit_entry(&self) -> crate::observability::AuditEntry {
        use crate::observability::{ActorType, AuditEntry};
        let actor_type = match self.actor_type.as_str() {
            "operator" => ActorType::Operator,
            "detector" => ActorType::Detector,
            _ => ActorType::System,
        };
        AuditEntry::new(
            actor_type,
            Some(self.actor.clone()),
            if self.is_expiry() {
                "expire"
            } else {
                "withdraw"
            },
            Some("mitigation"),
            Some(self.mitigation_id.to_string()),
            serde_json::json!({"reason": self.reason, "operation_id": self.operation_id}),
        )
    }

    pub fn is_expiry(&self) -> bool {
        self.terminal_status == "expired"
    }
}

pub fn mitigation_rule(mitigation: &Mitigation) -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri::from(&mitigation.match_criteria),
        FlowSpecAction::from((mitigation.action_type, &mitigation.action_params)),
    )
}

/// Caller holds the controller's lifecycle mutex through preparation, RPC and finalization.
pub async fn request_withdrawal(
    repo: &dyn RepositoryTrait,
    mitigation: &Mitigation,
    expired: bool,
    actor_type: &str,
    actor: &str,
    reason: String,
) -> Result<WithdrawalRequest> {
    let request = WithdrawalRequest::new(mitigation, expired, actor_type, actor, reason)?;
    check_withdrawal_owner(repo, &request).await?;
    repo.begin_withdrawal(&request).await
}

pub async fn ensure_no_pending_withdrawal(
    repo: &dyn RepositoryTrait,
    pop: &str,
    rule: &FlowSpecRule,
    scope_hash: &str,
) -> Result<()> {
    let pending = repo.pending_withdrawals(Some(pop)).await?;
    let existing = if pending.is_empty() {
        None
    } else {
        repo.find_active_by_scope(scope_hash, pop).await?
    };
    if pending.iter().any(|request| {
        request.nlri_hash == rule.nlri_hash()
            || existing
                .as_ref()
                .is_some_and(|mitigation| request.mitigation_id == mitigation.mitigation_id)
    }) {
        return Err(PrefixdError::Conflict(
            "FlowSpec rule has a pending withdrawal".into(),
        ));
    }
    Ok(())
}

async fn check_withdrawal_owner(
    repo: &dyn RepositoryTrait,
    request: &WithdrawalRequest,
) -> Result<()> {
    let current = repo
        .get_mitigation(request.mitigation_id)
        .await?
        .ok_or(PrefixdError::MitigationNotFound(request.mitigation_id))?;
    if !current.is_active()
        || current.pop != request.pop
        || current.updated_at != request.mitigation_updated_at
        || mitigation_rule(&current).nlri_hash() != request.nlri_hash
    {
        return Err(PrefixdError::Conflict(
            "withdrawal intent no longer matches mitigation".into(),
        ));
    }
    if repo
        .active_mitigations_for_pop(&request.pop)
        .await?
        .iter()
        .any(|owner| {
            owner.mitigation_id != request.mitigation_id
                && mitigation_rule(owner).nlri_hash() == request.nlri_hash
        })
    {
        return Err(PrefixdError::Conflict(
            "FlowSpec rule has another active owner".into(),
        ));
    }
    Ok(())
}

pub async fn execute_withdrawal(
    repo: &dyn RepositoryTrait,
    announcer: &dyn FlowSpecAnnouncer,
    dry_run: bool,
    request: &WithdrawalRequest,
) -> Result<Mitigation> {
    let request = repo
        .pending_withdrawals(Some(&request.pop))
        .await?
        .into_iter()
        .find(|pending| {
            pending.operation_id == request.operation_id
                && pending.mitigation_id == request.mitigation_id
        })
        .ok_or_else(|| {
            PrefixdError::Conflict("withdrawal operation is no longer pending".into())
        })?;
    check_withdrawal_owner(repo, &request).await?;
    let rule: FlowSpecRule = serde_json::from_str(&request.rule_json)?;
    if rule.nlri_hash() != request.nlri_hash {
        return Err(PrefixdError::Internal(
            "withdrawal rule identity does not match persisted intent".into(),
        ));
    }
    let start = std::time::Instant::now();
    if !dry_run {
        announcer.withdraw(&rule).await?;
    }
    let rpc_seconds = start.elapsed().as_secs_f64();
    let mitigation = repo.finish_withdrawal(&request).await?.ok_or_else(|| {
        PrefixdError::Conflict("withdrawal completion no longer matches mitigation".into())
    })?;
    if !dry_run {
        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
            .with_label_values(&["withdrawn"])
            .inc();
        crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(rpc_seconds);
    }
    debug_assert!(matches!(
        mitigation.status,
        MitigationStatus::Withdrawn | MitigationStatus::Expired
    ));
    Ok(mitigation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgp::MockAnnouncer,
        db::MockRepository,
        domain::{ActionParams, ActionType, AttackVector, MatchCriteria, MitigationIntent},
    };

    fn mitigation(prefix: &str) -> Mitigation {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 60,
                reason: "test".into(),
            },
            prefix.split('/').next().unwrap().into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation
    }

    #[tokio::test]
    async fn canonical_shared_owner_blocks_delete_before_intent_or_rpc() {
        let repo = MockRepository::new();
        let first = mitigation("2001:db8::1/128");
        let second = mitigation("2001:0DB8:0:0:0:0:0:1/128");
        repo.insert_mitigation(&first).await.unwrap();
        repo.insert_mitigation(&second).await.unwrap();
        assert_eq!(
            mitigation_rule(&first).nlri_hash(),
            mitigation_rule(&second).nlri_hash()
        );
        assert!(matches!(
            request_withdrawal(&repo, &first, false, "operator", "alice", "test".into()).await,
            Err(PrefixdError::Conflict(_))
        ));
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn scope_alias_cannot_extend_a_pending_withdrawal() {
        let repo = MockRepository::new();
        let mut original = mitigation("192.0.2.1/32");
        original.match_criteria.dst_ports = vec![53, 53];
        original.scope_hash = original.match_criteria.compute_scope_hash();
        repo.insert_mitigation(&original).await.unwrap();
        request_withdrawal(&repo, &original, false, "operator", "alice", "test".into())
            .await
            .unwrap();
        let candidate = mitigation("192.0.2.1/32");
        assert_eq!(candidate.scope_hash, original.scope_hash);
        assert_ne!(
            mitigation_rule(&candidate).nlri_hash(),
            mitigation_rule(&original).nlri_hash()
        );
        assert!(matches!(
            ensure_no_pending_withdrawal(
                &repo,
                "test",
                &mitigation_rule(&candidate),
                &candidate.scope_hash
            )
            .await,
            Err(PrefixdError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn original_operation_and_revision_fence_completion_and_repeated_requests() {
        let repo = MockRepository::new();
        let speaker = MockAnnouncer::new();
        let mut mitigation = mitigation("192.0.2.1/32");
        repo.insert_mitigation(&mitigation).await.unwrap();
        speaker
            .announce(&mitigation_rule(&mitigation))
            .await
            .unwrap();
        let request = request_withdrawal(
            &repo,
            &mitigation,
            false,
            "operator",
            "alice",
            "first reason".into(),
        )
        .await
        .unwrap();
        let repeated = request_withdrawal(
            &repo,
            &mitigation,
            true,
            "system",
            "scheduler",
            "TTL expired".into(),
        )
        .await
        .unwrap();
        assert_eq!(repeated.operation_id, request.operation_id);
        assert_eq!(repeated.actor, "alice");
        assert_eq!(repeated.reason, "first reason");
        assert!(!repeated.is_expiry());
        let mut stale = request.clone();
        stale.operation_id = Uuid::new_v4();
        assert!(repo.finish_withdrawal(&stale).await.unwrap().is_none());
        assert!(
            execute_withdrawal(&repo, &speaker, false, &stale)
                .await
                .is_err()
        );
        assert_eq!(speaker.announced_count().await, 1);
        mitigation.extend_ttl(120, Uuid::new_v4());
        repo.update_mitigation(&mitigation).await.unwrap();
        assert!(repo.finish_withdrawal(&request).await.unwrap().is_none());
        assert!(
            execute_withdrawal(&repo, &speaker, false, &request)
                .await
                .is_err()
        );
        assert_eq!(speaker.announced_count().await, 1);
        assert!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        assert_eq!(repo.pending_withdrawals(None).await.unwrap().len(), 1);
    }
}
