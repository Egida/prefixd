use async_trait::async_trait;

use crate::domain::{FlowSpecNlri, FlowSpecRule};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub name: String,
    pub address: String,
    pub state: SessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl SessionState {
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Established)
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connect => write!(f, "connect"),
            Self::Active => write!(f, "active"),
            Self::OpenSent => write!(f, "opensent"),
            Self::OpenConfirm => write!(f, "openconfirm"),
            Self::Established => write!(f, "established"),
        }
    }
}

/// Required mutation contract: announcement is an upsert and withdrawal is idempotent.
/// Implementations must make retrying the same request safe after an ambiguous response.
/// Success acknowledges the backend's local mutation stage, not router enforcement.
#[async_trait]
pub trait FlowSpecWriter: Send + Sync {
    /// Whether both matches address the same backend-local route for upsert and delete.
    /// Writers that normalize match terms must use the same normalization here.
    fn matches_nlri(&self, left: &FlowSpecNlri, right: &FlowSpecNlri) -> Result<bool> {
        let prefix = |nlri: &FlowSpecNlri| {
            nlri.dst_prefix.parse::<ipnet::IpNet>().map_err(|_| {
                crate::error::PrefixdError::BgpAnnouncementFailed(
                    "invalid destination prefix".into(),
                )
            })
        };
        Ok(prefix(left)? == prefix(right)?
            && left.protocol == right.protocol
            && left.dst_ports == right.dst_ports)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()>;
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()>;
}

/// Complete local-rule observation; errors must never become an empty inventory.
/// GoBGP observes accepted local RIB state after import policy; rustbgpd observes
/// retained local injection intent. Neither view proves export or enforcement.
#[async_trait]
pub trait FlowSpecReader: Send + Sync {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>>;
}

#[async_trait]
pub trait PeerObserver: Send + Sync {
    async fn session_status(&self) -> Result<Vec<PeerStatus>>;
}

/// Selected speaker: writing is required, observation is explicitly optional.
/// A production write-only backend still needs a durable reconciliation ledger.
pub trait FlowSpecAnnouncer: FlowSpecWriter {
    fn backend(&self) -> &'static str;

    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        None
    }

    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        None
    }
}

/// Observation availability, not the success of a recent read or rule delivery.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct SpeakerCapabilities {
    pub rule_reader: bool,
    pub peer_observer: bool,
}

impl dyn FlowSpecAnnouncer + '_ {
    pub fn capabilities(&self) -> SpeakerCapabilities {
        SpeakerCapabilities {
            rule_reader: self.reader().is_some(),
            peer_observer: self.peer_observer().is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_match_identity_preserves_port_order_and_duplicate_terms() {
        let writer = crate::bgp::MockAnnouncer::new();
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let left = FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![443, 53],
            };
            assert!(writer.matches_nlri(&left, &left).unwrap());
            let mut right = left.clone();
            if prefix.contains(':') {
                right.dst_prefix = "2001:0DB8:0:0:0:0:0:1/128".into();
                assert!(writer.matches_nlri(&left, &right).unwrap());
            }
            right.dst_ports.reverse();
            assert!(!writer.matches_nlri(&left, &right).unwrap());
            right.dst_ports = vec![443, 53, 53];
            assert!(!writer.matches_nlri(&left, &right).unwrap());
            right.dst_ports = left.dst_ports.clone();
            right.protocol = Some(6);
            assert!(!writer.matches_nlri(&left, &right).unwrap());
            right.dst_prefix = "invalid".into();
            assert!(writer.matches_nlri(&left, &right).is_err());
            assert!(writer.matches_nlri(&right, &left).is_err());
        }
    }
}
