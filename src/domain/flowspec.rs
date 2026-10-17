use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ActionParams, ActionType, MatchCriteria};

/// IP version for FlowSpec rules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSpecNlri {
    pub dst_prefix: String,
    pub protocol: Option<u8>,
    pub dst_ports: Vec<u16>,
}

impl FlowSpecNlri {
    /// Detect IP version from the destination prefix
    pub fn ip_version(&self) -> IpVersion {
        if self.dst_prefix.contains(':') {
            IpVersion::V6
        } else {
            IpVersion::V4
        }
    }

    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        match self.dst_prefix.parse::<ipnet::IpNet>() {
            Ok(prefix) => hasher.update(prefix.to_string().as_bytes()),
            Err(_) => hasher.update(self.dst_prefix.as_bytes()),
        }
        if let Some(proto) = self.protocol {
            hasher.update([proto]);
        }
        let mut sorted_ports = self.dst_ports.clone();
        sorted_ports.sort();
        for port in &sorted_ports {
            hasher.update(port.to_be_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

impl From<&MatchCriteria> for FlowSpecNlri {
    fn from(criteria: &MatchCriteria) -> Self {
        Self {
            dst_prefix: criteria.dst_prefix.clone(),
            protocol: criteria.protocol,
            dst_ports: criteria.dst_ports.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSpecAction {
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<u64>,
}

impl FlowSpecAction {
    pub fn police(rate_bps: u64) -> Self {
        Self {
            action_type: ActionType::Police,
            rate_bps: Some(rate_bps),
        }
    }

    pub fn discard() -> Self {
        Self {
            action_type: ActionType::Discard,
            rate_bps: None,
        }
    }
}

impl From<(ActionType, &ActionParams)> for FlowSpecAction {
    fn from((action_type, params): (ActionType, &ActionParams)) -> Self {
        Self {
            action_type,
            rate_bps: params.rate_bps,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSpecRule {
    pub nlri: FlowSpecNlri,
    pub actions: Vec<FlowSpecAction>,
}

impl FlowSpecRule {
    pub fn new(nlri: FlowSpecNlri, action: FlowSpecAction) -> Self {
        Self {
            nlri,
            actions: vec![action],
        }
    }

    pub fn nlri_hash(&self) -> String {
        self.nlri.compute_hash()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementStatus {
    Pending,
    Announced,
    Withdrawn,
    Failed,
}

impl AnnouncementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Announced => "announced",
            Self::Withdrawn => "withdrawn",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for AnnouncementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_ipv6_prefix_spellings_have_the_same_rule_identity() {
        let mut nlri = FlowSpecNlri {
            dst_prefix: "2001:0DB8:0:0:0:0:0:1/128".into(),
            protocol: Some(6),
            dst_ports: vec![443, 80],
        };
        let hash = nlri.compute_hash();
        nlri.dst_prefix = "2001:db8::1/128".into();
        assert_eq!(nlri.compute_hash(), hash);
        nlri.dst_prefix = "2001:db8::2/128".into();
        assert_ne!(nlri.compute_hash(), hash);
    }
}
