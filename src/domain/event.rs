use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    UdpFlood,
    SynFlood,
    AckFlood,
    IcmpFlood,
    Unknown,
}

impl AttackVector {
    /// IPv4 protocol mapping retained for existing callers.
    pub fn to_protocol(&self) -> Option<u8> {
        match self {
            Self::UdpFlood => Some(17),
            Self::SynFlood | Self::AckFlood => Some(6),
            Self::IcmpFlood => Some(1),
            Self::Unknown => None,
        }
    }

    pub(crate) fn to_protocol_for(self, victim_ip: IpAddr) -> Option<u8> {
        if matches!(self, Self::IcmpFlood) && victim_ip.is_ipv6() {
            Some(58)
        } else {
            self.to_protocol()
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UdpFlood => "udp_flood",
            Self::SynFlood => "syn_flood",
            Self::AckFlood => "ack_flood",
            Self::IcmpFlood => "icmp_flood",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for AttackVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for AttackVector {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp_flood" => Ok(Self::UdpFlood),
            "syn_flood" => Ok(Self::SynFlood),
            "ack_flood" => Ok(Self::AckFlood),
            "icmp_flood" => Ok(Self::IcmpFlood),
            "unknown" => Ok(Self::Unknown),
            _ => Err(format!("unknown vector: {}", s)),
        }
    }
}

fn default_action() -> String {
    "ban".to_string()
}

/// API input for attack events
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttackEventInput {
    #[serde(default)]
    pub event_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub victim_ip: String,
    pub vector: AttackVector,
    #[serde(default)]
    pub bps: Option<i64>,
    #[serde(default)]
    pub pps: Option<i64>,
    #[serde(default)]
    pub top_dst_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub confidence: Option<f32>,
    /// Action type: "ban" (default) or "unban"
    #[serde(default = "default_action")]
    pub action: String,
    /// Raw details from detector for forensics
    #[serde(default)]
    pub raw_details: Option<serde_json::Value>,
}

/// Internal event representation
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct AttackEvent {
    pub event_id: Uuid,
    pub external_event_id: Option<String>,
    pub source: String,
    pub event_timestamp: DateTime<Utc>,
    pub ingested_at: DateTime<Utc>,
    pub victim_ip: String,
    pub vector: String,
    pub protocol: Option<i32>,
    pub bps: Option<i64>,
    pub pps: Option<i64>,
    pub top_dst_ports_json: String,
    pub confidence: Option<f32>,
    pub action: String,
    pub raw_details: Option<serde_json::Value>,
}

impl AttackEvent {
    pub fn from_input(input: AttackEventInput) -> Self {
        let protocol = input
            .victim_ip
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| input.vector.to_protocol_for(ip))
            .map(i32::from);
        let ports = input.top_dst_ports.clone().unwrap_or_default();

        Self {
            event_id: Uuid::new_v4(),
            external_event_id: input.event_id,
            source: input.source,
            event_timestamp: input.timestamp,
            ingested_at: Utc::now(),
            victim_ip: input.victim_ip,
            vector: input.vector.to_string(),
            protocol,
            bps: input.bps,
            pps: input.pps,
            top_dst_ports_json: serde_json::to_string(&ports).unwrap_or_default(),
            confidence: input.confidence,
            action: input.action,
            raw_details: input.raw_details,
        }
    }

    pub fn top_dst_ports(&self) -> Vec<u16> {
        serde_json::from_str(&self.top_dst_ports_json).unwrap_or_default()
    }

    pub fn attack_vector(&self) -> AttackVector {
        self.vector.parse().unwrap_or(AttackVector::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_protocol_tracks_victim_address_family() {
        for (vector, v4_protocol, v6_protocol) in [
            (AttackVector::UdpFlood, Some(17), Some(17)),
            (AttackVector::SynFlood, Some(6), Some(6)),
            (AttackVector::AckFlood, Some(6), Some(6)),
            (AttackVector::IcmpFlood, Some(1), Some(58)),
            (AttackVector::Unknown, None, None),
        ] {
            assert_eq!(vector.to_protocol(), v4_protocol);
            for (victim_ip, protocol) in [
                ("203.0.113.10", v4_protocol),
                ("2001:db8::10", v6_protocol),
                ("2001:0DB8:0000:0000:0000:0000:0000:0010", v6_protocol),
            ] {
                let input = serde_json::from_value(serde_json::json!({
                    "timestamp": "2026-10-17T00:00:00Z",
                    "source": "family-test", "victim_ip": victim_ip, "vector": vector,
                }))
                .unwrap();
                let event = AttackEvent::from_input(input);
                assert_eq!(
                    event.protocol,
                    protocol.map(i32::from),
                    "{vector} {victim_ip}"
                );
            }
        }
    }
}
