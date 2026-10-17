use uuid::Uuid;

use crate::config::{BgpConfig, BgpMode};
use crate::error::{PrefixdError, Result};

/// Configuration identity of a speaker, not proof of remote exclusivity.
/// Credentials, TLS files and controller operation mode are deliberately absent.
#[derive(Clone, PartialEq, Eq)]
pub struct SpeakerTarget {
    pub(crate) backend: &'static str,
    pub(crate) endpoint: String,
    pub(crate) namespace: &'static str,
}

// Keep connection coordinates out of accidental diagnostics and API errors.
impl std::fmt::Debug for SpeakerTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeakerTarget")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl SpeakerTarget {
    pub fn from_config(config: &BgpConfig) -> Result<Self> {
        let (backend, endpoint) = match config.mode {
            BgpMode::Sidecar | BgpMode::Gobgp => ("gobgp", config.gobgp_grpc.as_str()),
            BgpMode::Rustbgpd => (
                "rustbgpd",
                config
                    .rustbgpd
                    .as_ref()
                    .ok_or_else(|| {
                        PrefixdError::Config("rustbgpd speaker configuration is required".into())
                    })?
                    .endpoint
                    .as_str(),
            ),
            BgpMode::Mock => {
                return Ok(Self {
                    backend: "mock",
                    endpoint: "in-process".into(),
                    namespace: "GLOBAL",
                });
            }
        };
        let invalid = || {
            PrefixdError::Config("invalid speaker endpoint: use a credential-free HTTP(S) address without userinfo, query or fragment".into())
        };
        // Reject even empty userinfo/query/fragment and URL-parser whitespace repair.
        if endpoint.is_empty()
            || endpoint.contains(['@', '?', '#'])
            || endpoint.chars().any(char::is_whitespace)
        {
            return Err(invalid());
        }
        let address = if endpoint.contains("://") {
            endpoint.to_owned()
        } else {
            format!("http://{endpoint}")
        };
        let url = reqwest::Url::parse(&address).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        Ok(Self {
            backend,
            endpoint: url.to_string(),
            namespace: "GLOBAL",
        })
    }

    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// Normalized, credential-free endpoint for repository identity storage.
    /// Connection coordinates must stay out of public API responses and diagnostics.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Routing namespace included in the persistent target identity.
    pub fn namespace(&self) -> &'static str {
        self.namespace
    }
}

/// Startup consistency evidence issued by a trusted repository implementation.
/// This is not an authorization token or an interprocess lease.
#[derive(Debug, Clone)]
pub struct VerifiedSpeakerBinding {
    pop: String,
    target_id: Uuid,
    target: SpeakerTarget,
}

impl VerifiedSpeakerBinding {
    /// Issue a binding after repository registration has committed successfully.
    ///
    /// The trusted repository must first persist or validate the POP's exclusive
    /// target assignment and complete any required legacy adoption atomically.
    /// This constructor performs no persistence or ownership verification itself;
    /// callers must not use it to bypass registration.
    pub fn new(pop: String, target_id: Uuid, target: SpeakerTarget) -> Self {
        Self {
            pop,
            target_id,
            target,
        }
    }

    pub fn pop(&self) -> &str {
        &self.pop
    }
    pub fn target_id(&self) -> Uuid {
        self.target_id
    }

    pub fn validate(&self, pop: &str, target: &SpeakerTarget, backend: &str) -> Result<()> {
        if self.pop != pop || self.target != *target || self.target.backend != backend {
            return Err(binding_mismatch());
        }
        Ok(())
    }

    pub fn validate_backend(&self, backend: &str) -> Result<()> {
        if self.target.backend != backend {
            return Err(binding_mismatch());
        }
        Ok(())
    }

    pub fn validate_request(&self, pop: &str, target_id: Option<Uuid>) -> Result<()> {
        if self.pop != pop || target_id != Some(self.target_id) {
            return Err(binding_mismatch());
        }
        Ok(())
    }
}

pub(crate) fn binding_mismatch() -> PrefixdError {
    PrefixdError::Conflict("speaker target ownership is missing or mismatched".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str) -> BgpConfig {
        BgpConfig {
            mode: BgpMode::Sidecar,
            gobgp_grpc: endpoint.into(),
            rustbgpd: None,
            local_asn: 65000,
            router_id: "192.0.2.1".into(),
            neighbors: vec![],
        }
    }

    #[test]
    fn aliases_and_credentials_do_not_change_target_identity() {
        let original = SpeakerTarget::from_config(&config("Speaker.EXAMPLE:50051")).unwrap();
        let mut alias = config("http://speaker.example:50051/");
        alias.mode = BgpMode::Gobgp;
        alias.local_asn = 65001;
        assert_eq!(original, SpeakerTarget::from_config(&alias).unwrap());
        assert_eq!(
            SpeakerTarget::from_config(&config("http://speaker.example:80")).unwrap(),
            SpeakerTarget::from_config(&config("speaker.example")).unwrap()
        );
        assert_eq!(
            SpeakerTarget::from_config(&config("[0:0:0:0:0:0:0:1]:50051")).unwrap(),
            SpeakerTarget::from_config(&config("http://[::1]:50051")).unwrap()
        );
        alias.mode = BgpMode::Rustbgpd;
        alias.rustbgpd = Some(crate::config::RustBgpdConfig {
            endpoint: "https://speaker.example:50051".into(),
            bearer_token_env: "ORIGINAL_TOKEN".into(),
            ca_cert_path: Some("/original.pem".into()),
        });
        let before = SpeakerTarget::from_config(&alias).unwrap();
        alias.rustbgpd.as_mut().unwrap().bearer_token_env = "ROTATED_TOKEN".into();
        alias.rustbgpd.as_mut().unwrap().ca_cert_path = Some("/rotated.pem".into());
        assert_eq!(before, SpeakerTarget::from_config(&alias).unwrap());
        assert_ne!(original, before);
        assert!(!format!("{before:?}").contains("speaker.example"));
    }

    #[test]
    fn endpoint_secrets_and_invalid_addresses_are_rejected_without_echoing_them() {
        for endpoint in [
            "http://secret@host:50051",
            "http://@host:50051",
            "http://host?secret",
            "http://host#secret",
            "http://host?",
            "http://host#",
            "http://host/ secret",
            "unix:///secret",
            "",
        ] {
            let error = SpeakerTarget::from_config(&config(endpoint))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
            assert!(!error.contains(endpoint) || endpoint.is_empty());
        }
    }
}
