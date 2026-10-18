use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use crate::domain::{ActionType, AttackVector, FlowSpecAction};

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Playbooks {
    pub playbooks: Vec<Playbook>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Playbook {
    pub name: String,
    #[serde(rename = "match")]
    pub match_criteria: PlaybookMatch,
    /// Per-playbook correlation override. When present, overrides global
    /// correlation `min_sources` and `confidence_threshold` for events
    /// matching this playbook.
    #[serde(default)]
    pub correlation: Option<crate::correlation::PlaybookCorrelationOverride>,
    pub steps: Vec<PlaybookStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PlaybookMatch {
    pub vector: AttackVector,
    #[serde(default)]
    pub require_top_ports: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PlaybookStep {
    pub action: PlaybookAction,
    #[serde(default)]
    pub rate_bps: Option<u64>,
    pub ttl_seconds: u32,
    #[serde(default)]
    pub require_confidence_at_least: Option<f64>,
    #[serde(default)]
    pub require_persistence_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PlaybookAction {
    Police,
    Discard,
}

impl PlaybookStep {
    pub fn flowspec_action(&self) -> FlowSpecAction {
        FlowSpecAction {
            action_type: match self.action {
                PlaybookAction::Police => ActionType::Police,
                PlaybookAction::Discard => ActionType::Discard,
            },
            rate_bps: self.rate_bps,
        }
    }
}

impl Playbooks {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let playbooks: Playbooks = crate::config::parse_yaml(&content)?;
        playbooks.validate_actions()?;
        Ok(playbooks)
    }

    fn validate_actions(&self) -> Result<()> {
        for (i, playbook) in self.playbooks.iter().enumerate() {
            for (j, step) in playbook.steps.iter().enumerate() {
                step.flowspec_action()
                    .traffic_rate_bytes_per_second()
                    .map_err(|error| {
                        anyhow::anyhow!("playbook[{i}] ({:?}) step[{j}]: {error}", playbook.name)
                    })?;
            }
        }
        Ok(())
    }

    /// Validate all playbook rules, returning a list of errors (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut names = HashSet::new();

        if self.playbooks.is_empty() {
            errors.push("at least one playbook is required".to_string());
            return errors;
        }

        for (i, pb) in self.playbooks.iter().enumerate() {
            let ctx = format!("playbook[{}] ({:?})", i, pb.name);

            if pb.name.is_empty() {
                errors.push(format!("{}: name is required", ctx));
            } else if pb.name.len() > 128 {
                errors.push(format!("{}: name exceeds 128 bytes", ctx));
            } else if !names.insert(&pb.name) {
                errors.push(format!("{}: duplicate name", ctx));
            }

            if pb.steps.is_empty() {
                errors.push(format!("{}: at least one step is required", ctx));
                continue;
            }

            // First step must not have escalation requirements
            if let Some(first) = pb.steps.first() {
                if first.require_confidence_at_least.is_some()
                    || first.require_persistence_seconds.is_some()
                {
                    errors.push(format!(
                        "{}: first step must not have escalation requirements",
                        ctx
                    ));
                }
            }

            for (j, step) in pb.steps.iter().enumerate() {
                let step_ctx = format!("{} step[{}]", ctx, j);

                if step.ttl_seconds == 0 || step.ttl_seconds > 86400 {
                    errors.push(format!(
                        "{}: ttl_seconds must be 1..=86400, got {}",
                        step_ctx, step.ttl_seconds
                    ));
                }

                if let Err(error) = step.flowspec_action().traffic_rate_bytes_per_second() {
                    errors.push(format!("{step_ctx}: {error}"));
                }

                if let Some(conf) = step.require_confidence_at_least {
                    if !(0.0..=1.0).contains(&conf) {
                        errors.push(format!(
                            "{}: require_confidence_at_least must be 0.0..=1.0, got {}",
                            step_ctx, conf
                        ));
                    }
                }
            }
        }

        errors
    }

    /// Save playbooks to a YAML file, creating a .bak backup first.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.validate_actions()?;
        let path = path.as_ref();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid playbooks path"))?;
        let tmp_path = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("playbooks.yaml"),
            uuid::Uuid::new_v4()
        ));

        // Refuse to operate on symlink paths for defense-in-depth.
        if std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(anyhow::anyhow!(
                "refusing to write playbooks through symlink"
            ));
        }

        // Backup existing file
        if path.exists() {
            let bak = path.with_extension("yaml.bak");
            if std::fs::symlink_metadata(&bak)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(anyhow::anyhow!(
                    "refusing to write playbooks backup through symlink"
                ));
            }
            std::fs::copy(path, &bak)?;
        }

        let yaml = serde_saphyr::to_string(self)?;
        let mut tmp_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;

        tmp_file.write_all(yaml.as_bytes())?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })?;

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    pub fn find_playbook(&self, vector: AttackVector, has_ports: bool) -> Option<&Playbook> {
        self.playbooks.iter().find(|p| {
            p.match_criteria.vector == vector && (!p.match_criteria.require_top_ports || has_ports)
        })
    }

    pub fn get_initial_step<'a>(&self, playbook: &'a Playbook) -> Option<&'a PlaybookStep> {
        playbook.steps.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_playbook() -> Playbook {
        Playbook {
            name: "test_playbook".to_string(),
            match_criteria: PlaybookMatch {
                vector: AttackVector::UdpFlood,
                require_top_ports: false,
            },
            correlation: None,
            steps: vec![PlaybookStep {
                action: PlaybookAction::Police,
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
            }],
        }
    }

    #[test]
    fn test_validate_valid_playbooks() {
        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        assert!(pb.validate().is_empty());
    }

    #[test]
    fn test_validate_empty_playbooks() {
        let pb = Playbooks { playbooks: vec![] };
        let errors = pb.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("at least one playbook"));
    }

    #[test]
    fn test_validate_duplicate_names() {
        let mut p1 = valid_playbook();
        let mut p2 = valid_playbook();
        p1.name = "dup".to_string();
        p2.name = "dup".to_string();
        p2.match_criteria.vector = AttackVector::SynFlood;
        let pb = Playbooks {
            playbooks: vec![p1, p2],
        };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("duplicate name")));
    }

    #[test]
    fn test_validate_empty_steps() {
        let mut p = valid_playbook();
        p.steps.clear();
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("at least one step")));
    }

    #[test]
    fn test_validate_police_requires_rate() {
        let mut p = valid_playbook();
        p.steps[0].rate_bps = None;
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("requires rate_bps")));
    }

    #[test]
    fn action_validation_covers_load_save_and_later_steps() {
        for (action, rate) in [
            (PlaybookAction::Police, None),
            (PlaybookAction::Police, Some(0)),
            (PlaybookAction::Police, Some(16_777_217)),
            (PlaybookAction::Police, Some(u64::MAX)),
            (PlaybookAction::Discard, Some(0)),
            (PlaybookAction::Discard, Some(8)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("playbooks.yaml");
            let original = Playbooks {
                playbooks: vec![valid_playbook()],
            };
            original.save(&path).unwrap();
            let original_bytes = std::fs::read(&path).unwrap();
            let mut invalid = original;
            let mut step = invalid.playbooks[0].steps[0].clone();
            step.action = action;
            step.rate_bps = rate;
            invalid.playbooks[0].steps.push(step);
            assert!(!invalid.validate().is_empty());
            assert!(invalid.save(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
            assert!(!path.with_extension("yaml.bak").exists());
            std::fs::write(&path, serde_saphyr::to_string(&invalid).unwrap()).unwrap();
            assert!(
                Playbooks::load(&path)
                    .unwrap_err()
                    .to_string()
                    .contains("step[1]")
            );
        }
        for rate in [1, 7, 8, 9, 16_777_216, 16_777_218, 1_000_000_000] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("playbooks.yaml");
            let mut valid = Playbooks {
                playbooks: vec![valid_playbook()],
            };
            valid.playbooks[0].steps[0].rate_bps = Some(rate);
            assert!(valid.validate().is_empty());
            valid.save(&path).unwrap();
            assert_eq!(
                Playbooks::load(&path).unwrap().playbooks[0].steps[0].rate_bps,
                Some(rate)
            );
        }
    }

    #[test]
    fn test_validate_ttl_bounds() {
        let mut p = valid_playbook();
        p.steps[0].ttl_seconds = 0;
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("ttl_seconds")));

        let mut p2 = valid_playbook();
        p2.steps[0].ttl_seconds = 86401;
        let pb2 = Playbooks {
            playbooks: vec![p2],
        };
        assert!(!pb2.validate().is_empty());
    }

    #[test]
    fn test_validate_confidence_bounds() {
        let mut p = valid_playbook();
        p.steps.push(PlaybookStep {
            action: PlaybookAction::Discard,
            rate_bps: None,
            ttl_seconds: 300,
            require_confidence_at_least: Some(1.5),
            require_persistence_seconds: None,
        });
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("confidence")));
    }

    #[test]
    fn test_validate_first_step_no_escalation() {
        let mut p = valid_playbook();
        p.steps[0].require_confidence_at_least = Some(0.5);
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("first step")));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        pb.save(&path).unwrap();
        let loaded = Playbooks::load(&path).unwrap();
        assert_eq!(loaded.playbooks.len(), 1);
        assert_eq!(loaded.playbooks[0].name, "test_playbook");
    }

    #[test]
    fn test_save_creates_backup() {
        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        // First save (no backup yet)
        pb.save(&path).unwrap();
        assert!(!dir.path().join("playbooks.yaml.bak").exists());
        // Second save creates backup
        pb.save(&path).unwrap();
        assert!(dir.path().join("playbooks.yaml.bak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_save_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.yaml");
        std::fs::write(&target, "playbooks: []").unwrap();
        let link = dir.path().join("playbooks.yaml");
        symlink(&target, &link).unwrap();

        assert!(pb.save(&link).is_err());
    }

    #[test]
    fn test_playbook_without_correlation_override() {
        let yaml = r#"
playbooks:
  - name: test
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 5000000
        ttl_seconds: 120
"#;
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).unwrap();
        assert!(playbooks.playbooks[0].correlation.is_none());
    }

    #[test]
    fn test_playbook_with_correlation_override() {
        let yaml = r#"
playbooks:
  - name: corroborated_udp
    match:
      vector: udp_flood
    correlation:
      min_sources: 2
      confidence_threshold: 0.7
    steps:
      - action: police
        rate_bps: 5000000
        ttl_seconds: 120
"#;
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).unwrap();
        let corr = playbooks.playbooks[0].correlation.as_ref().unwrap();
        assert_eq!(corr.min_sources, Some(2));
        assert_eq!(corr.confidence_threshold, Some(0.7));
    }

    #[test]
    fn test_playbook_with_partial_correlation_override() {
        let yaml = r#"
playbooks:
  - name: partial_override
    match:
      vector: syn_flood
    correlation:
      min_sources: 3
    steps:
      - action: discard
        ttl_seconds: 300
"#;
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).unwrap();
        let corr = playbooks.playbooks[0].correlation.as_ref().unwrap();
        assert_eq!(corr.min_sources, Some(3));
        assert_eq!(corr.confidence_threshold, None);
    }

    #[test]
    fn test_playbook_roundtrip_with_correlation() {
        use crate::correlation::PlaybookCorrelationOverride;

        let pb = Playbooks {
            playbooks: vec![Playbook {
                name: "test_corr".to_string(),
                match_criteria: PlaybookMatch {
                    vector: AttackVector::UdpFlood,
                    require_top_ports: false,
                },
                correlation: Some(PlaybookCorrelationOverride {
                    min_sources: Some(2),
                    confidence_threshold: Some(0.8),
                    ..Default::default()
                }),
                steps: vec![PlaybookStep {
                    action: PlaybookAction::Police,
                    rate_bps: Some(5_000_000),
                    ttl_seconds: 120,
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                }],
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        pb.save(&path).unwrap();
        let loaded = Playbooks::load(&path).unwrap();
        let corr = loaded.playbooks[0].correlation.as_ref().unwrap();
        assert_eq!(corr.min_sources, Some(2));
        assert_eq!(corr.confidence_threshold, Some(0.8));
    }
}
