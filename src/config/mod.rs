mod inventory;
mod playbooks;
mod settings;

pub use inventory::*;
pub use playbooks::*;
pub use settings::*;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub settings: Settings,
    pub inventory: Inventory,
    pub playbooks: Playbooks,
}

impl AppConfig {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let mut settings = Settings::load(config_dir.join("prefixd.yaml"))?;
        match crate::correlation::CorrelationConfig::load(config_dir.join("correlation.yaml")) {
            Ok(correlation) => settings.correlation = correlation,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        let inventory = Inventory::load(config_dir.join("inventory.yaml"))?;
        let playbooks = Playbooks::load(config_dir.join("playbooks.yaml"))?;

        Ok(Self {
            settings,
            inventory,
            playbooks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let mut settings: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings["correlation"]["confidence_threshold"] = serde_yaml::to_value(0.5).unwrap();
        std::fs::write(
            directory.path().join("prefixd.yaml"),
            serde_yaml::to_string(&settings).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("inventory.yaml"),
            include_str!("../../configs/inventory.yaml"),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("playbooks.yaml"),
            include_str!("../../configs/playbooks.yaml"),
        )
        .unwrap();
        directory
    }

    #[test]
    fn startup_prefers_persisted_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "confidence_threshold: 0.625\n",
        )
        .unwrap();
        let config = AppConfig::load(directory.path()).unwrap();
        assert_eq!(config.settings.correlation.confidence_threshold, 0.625);
    }

    #[test]
    fn startup_uses_inline_correlation_when_standalone_is_absent() {
        let directory = fixture();
        let config = AppConfig::load(directory.path()).unwrap();
        assert_eq!(config.settings.correlation.confidence_threshold, 0.5);
    }

    #[test]
    fn startup_rejects_malformed_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "confidence_threshold: [",
        )
        .unwrap();
        assert!(AppConfig::load(directory.path()).is_err());
    }

    #[test]
    fn startup_rejects_invalid_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "window_seconds: 0\n",
        )
        .unwrap();
        let error = AppConfig::load(directory.path()).unwrap_err();
        assert!(error.to_string().contains("window_seconds must be > 0"));
    }

    #[test]
    fn startup_rejects_unreadable_standalone_correlation() {
        let directory = fixture();
        std::fs::create_dir(directory.path().join("correlation.yaml")).unwrap();
        assert!(AppConfig::load(directory.path()).is_err());
    }

    #[test]
    fn startup_still_validates_inline_settings_before_standalone_override() {
        let directory = fixture();
        let path = directory.path().join("prefixd.yaml");
        let mut settings: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        settings["correlation"]["window_seconds"] = serde_yaml::to_value(0).unwrap();
        std::fs::write(path, serde_yaml::to_string(&settings).unwrap()).unwrap();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "confidence_threshold: 0.625\n",
        )
        .unwrap();
        assert!(AppConfig::load(directory.path()).is_err());
    }
}
