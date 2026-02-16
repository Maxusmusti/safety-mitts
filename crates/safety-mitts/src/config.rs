use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub openclaw: OpenClawConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default = "default_policy_file")]
    pub policy_file: PathBuf,
    #[serde(default)]
    pub sanitizer: SanitizerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            openclaw: OpenClawConfig::default(),
            network: NetworkConfig::default(),
            logging: LoggingConfig::default(),
            policy_file: default_policy_file(),
            sanitizer: SanitizerConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OpenClawConfig {
    #[serde(default = "default_binary")]
    pub binary: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    #[serde(default = "default_restart_delay")]
    pub restart_delay_secs: u64,
}

impl Default for OpenClawConfig {
    fn default() -> Self {
        Self {
            binary: default_binary(),
            args: Vec::new(),
            max_restarts: default_max_restarts(),
            restart_delay_secs: default_restart_delay(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_listen")]
    pub listen_addr: String,
    #[serde(default = "default_upstream")]
    pub upstream_addr: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
            upstream_addr: default_upstream(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_audit_path")]
    pub audit_log_path: PathBuf,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            audit_log_path: default_audit_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SanitizerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mode")]
    pub mode: String,
}

impl Default for SanitizerConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            mode: default_mode(),
        }
    }
}

// ---------------------------------------------------------------------------
// Default-value functions used by serde
// ---------------------------------------------------------------------------

fn default_policy_file() -> PathBuf {
    PathBuf::from("policy.yaml")
}

fn default_binary() -> PathBuf {
    PathBuf::from("openclaw")
}

fn default_max_restarts() -> u32 {
    5
}

fn default_restart_delay() -> u64 {
    2
}

fn default_listen() -> String {
    "127.0.0.1:18789".to_string()
}

fn default_upstream() -> String {
    "127.0.0.1:18790".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_audit_path() -> PathBuf {
    PathBuf::from("audit.jsonl")
}

fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "flag".to_string()
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load configuration from a YAML file.
///
/// If the file does not exist a default configuration is returned and a
/// warning is emitted. This allows safety-mitts to start with sensible
/// defaults when no config file has been written yet.
pub fn load(path: &Path) -> anyhow::Result<Config> {
    if !path.exists() {
        warn!(
            path = %path.display(),
            "configuration file not found; using defaults"
        );
        return Ok(Config::default());
    }

    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;

    let config: Config = serde_yml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("failed to parse config file {}: {e}", path.display()))?;

    Ok(config)
}
