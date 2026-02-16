use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "safety-mitts", version, about = "Security wrapper for OpenClaw")]
pub struct Cli {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.yaml")]
    pub config: PathBuf,

    /// Path to the policy file (overrides config file setting)
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Path to the OpenClaw binary (overrides config file setting)
    #[arg(long)]
    pub openclaw_bin: Option<PathBuf>,

    /// Listen address (overrides config file setting)
    #[arg(long)]
    pub listen: Option<String>,

    /// Upstream address (overrides config file setting)
    #[arg(long)]
    pub upstream: Option<String>,
}
