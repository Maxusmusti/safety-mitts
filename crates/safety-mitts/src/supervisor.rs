use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use audit_log::{AuditEntry, AuditEventType, AuditSink, AuditSource};
use net_guard::BindConfig;

/// Configuration for the OpenClaw process supervisor.
pub struct SupervisorConfig {
    /// Path to the OpenClaw binary.
    pub openclaw_bin: PathBuf,
    /// Arguments to pass to the OpenClaw binary.
    pub openclaw_args: Vec<String>,
    /// The internal address OpenClaw should bind to (enforced via env vars).
    pub internal_addr: std::net::SocketAddr,
    /// Maximum number of automatic restarts before the supervisor gives up.
    pub max_restarts: u32,
    /// Delay between restart attempts.
    pub restart_delay: Duration,
}

/// Process supervisor for the OpenClaw child process.
///
/// Spawns OpenClaw with enforced localhost binding, monitors it for
/// unexpected exits, and restarts it up to [`SupervisorConfig::max_restarts`]
/// times. Listens for a shutdown signal to perform graceful termination.
pub struct Supervisor {
    config: SupervisorConfig,
    child: Option<tokio::process::Child>,
    audit: AuditSink,
    shutdown_rx: broadcast::Receiver<()>,
}

impl Supervisor {
    /// Create a new supervisor. The child process is **not** started until
    /// [`start`](Self::start) is called.
    pub fn new(
        config: SupervisorConfig,
        audit: AuditSink,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            config,
            child: None,
            audit,
            shutdown_rx,
        }
    }

    /// Spawn OpenClaw as a child process with enforced localhost binding.
    ///
    /// Environment variables produced by [`net_guard::enforce_bind_env`] are
    /// injected into the child process so that OpenClaw can only bind to the
    /// configured internal address.
    pub async fn start(&mut self) -> Result<()> {
        let bind_config = BindConfig {
            internal_addr: self.config.internal_addr,
        };
        let env_overrides = net_guard::enforce_bind_env(&bind_config);

        info!(
            bin = %self.config.openclaw_bin.display(),
            addr = %self.config.internal_addr,
            "spawning OpenClaw"
        );

        let mut cmd = tokio::process::Command::new(&self.config.openclaw_bin);
        cmd.args(&self.config.openclaw_args)
            .envs(&env_overrides)
            .kill_on_drop(true);

        // On Unix, place the child in its own process group so we can send
        // signals to the entire group for clean shutdown.
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }

        let child = cmd
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn OpenClaw binary: {}",
                    self.config.openclaw_bin.display()
                )
            })?;

        let pid = child.id().unwrap_or(0);
        info!(pid, "OpenClaw process started");

        self.audit
            .log(AuditEntry::new(
                AuditEventType::ProcessStarted,
                AuditSource::new("supervisor"),
                serde_json::json!({
                    "binary": self.config.openclaw_bin.display().to_string(),
                    "pid": pid,
                    "internal_addr": self.config.internal_addr.to_string(),
                }),
            ))
            .await;

        self.child = Some(child);
        Ok(())
    }

    /// Main supervision loop.
    ///
    /// Watches the child process for unexpected exits and restarts it up to
    /// `max_restarts` times. Exits cleanly when a shutdown signal is
    /// received.
    pub async fn supervise(&mut self) -> Result<()> {
        let mut restart_count: u32 = 0;

        loop {
            let child = match self.child.as_mut() {
                Some(c) => c,
                None => {
                    // No child to supervise -- this should only happen if
                    // `start()` was never called or the child was already
                    // taken during shutdown.
                    warn!("no child process to supervise");
                    return Ok(());
                }
            };

            tokio::select! {
                // Child process exited.
                status = child.wait() => {
                    let status = status.context("failed to wait on child process")?;
                    let code = status.code().unwrap_or(-1);

                    warn!(code, "OpenClaw exited unexpectedly");

                    self.audit
                        .log(AuditEntry::new(
                            AuditEventType::ProcessStopped,
                            AuditSource::new("supervisor"),
                            serde_json::json!({
                                "exit_code": code,
                                "restart_count": restart_count,
                            }),
                        ))
                        .await;

                    self.child = None;

                    if restart_count >= self.config.max_restarts {
                        error!(
                            max = self.config.max_restarts,
                            "maximum restart count reached; giving up"
                        );
                        return Err(anyhow::anyhow!(
                            "OpenClaw exceeded maximum restart count ({})",
                            self.config.max_restarts
                        ));
                    }

                    restart_count += 1;
                    info!(
                        attempt = restart_count,
                        delay_secs = self.config.restart_delay.as_secs(),
                        "restarting OpenClaw"
                    );

                    tokio::time::sleep(self.config.restart_delay).await;
                    self.start().await?;
                }

                // Shutdown signal received.
                _ = self.shutdown_rx.recv() => {
                    info!("shutdown signal received; stopping OpenClaw");
                    self.shutdown_child().await?;
                    return Ok(());
                }
            }
        }
    }

    /// Graceful shutdown: send SIGTERM, wait up to 5 seconds, then SIGKILL.
    async fn shutdown_child(&mut self) -> Result<()> {
        let child = match self.child.as_mut() {
            Some(c) => c,
            None => return Ok(()),
        };

        let pid = child.id();

        info!(?pid, "sending SIGTERM to OpenClaw");

        // On Unix, send SIGTERM to the process group. We use
        // nix-style raw signal delivery via the `kill` utility.
        #[cfg(unix)]
        {
            if let Some(raw_pid) = pid {
                // Send SIGTERM to the process group (negative PID).
                let pgid = format!("-{}", raw_pid);
                let kill_result = std::process::Command::new("kill")
                    .args(["-s", "TERM", &pgid])
                    .status();
                match kill_result {
                    Ok(status) if status.success() => {
                        info!("SIGTERM sent to process group");
                    }
                    _ => {
                        // Fall back to sending SIGTERM to just the child.
                        let pid_str = raw_pid.to_string();
                        let _ = std::process::Command::new("kill")
                            .args(["-s", "TERM", &pid_str])
                            .status();
                    }
                }
            } else {
                let _ = child.start_kill();
            }
        }

        // On non-Unix, use Tokio's start_kill which sends the
        // platform-appropriate termination signal.
        #[cfg(not(unix))]
        {
            let _ = child.start_kill();
        }

        // Wait up to 5 seconds for the child to exit.
        let graceful = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;

        match graceful {
            Ok(Ok(status)) => {
                let code = status.code().unwrap_or(-1);
                info!(code, "OpenClaw exited after SIGTERM");

                self.audit
                    .log(AuditEntry::new(
                        AuditEventType::ProcessStopped,
                        AuditSource::new("supervisor"),
                        serde_json::json!({
                            "exit_code": code,
                            "shutdown": "graceful",
                        }),
                    ))
                    .await;
            }
            Ok(Err(e)) => {
                error!(%e, "error waiting for OpenClaw after SIGTERM");
            }
            Err(_) => {
                warn!("OpenClaw did not exit within 5s; sending SIGKILL");
                let _ = child.kill().await;

                self.audit
                    .log(AuditEntry::new(
                        AuditEventType::ProcessStopped,
                        AuditSource::new("supervisor"),
                        serde_json::json!({ "shutdown": "forced (SIGKILL)" }),
                    ))
                    .await;
            }
        }

        self.child = None;
        Ok(())
    }
}
