mod cli;
mod config;
mod supervisor;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use audit_log::{AuditEntry, AuditEventType, AuditSink, AuditSource};
use policy_engine::{PolicyDecision, PolicyEngine, ResolvedAction};
use prompt_sanitizer::{PromptSanitizer, SanitizeMode};
use ws_proxy::{
    ConnectionContext, GatewayMessage, InspectionResult, MessageInspector, Proxy, ProxyConfig,
};

use crate::cli::Cli;
use crate::supervisor::{Supervisor, SupervisorConfig};

// ---------------------------------------------------------------------------
// PolicyInspector
// ---------------------------------------------------------------------------

/// Wraps the [`PolicyEngine`] as a [`MessageInspector`].
///
/// On upstream messages (client -> OpenClaw), if the message is a `Request`
/// whose method looks like a command-execution or agent action, the
/// inspector extracts the command from the params and evaluates it against
/// the loaded policy. Method-level evaluation is also performed.
struct PolicyInspector {
    engine: Arc<PolicyEngine>,
    audit: AuditSink,
}

impl PolicyInspector {
    fn new(engine: Arc<PolicyEngine>, audit: AuditSink) -> Self {
        Self { engine, audit }
    }

    /// Map a [`ResolvedAction`] to an [`InspectionResult`], using the
    /// decision reason as the human-readable string.
    fn map_decision(decision: &PolicyDecision) -> InspectionResult {
        match decision.action {
            ResolvedAction::Allow => InspectionResult::Pass,
            ResolvedAction::AllowWithWarning => {
                InspectionResult::Flag(decision.reason.clone())
            }
            ResolvedAction::Block => {
                InspectionResult::Block(decision.reason.clone())
            }
        }
    }

    /// Try to extract a command string from the JSON params.
    ///
    /// Supports common parameter shapes:
    /// - `{ "command": "..." }`
    /// - `{ "cmd": "..." }`
    /// - `{ "args": ["cmd", "arg1", ...] }`  (joined with spaces)
    fn extract_command(params: &serde_json::Value) -> Option<String> {
        if let Some(cmd) = params.get("command").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        if let Some(cmd) = params.get("cmd").and_then(|v| v.as_str()) {
            return Some(cmd.to_string());
        }
        if let Some(args) = params.get("args").and_then(|v| v.as_array()) {
            let parts: Vec<&str> = args.iter().filter_map(|v| v.as_str()).collect();
            if !parts.is_empty() {
                return Some(parts.join(" "));
            }
        }
        None
    }

    /// Check whether a method name looks like it triggers command execution
    /// or an agent action.
    fn is_exec_method(method: &str) -> bool {
        let lower = method.to_lowercase();
        lower.contains("exec")
            || lower.contains("execute")
            || lower.contains("run")
            || lower.contains("shell")
            || lower.contains("terminal")
            || lower.contains("agent")
            || lower.contains("bash")
            || lower.contains("command")
    }
}

impl MessageInspector for PolicyInspector {
    fn inspect_upstream(
        &self,
        msg: &GatewayMessage,
        ctx: &ConnectionContext,
    ) -> InspectionResult {
        match msg {
            GatewayMessage::Request { method, params, .. } => {
                // 1. Method-level evaluation.
                let method_decision = self.engine.evaluate_method(method, params);
                if method_decision.action == ResolvedAction::Block {
                    log_policy_decision_sync(
                        &self.audit,
                        ctx,
                        method,
                        &method_decision,
                        AuditEventType::ExecBlocked,
                    );
                    return Self::map_decision(&method_decision);
                }

                // 2. If this looks like a command-execution method, evaluate
                //    the command itself.
                if Self::is_exec_method(method) {
                    if let Some(command) = Self::extract_command(params) {
                        let cmd_decision = self.engine.evaluate_command(&command);
                        let event_type = match cmd_decision.action {
                            ResolvedAction::Allow => AuditEventType::ExecAllowed,
                            ResolvedAction::AllowWithWarning => AuditEventType::ExecSoftGated,
                            ResolvedAction::Block => AuditEventType::ExecBlocked,
                        };
                        log_policy_decision_sync(
                            &self.audit,
                            ctx,
                            &command,
                            &cmd_decision,
                            event_type,
                        );
                        return Self::map_decision(&cmd_decision);
                    }
                }

                // 3. Propagate any method-level warnings.
                if method_decision.action == ResolvedAction::AllowWithWarning {
                    log_policy_decision_sync(
                        &self.audit,
                        ctx,
                        method,
                        &method_decision,
                        AuditEventType::ExecSoftGated,
                    );
                    return Self::map_decision(&method_decision);
                }

                InspectionResult::Pass
            }
            // Events and responses from the client are not policy-relevant.
            _ => InspectionResult::Pass,
        }
    }

    fn inspect_downstream(
        &self,
        _msg: &GatewayMessage,
        _ctx: &ConnectionContext,
    ) -> InspectionResult {
        // Policy evaluation is only needed on upstream (client-initiated)
        // messages.
        InspectionResult::Pass
    }
}

/// Fire-and-forget audit log helper. Spawns a background task so we don't
/// need an async context in the synchronous `MessageInspector` trait methods.
fn log_policy_decision_sync(
    audit: &AuditSink,
    ctx: &ConnectionContext,
    subject: &str,
    decision: &PolicyDecision,
    event_type: AuditEventType,
) {
    let audit = audit.clone();
    let source = AuditSource {
        component: "policy-inspector".to_string(),
        origin: ctx.origin.clone(),
        remote_addr: Some(ctx.remote_addr.to_string()),
        session_id: Some(ctx.connection_id.to_string()),
    };
    let details = serde_json::json!({
        "subject": subject,
        "action": format!("{:?}", decision.action),
        "matched_rule": decision.matched_rule,
        "reason": decision.reason,
    });
    let entry = AuditEntry::new(event_type, source, details);
    tokio::spawn(async move {
        audit.log(entry).await;
    });
}

// ---------------------------------------------------------------------------
// SanitizerInspector
// ---------------------------------------------------------------------------

/// Wraps the [`PromptSanitizer`] as a [`MessageInspector`].
///
/// Inspects downstream messages (OpenClaw -> client) for prompt-injection
/// patterns. Depending on the sanitizer mode:
///
/// - **Flag**: findings are logged but the message passes unchanged.
/// - **Strip**: matched injection patterns are replaced with `[REDACTED]`.
/// - **Wrap**: matched patterns are surrounded with safety delimiters.
struct SanitizerInspector {
    sanitizer: Arc<PromptSanitizer>,
    audit: AuditSink,
}

impl SanitizerInspector {
    fn new(sanitizer: Arc<PromptSanitizer>, audit: AuditSink) -> Self {
        Self { sanitizer, audit }
    }

    /// Extract text content from a [`GatewayMessage`] for scanning.
    fn extract_text(msg: &GatewayMessage) -> Option<String> {
        match msg {
            GatewayMessage::Response { body, .. } => {
                // Look for common text fields in the response body.
                if let Some(text) = body.get("result").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                if let Some(text) = body.get("content").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                if let Some(text) = body.get("text").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                // Fall back to the whole body as a string.
                Some(body.to_string())
            }
            GatewayMessage::Event { payload, .. } => {
                if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                if let Some(text) = payload.get("content").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                if let Some(text) = payload.get("data").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                Some(payload.to_string())
            }
            GatewayMessage::Request { params, .. } => {
                if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                if let Some(text) = params.get("content").and_then(|v| v.as_str()) {
                    return Some(text.to_string());
                }
                None
            }
        }
    }

    /// Try to replace text content within a message, producing a modified
    /// copy. Returns `None` if the message shape does not support replacement.
    fn replace_text_in_message(
        msg: &GatewayMessage,
        new_text: &str,
    ) -> Option<GatewayMessage> {
        match msg {
            GatewayMessage::Response { id, ok, body } => {
                let mut body = body.clone();
                // Try each known field in order of preference.
                if body.get("result").and_then(|v| v.as_str()).is_some() {
                    body["result"] = serde_json::Value::String(new_text.to_string());
                } else if body.get("content").and_then(|v| v.as_str()).is_some() {
                    body["content"] = serde_json::Value::String(new_text.to_string());
                } else if body.get("text").and_then(|v| v.as_str()).is_some() {
                    body["text"] = serde_json::Value::String(new_text.to_string());
                }
                Some(GatewayMessage::Response {
                    id: id.clone(),
                    ok: *ok,
                    body,
                })
            }
            GatewayMessage::Event { event, payload } => {
                let mut payload = payload.clone();
                if payload.get("text").and_then(|v| v.as_str()).is_some() {
                    payload["text"] = serde_json::Value::String(new_text.to_string());
                } else if payload.get("content").and_then(|v| v.as_str()).is_some() {
                    payload["content"] = serde_json::Value::String(new_text.to_string());
                } else if payload.get("data").and_then(|v| v.as_str()).is_some() {
                    payload["data"] = serde_json::Value::String(new_text.to_string());
                }
                Some(GatewayMessage::Event {
                    event: event.clone(),
                    payload,
                })
            }
            _ => None,
        }
    }
}

impl MessageInspector for SanitizerInspector {
    fn inspect_upstream(
        &self,
        _msg: &GatewayMessage,
        _ctx: &ConnectionContext,
    ) -> InspectionResult {
        // Prompt-injection scanning is primarily relevant on downstream
        // content (responses from OpenClaw that may contain user-submitted
        // text or tool output). Upstream messages are controlled by the
        // client and evaluated by the PolicyInspector instead.
        InspectionResult::Pass
    }

    fn inspect_downstream(
        &self,
        msg: &GatewayMessage,
        ctx: &ConnectionContext,
    ) -> InspectionResult {
        let text = match Self::extract_text(msg) {
            Some(t) if !t.is_empty() => t,
            _ => return InspectionResult::Pass,
        };

        let result = self.sanitizer.sanitize(&text);

        if !result.has_findings() {
            return InspectionResult::Pass;
        }

        // Log findings via audit.
        let finding_names: Vec<String> = result
            .findings
            .iter()
            .map(|f| f.pattern_name.clone())
            .collect();

        let audit = self.audit.clone();
        let source = AuditSource {
            component: "sanitizer-inspector".to_string(),
            origin: ctx.origin.clone(),
            remote_addr: Some(ctx.remote_addr.to_string()),
            session_id: Some(ctx.connection_id.to_string()),
        };
        let details = serde_json::json!({
            "findings": finding_names,
            "mode": format!("{:?}", self.sanitizer.mode()),
            "finding_count": result.findings.len(),
        });
        let entry = AuditEntry::new(AuditEventType::PromptInjectionDetected, source, details);
        tokio::spawn(async move {
            audit.log(entry).await;
        });

        match self.sanitizer.mode() {
            SanitizeMode::Flag => {
                // Flag mode: report findings but let the message through
                // unmodified.
                let description = format!(
                    "prompt injection detected ({} pattern(s): {})",
                    result.findings.len(),
                    finding_names.join(", ")
                );
                InspectionResult::Flag(description)
            }
            SanitizeMode::Strip | SanitizeMode::Wrap => {
                // Strip/Wrap mode: replace the text content in the message
                // with the sanitized version.
                if let Some(modified_text) = result.modified_text {
                    if let Some(modified_msg) =
                        Self::replace_text_in_message(msg, &modified_text)
                    {
                        return InspectionResult::Modify(modified_msg);
                    }
                }
                // If we could not replace the text in the message structure,
                // fall back to flagging.
                let description = format!(
                    "prompt injection detected but could not modify message ({} pattern(s))",
                    result.findings.len()
                );
                InspectionResult::Flag(description)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Parse CLI args.
    let cli = Cli::parse();

    // 2. Load config, then merge CLI overrides.
    let mut cfg = config::load(&cli.config)?;

    if let Some(ref policy) = cli.policy {
        cfg.policy_file = policy.clone();
    }
    if let Some(ref bin) = cli.openclaw_bin {
        cfg.openclaw.binary = bin.clone();
    }
    if let Some(ref listen) = cli.listen {
        cfg.network.listen_addr = listen.clone();
    }
    if let Some(ref upstream) = cli.upstream {
        cfg.network.upstream_addr = upstream.clone();
    }

    // 3. Init tracing-subscriber with JSON format.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.logging.level));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!(
        config_file = %cli.config.display(),
        policy_file = %cfg.policy_file.display(),
        listen = %cfg.network.listen_addr,
        upstream = %cfg.network.upstream_addr,
        "safety-mitts starting"
    );

    // 4. Start audit logger.
    let (audit, _audit_handle) = AuditSink::start(&cfg.logging.audit_log_path)
        .await
        .context("failed to start audit logger")?;

    audit
        .log(AuditEntry::new(
            AuditEventType::ProcessStarted,
            AuditSource::new("safety-mitts"),
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "config_file": cli.config.display().to_string(),
            }),
        ))
        .await;

    // 5. Load policy engine.
    let policy_config = policy_engine::loader::load_policy(&cfg.policy_file)
        .context("failed to load policy file")?;
    let engine = PolicyEngine::new(policy_config)
        .context("failed to initialize policy engine")?;
    let engine = Arc::new(engine);

    info!(
        policy_file = %cfg.policy_file.display(),
        ?engine,
        "policy engine loaded"
    );

    audit
        .log(AuditEntry::new(
            AuditEventType::PolicyReloaded,
            AuditSource::new("safety-mitts"),
            serde_json::json!({
                "policy_file": cfg.policy_file.display().to_string(),
            }),
        ))
        .await;

    // 6. Create prompt sanitizer.
    let sanitize_mode = match cfg.sanitizer.mode.to_lowercase().as_str() {
        "strip" => SanitizeMode::Strip,
        "wrap" => SanitizeMode::Wrap,
        _ => SanitizeMode::Flag,
    };

    let sanitizer: Arc<PromptSanitizer> = if cfg.sanitizer.enabled {
        Arc::new(
            PromptSanitizer::new(sanitize_mode)
                .context("failed to create prompt sanitizer")?,
        )
    } else {
        // Even when disabled, create a default sanitizer in Flag mode;
        // the SanitizerInspector is simply not added to the inspector chain.
        Arc::new(PromptSanitizer::default())
    };

    info!(
        enabled = cfg.sanitizer.enabled,
        mode = ?sanitize_mode,
        "prompt sanitizer configured"
    );

    // 7. Build inspector chain.
    let mut inspectors: Vec<Arc<dyn MessageInspector>> = Vec::new();

    // Policy inspector is always active.
    inspectors.push(Arc::new(PolicyInspector::new(
        Arc::clone(&engine),
        audit.clone(),
    )));

    // Sanitizer inspector is only active when enabled.
    if cfg.sanitizer.enabled {
        inspectors.push(Arc::new(SanitizerInspector::new(
            Arc::clone(&sanitizer),
            audit.clone(),
        )));
    }

    info!(count = inspectors.len(), "inspector chain built");

    // 8. Set up shutdown signal (ctrl_c + SIGTERM).
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Spawn a task that waits for ctrl-c or SIGTERM and then broadcasts
    // the shutdown signal.
    let shutdown_tx_signal = shutdown_tx.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");

            tokio::select! {
                _ = ctrl_c => {
                    info!("received SIGINT (ctrl-c)");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
            }
        }

        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            info!("received SIGINT (ctrl-c)");
        }

        let _ = shutdown_tx_signal.send(());
    });

    // 9. Create supervisor and start OpenClaw.
    let listen_addr: std::net::SocketAddr = cfg
        .network
        .listen_addr
        .parse()
        .context("invalid listen address")?;
    let upstream_addr: std::net::SocketAddr = cfg
        .network
        .upstream_addr
        .parse()
        .context("invalid upstream address")?;

    let supervisor_config = SupervisorConfig {
        openclaw_bin: cfg.openclaw.binary.clone(),
        openclaw_args: cfg.openclaw.args.clone(),
        internal_addr: upstream_addr,
        max_restarts: cfg.openclaw.max_restarts,
        restart_delay: Duration::from_secs(cfg.openclaw.restart_delay_secs),
    };

    let mut supervisor = Supervisor::new(
        supervisor_config,
        audit.clone(),
        shutdown_tx.subscribe(),
    );
    supervisor
        .start()
        .await
        .context("failed to start OpenClaw")?;

    // 10. Wait for OpenClaw to initialize.
    info!("waiting 2 seconds for OpenClaw to initialize...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 11. Create WebSocket proxy.
    let origin_allowlist = engine
        .config()
        .origin_allowlist
        .clone();

    let proxy_config = ProxyConfig {
        listen_addr,
        upstream_addr,
        origin_allowlist,
        inspectors,
        audit: audit.clone(),
    };
    let proxy = Proxy::new(proxy_config);

    info!(
        listen = %listen_addr,
        upstream = %upstream_addr,
        "starting WebSocket proxy"
    );

    // 12. Run proxy and supervisor concurrently.
    let proxy_result;
    let supervisor_result;

    tokio::select! {
        r = proxy.run() => {
            proxy_result = r;
            info!("WebSocket proxy exited");
            // Signal supervisor to shut down as well.
            let _ = shutdown_tx.send(());
            // Give the supervisor a moment to handle shutdown.
            supervisor_result = Ok(());
        }
        r = supervisor.supervise() => {
            supervisor_result = r;
            info!("supervisor exited");
            // If the supervisor exited (OpenClaw crashed too many times or
            // shutdown was signalled), the proxy should stop too.  The proxy
            // loop will end when the runtime shuts down.
            proxy_result = Ok(());
        }
    }

    // 13. Log shutdown.
    info!("safety-mitts shutting down");

    audit
        .log(AuditEntry::new(
            AuditEventType::ProcessStopped,
            AuditSource::new("safety-mitts"),
            serde_json::json!({
                "proxy_result": format!("{:?}", proxy_result),
                "supervisor_result": format!("{:?}", supervisor_result),
            }),
        ))
        .await;

    // Propagate any errors.
    proxy_result?;
    supervisor_result?;

    Ok(())
}
