use std::net::SocketAddr;
use std::sync::Arc;

use audit_log::{AuditEntry, AuditEventType, AuditSink, AuditSource};
use futures_util::{SinkExt, StreamExt};
use http::StatusCode;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HsRequest, Response as HsResponse,
};
use tokio_tungstenite::tungstenite::Message;

use crate::origin;
use crate::relay::{ConnectionContext, GatewayMessage, InspectionResult, MessageInspector};

/// Configuration for the WebSocket reverse proxy.
pub struct ProxyConfig {
    /// Address to bind the listening socket to.
    pub listen_addr: SocketAddr,
    /// Address of the upstream OpenClaw WebSocket server.
    pub upstream_addr: SocketAddr,
    /// Allowed origin patterns (glob-style with `*`).
    pub origin_allowlist: Vec<String>,
    /// Ordered list of message inspectors. Each message is passed through
    /// every inspector in sequence.
    pub inspectors: Vec<Arc<dyn MessageInspector>>,
    /// Audit log sink for recording connection and message events.
    pub audit: AuditSink,
}

/// The WebSocket reverse proxy server.
///
/// Accepts client WebSocket connections, validates their `Origin` header,
/// opens a matching connection to the upstream OpenClaw server, and relays
/// messages bidirectionally while running each message through the configured
/// [`MessageInspector`] chain.
pub struct Proxy {
    config: Arc<ProxyConfig>,
}

impl Proxy {
    /// Create a new proxy with the given configuration.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Run the proxy server.
    ///
    /// This method binds to `listen_addr` and loops forever accepting
    /// connections. Each connection is handled in its own Tokio task.
    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        tracing::info!(addr = %self.config.listen_addr, "ws-proxy listening");

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let config = Arc::clone(&self.config);

            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, remote_addr, config).await {
                    tracing::error!(%remote_addr, %err, "connection handler error");
                }
            });
        }
    }
}

/// Handle a single TCP connection from accept through WebSocket relay and
/// teardown.
async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    config: Arc<ProxyConfig>,
) -> anyhow::Result<()> {
    let connection_id = uuid::Uuid::new_v4();

    // ------------------------------------------------------------------
    // 1. Accept the WebSocket handshake, capturing and validating the
    //    Origin header via the callback.
    // ------------------------------------------------------------------
    let captured_origin: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let captured_origin_cb = Arc::clone(&captured_origin);
    let allowlist = config.origin_allowlist.clone();

    let callback =
        move |req: &HsRequest, response: HsResponse| -> Result<HsResponse, ErrorResponse> {
            // Extract the Origin header value if present.
            let origin_value = req
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Store captured origin for later use.
            if let Ok(mut guard) = captured_origin_cb.lock() {
                *guard = origin_value.clone();
            }

            // Validate the origin.
            let origin_str = origin_value.as_deref();
            if let Err(rejection) = origin::validate_origin(origin_str, &allowlist) {
                tracing::warn!(
                    %remote_addr,
                    ?rejection,
                    "origin rejected"
                );
                let mut err_response =
                    ErrorResponse::new(Some("Origin not allowed".to_string()));
                *err_response.status_mut() = StatusCode::FORBIDDEN;
                return Err(err_response);
            }

            Ok(response)
        };

    let client_ws = match tokio_tungstenite::accept_hdr_async(stream, callback).await {
        Ok(ws) => ws,
        Err(err) => {
            // If the handshake failed due to origin rejection, log it.
            let origin_val = captured_origin
                .lock()
                .ok()
                .and_then(|g| g.clone());

            config
                .audit
                .log(AuditEntry::new(
                    AuditEventType::OriginRejected,
                    make_source(connection_id, remote_addr, origin_val.as_deref()),
                    serde_json::json!({
                        "error": err.to_string(),
                    }),
                ))
                .await;

            return Err(err.into());
        }
    };

    let origin = captured_origin
        .lock()
        .ok()
        .and_then(|g| g.clone());

    tracing::info!(
        %connection_id,
        %remote_addr,
        origin = origin.as_deref().unwrap_or("<none>"),
        "client connected"
    );

    // Audit: connection opened.
    config
        .audit
        .log(AuditEntry::new(
            AuditEventType::ConnectionOpened,
            make_source(connection_id, remote_addr, origin.as_deref()),
            serde_json::json!({
                "remote_addr": remote_addr.to_string(),
            }),
        ))
        .await;

    // ------------------------------------------------------------------
    // 2. Connect to the upstream OpenClaw server.
    // ------------------------------------------------------------------
    let upstream_url = format!("ws://{}", config.upstream_addr);
    let (upstream_ws, _) = tokio_tungstenite::connect_async(&upstream_url).await?;

    tracing::debug!(%connection_id, upstream = %upstream_url, "upstream connected");

    // ------------------------------------------------------------------
    // 3. Split both WebSocket connections and run bidirectional relay.
    // ------------------------------------------------------------------
    let (client_write, client_read) = client_ws.split();
    let (upstream_write, upstream_read) = upstream_ws.split();

    let ctx = Arc::new(ConnectionContext {
        connection_id,
        remote_addr,
        origin: origin.clone(),
    });

    // client -> upstream
    let inspectors_up = config.inspectors.clone();
    let audit_up = config.audit.clone();
    let ctx_up = Arc::clone(&ctx);

    let up_task = tokio::spawn(relay_messages(
        client_read,
        upstream_write,
        inspectors_up,
        audit_up,
        ctx_up,
        Direction::Upstream,
    ));

    // upstream -> client
    let inspectors_down = config.inspectors.clone();
    let audit_down = config.audit.clone();
    let ctx_down = Arc::clone(&ctx);

    let down_task = tokio::spawn(relay_messages(
        upstream_read,
        client_write,
        inspectors_down,
        audit_down,
        ctx_down,
        Direction::Downstream,
    ));

    // Wait for either direction to finish (usually means one side closed).
    tokio::select! {
        result = up_task => {
            if let Err(err) = result {
                tracing::debug!(%connection_id, %err, "upstream relay task ended");
            }
        }
        result = down_task => {
            if let Err(err) = result {
                tracing::debug!(%connection_id, %err, "downstream relay task ended");
            }
        }
    }

    tracing::info!(%connection_id, %remote_addr, "connection closed");

    // Audit: connection closed.
    config
        .audit
        .log(AuditEntry::new(
            AuditEventType::ConnectionClosed,
            make_source(connection_id, remote_addr, origin.as_deref()),
            serde_json::json!({
                "remote_addr": remote_addr.to_string(),
            }),
        ))
        .await;

    Ok(())
}

/// Direction of message flow, used for choosing the right inspector method.
#[derive(Debug, Clone, Copy)]
enum Direction {
    /// Client -> OpenClaw
    Upstream,
    /// OpenClaw -> Client
    Downstream,
}

/// Relay messages from a reader half to a writer half, running each text
/// message through the inspector chain.
async fn relay_messages<R, W>(
    mut reader: R,
    mut writer: W,
    inspectors: Vec<Arc<dyn MessageInspector>>,
    audit: AuditSink,
    ctx: Arc<ConnectionContext>,
    direction: Direction,
) where
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    W: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    while let Some(msg_result) = reader.next().await {
        let msg = match msg_result {
            Ok(msg) => msg,
            Err(err) => {
                tracing::debug!(
                    connection_id = %ctx.connection_id,
                    ?direction,
                    %err,
                    "read error, closing relay"
                );
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                // Try to parse as a GatewayMessage for inspection.
                match serde_json::from_str::<GatewayMessage>(&text) {
                    Ok(gateway_msg) => {
                        let outcome =
                            run_inspectors(&inspectors, &gateway_msg, &ctx, direction);

                        match outcome {
                            InspectionOutcome::Pass => {
                                // Forward the original text unchanged to avoid
                                // any serialization differences.
                                if writer.send(Message::Text(text)).await.is_err() {
                                    break;
                                }
                            }
                            InspectionOutcome::Modify(modified) => {
                                match serde_json::to_string(&modified) {
                                    Ok(json) => {
                                        if writer.send(Message::Text(json.into())).await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!(
                                            %err,
                                            "failed to serialize modified message"
                                        );
                                        // Fall back to forwarding the original.
                                        if writer.send(Message::Text(text)).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            InspectionOutcome::Block(reason) => {
                                tracing::warn!(
                                    connection_id = %ctx.connection_id,
                                    ?direction,
                                    %reason,
                                    "message blocked"
                                );
                                audit
                                    .log(AuditEntry::new(
                                        AuditEventType::ExecBlocked,
                                        make_source(
                                            ctx.connection_id,
                                            ctx.remote_addr,
                                            ctx.origin.as_deref(),
                                        ),
                                        serde_json::json!({
                                            "direction": format!("{:?}", direction),
                                            "reason": reason,
                                            "message": text.to_string(),
                                        }),
                                    ))
                                    .await;
                                // Do NOT forward blocked messages.
                            }
                            InspectionOutcome::Flag(description) => {
                                tracing::info!(
                                    connection_id = %ctx.connection_id,
                                    ?direction,
                                    %description,
                                    "message flagged"
                                );
                                audit
                                    .log(AuditEntry::new(
                                        AuditEventType::MessageRelayed,
                                        make_source(
                                            ctx.connection_id,
                                            ctx.remote_addr,
                                            ctx.origin.as_deref(),
                                        ),
                                        serde_json::json!({
                                            "direction": format!("{:?}", direction),
                                            "flag": description,
                                            "message": text.to_string(),
                                        }),
                                    ))
                                    .await;
                                // Forward the message despite the flag.
                                if writer.send(Message::Text(text)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Not a recognized GatewayMessage -- pass through
                        // unmodified. This handles protocol-level messages we
                        // don't need to inspect.
                        if writer.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                }
            }
            // Binary, Ping, Pong, Close frames pass through unchanged.
            Message::Close(frame) => {
                let _ = writer.send(Message::Close(frame)).await;
                break;
            }
            other => {
                if writer.send(other).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Aggregate outcome after running all inspectors on a single message.
enum InspectionOutcome {
    Pass,
    Modify(GatewayMessage),
    Block(String),
    Flag(String),
}

/// Run all inspectors on a message and collapse the results.
///
/// Precedence (highest to lowest):
/// 1. `Block` -- any inspector blocking wins immediately.
/// 2. `Modify` -- the last `Modify` result is used.
/// 3. `Flag` -- flags are combined; the message still passes.
/// 4. `Pass` -- default if no inspector has an opinion.
fn run_inspectors(
    inspectors: &[Arc<dyn MessageInspector>],
    msg: &GatewayMessage,
    ctx: &ConnectionContext,
    direction: Direction,
) -> InspectionOutcome {
    let mut current_msg = msg.clone();
    let mut flags: Vec<String> = Vec::new();
    let mut was_modified = false;

    for inspector in inspectors {
        let result = match direction {
            Direction::Upstream => inspector.inspect_upstream(&current_msg, ctx),
            Direction::Downstream => inspector.inspect_downstream(&current_msg, ctx),
        };

        match result {
            InspectionResult::Pass => {}
            InspectionResult::Modify(modified) => {
                current_msg = modified;
                was_modified = true;
            }
            InspectionResult::Block(reason) => {
                return InspectionOutcome::Block(reason);
            }
            InspectionResult::Flag(description) => {
                flags.push(description);
            }
        }
    }

    if !flags.is_empty() {
        return InspectionOutcome::Flag(flags.join("; "));
    }

    if was_modified {
        return InspectionOutcome::Modify(current_msg);
    }

    InspectionOutcome::Pass
}

/// Construct an [`AuditSource`] for the ws-proxy component.
fn make_source(
    connection_id: uuid::Uuid,
    remote_addr: SocketAddr,
    origin: Option<&str>,
) -> AuditSource {
    AuditSource {
        component: "ws-proxy".to_string(),
        origin: origin.map(|s| s.to_string()),
        remote_addr: Some(remote_addr.to_string()),
        session_id: Some(connection_id.to_string()),
    }
}
