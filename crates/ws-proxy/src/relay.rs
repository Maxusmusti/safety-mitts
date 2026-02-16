use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Parsed OpenClaw WebSocket message.
///
/// The proxy only needs to understand the outer envelope to route and inspect
/// messages. Unknown fields are captured in the serde flattened `body` /
/// `params` / `payload` values so they round-trip losslessly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GatewayMessage {
    /// A request from the client to OpenClaw.
    #[serde(rename = "req")]
    Request {
        id: String,
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    },

    /// A response from OpenClaw back to the client.
    #[serde(rename = "res")]
    Response {
        id: String,
        #[serde(default)]
        ok: bool,
        #[serde(flatten)]
        body: serde_json::Value,
    },

    /// A server-pushed event (e.g. streaming output, status updates).
    #[serde(rename = "event")]
    Event {
        event: String,
        #[serde(default)]
        payload: serde_json::Value,
    },
}

/// Per-connection metadata passed to inspectors.
pub struct ConnectionContext {
    /// Unique identifier for this WebSocket connection.
    pub connection_id: uuid::Uuid,
    /// The TCP address of the connecting client.
    pub remote_addr: SocketAddr,
    /// The `Origin` header value, if one was present on the upgrade request.
    pub origin: Option<String>,
}

/// The result of a [`MessageInspector`] inspecting a single message.
pub enum InspectionResult {
    /// Let the message pass through unmodified.
    Pass,
    /// Replace the message with a modified version.
    Modify(GatewayMessage),
    /// Block the message entirely. The `String` is a human-readable reason.
    Block(String),
    /// Flag the message for auditing but allow it to pass through. The
    /// `String` is a description of the concern.
    Flag(String),
}

/// Trait for synchronous message inspection.
///
/// Implementors examine WebSocket messages flowing in each direction and
/// return an [`InspectionResult`] to control whether the message is passed
/// through, modified, blocked, or flagged.
///
/// The trait is deliberately synchronous to keep policy evaluation simple
/// and deterministic. Inspectors must not perform I/O.
pub trait MessageInspector: Send + Sync {
    /// Inspect a message travelling from the client toward the upstream
    /// (OpenClaw).
    fn inspect_upstream(
        &self,
        msg: &GatewayMessage,
        ctx: &ConnectionContext,
    ) -> InspectionResult;

    /// Inspect a message travelling from the upstream (OpenClaw) back toward
    /// the client.
    fn inspect_downstream(
        &self,
        msg: &GatewayMessage,
        ctx: &ConnectionContext,
    ) -> InspectionResult;
}
