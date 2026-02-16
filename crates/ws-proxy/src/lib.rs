//! WebSocket reverse proxy for the safety-mitts project.
//!
//! This crate implements a transparent WebSocket proxy that sits between
//! clients and the upstream OpenClaw server. Every message flowing through the
//! proxy is parsed and passed through a chain of [`MessageInspector`]
//! implementations, allowing the policy engine and prompt sanitizer to block,
//! modify, or flag messages in real time.
//!
//! # Architecture
//!
//! ```text
//! Client  <--WS-->  ws-proxy  <--WS-->  OpenClaw
//!                     |
//!               [Inspectors]
//!                     |
//!               [Audit Sink]
//! ```
//!
//! The proxy validates the `Origin` header on each incoming connection,
//! establishes a matching upstream connection, and runs two concurrent
//! forwarding loops (client-to-upstream and upstream-to-client). Non-text
//! frames (binary, ping, pong, close) are forwarded without inspection.

pub mod listener;
pub mod origin;
pub mod relay;

// Re-export the primary public types at the crate root for convenience.
pub use listener::{Proxy, ProxyConfig};
pub use relay::{ConnectionContext, GatewayMessage, InspectionResult, MessageInspector};
