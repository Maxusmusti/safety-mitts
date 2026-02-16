//! Append-only structured JSON-lines audit logging for the safety-mitts
//! project.
//!
//! This crate provides the shared audit-logging infrastructure used by every
//! component in the system.  Each audit event is serialised as a single
//! newline-terminated JSON object and appended to a log file, producing a
//! [JSON Lines](https://jsonlines.org/) stream that is easy to ship, parse,
//! and replay.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use audit_log::{AuditEntry, AuditEventType, AuditSink, AuditSource};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let (sink, _handle) = AuditSink::start("/var/log/safety-mitts/audit.jsonl").await?;
//!
//! sink.log(AuditEntry::new(
//!     AuditEventType::ProcessStarted,
//!     AuditSource::new("ws-proxy"),
//!     serde_json::json!({"version": "0.1.0"}),
//! ))
//! .await;
//! # Ok(())
//! # }
//! ```

pub mod entry;
pub mod sink;
pub mod writer;

// Re-export primary public types at the crate root for convenience.
pub use entry::{AuditEntry, AuditEventType, AuditSource, PolicyDecisionRecord};
pub use sink::AuditSink;
pub use writer::{AuditWriteError, AuditWriter};
