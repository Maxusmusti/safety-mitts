use serde::{Deserialize, Serialize};

/// A single audit log entry representing an event in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub source: AuditSource,
    pub details: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<PolicyDecisionRecord>,
}

impl AuditEntry {
    /// Create a new `AuditEntry` with an auto-generated UUID v4 and the current
    /// UTC timestamp. The caller supplies the event type, source, and
    /// free-form details JSON value. `policy_decision` defaults to `None`.
    pub fn new(
        event_type: AuditEventType,
        source: AuditSource,
        details: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type,
            source,
            details,
            policy_decision: None,
        }
    }

    /// Attach a policy decision record to this entry, consuming and returning
    /// `self` for builder-style usage.
    pub fn with_policy_decision(mut self, decision: PolicyDecisionRecord) -> Self {
        self.policy_decision = Some(decision);
        self
    }
}

/// The category of audit event being recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    ConnectionOpened,
    ConnectionClosed,
    OriginRejected,
    MessageRelayed,
    ExecRequested,
    ExecAllowed,
    ExecBlocked,
    ExecSoftGated,
    PromptInjectionDetected,
    ProcessStarted,
    ProcessStopped,
    PolicyReloaded,
    ConfigChanged,
}

/// Identifies the component and optional contextual metadata for the event
/// source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSource {
    pub component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl AuditSource {
    /// Convenience constructor that only requires the component name. All
    /// optional fields default to `None`.
    pub fn new(component: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            origin: None,
            remote_addr: None,
            session_id: None,
        }
    }
}

/// Records the outcome of a policy evaluation attached to an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionRecord {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    pub reason: String,
}
