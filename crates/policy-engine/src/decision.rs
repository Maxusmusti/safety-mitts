/// The outcome of evaluating a request against the loaded policy.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The resolved action to take.
    pub action: ResolvedAction,
    /// Name of the rule that matched, if any.
    pub matched_rule: Option<String>,
    /// Human-readable reason explaining the decision.
    pub reason: String,
}

/// The action the proxy should take after policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedAction {
    /// Silently forward the request.
    Allow,
    /// Forward the request but surface a warning to the user.
    AllowWithWarning,
    /// Drop / reject the request entirely.
    Block,
}

impl PolicyDecision {
    /// Convenience constructor for an allow decision with no matching rule.
    pub fn allow_default(reason: impl Into<String>) -> Self {
        Self {
            action: ResolvedAction::Allow,
            matched_rule: None,
            reason: reason.into(),
        }
    }

    /// Convenience constructor for a block decision with no matching rule.
    pub fn block_default(reason: impl Into<String>) -> Self {
        Self {
            action: ResolvedAction::Block,
            matched_rule: None,
            reason: reason.into(),
        }
    }

    /// Convenience constructor for a warning (log) decision with no matching rule.
    pub fn warn_default(reason: impl Into<String>) -> Self {
        Self {
            action: ResolvedAction::AllowWithWarning,
            matched_rule: None,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_default_has_correct_fields() {
        let d = PolicyDecision::allow_default("no rules matched");
        assert_eq!(d.action, ResolvedAction::Allow);
        assert!(d.matched_rule.is_none());
        assert_eq!(d.reason, "no rules matched");
    }

    #[test]
    fn block_default_has_correct_fields() {
        let d = PolicyDecision::block_default("default policy is block");
        assert_eq!(d.action, ResolvedAction::Block);
        assert!(d.matched_rule.is_none());
    }

    #[test]
    fn warn_default_has_correct_fields() {
        let d = PolicyDecision::warn_default("logging");
        assert_eq!(d.action, ResolvedAction::AllowWithWarning);
    }

    #[test]
    fn resolved_action_equality() {
        assert_eq!(ResolvedAction::Allow, ResolvedAction::Allow);
        assert_ne!(ResolvedAction::Allow, ResolvedAction::Block);
        assert_ne!(ResolvedAction::AllowWithWarning, ResolvedAction::Block);
    }
}
