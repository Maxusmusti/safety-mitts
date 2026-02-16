//! Injection pattern library.
//!
//! Contains the static catalogue of regex patterns used to detect common
//! prompt-injection techniques.  Each entry carries a human-readable name, a
//! [`PatternCategory`] for grouping/reporting, and a regex string that is
//! compiled at scanner-construction time.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/// Broad classification of the injection technique a pattern targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternCategory {
    /// Attempts to override or cancel the original system instructions.
    InstructionOverride,
    /// Attempts to redefine the model's persona or role.
    RoleHijack,
    /// Attempts to escape the current prompt context using delimiters or
    /// special tags recognised by common model formats.
    DelimiterEscape,
    /// Attempts to exfiltrate the system prompt or other hidden context.
    DataExfiltration,
}

impl fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstructionOverride => write!(f, "InstructionOverride"),
            Self::RoleHijack => write!(f, "RoleHijack"),
            Self::DelimiterEscape => write!(f, "DelimiterEscape"),
            Self::DataExfiltration => write!(f, "DataExfiltration"),
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern definition
// ---------------------------------------------------------------------------

/// A single detection pattern.
pub struct InjectionPattern {
    /// Short, snake_case identifier used in logs and findings.
    pub name: &'static str,
    /// The family of injection technique this pattern belongs to.
    pub category: PatternCategory,
    /// A regex string (compiled lazily by [`crate::scanner::Scanner`]).
    pub pattern: &'static str,
}

// ---------------------------------------------------------------------------
// Pattern catalogue
// ---------------------------------------------------------------------------

/// The built-in pattern library.
///
/// Patterns are intentionally kept as a static slice so that they are
/// available at zero runtime cost until the scanner compiles them.
pub static PATTERNS: &[InjectionPattern] = &[
    // ---- Instruction override ------------------------------------------
    InjectionPattern {
        name: "ignore_previous",
        category: PatternCategory::InstructionOverride,
        pattern: r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
    },
    InjectionPattern {
        name: "disregard_prior",
        category: PatternCategory::InstructionOverride,
        pattern: r"(?i)disregard\s+(all\s+)?(prior|previous|above)",
    },
    InjectionPattern {
        name: "new_instruction",
        category: PatternCategory::InstructionOverride,
        pattern: r"(?i)new\s+instruction\s*:",
    },
    InjectionPattern {
        name: "system_override",
        category: PatternCategory::InstructionOverride,
        pattern: r"(?i)system\s*:\s*override",
    },
    InjectionPattern {
        name: "do_not_follow",
        category: PatternCategory::InstructionOverride,
        pattern: r"(?i)\bdo\s+not\s+follow\s+(any|the)\s+(previous|above|prior)",
    },
    InjectionPattern {
        name: "developer_mode",
        category: PatternCategory::InstructionOverride,
        pattern: r"(?i)you\s+are\s+now\s+(in\s+)?developer\s+mode",
    },
    // ---- Role hijacking ------------------------------------------------
    InjectionPattern {
        name: "you_are_now",
        category: PatternCategory::RoleHijack,
        pattern: r"(?i)you\s+are\s+now\s+a\b",
    },
    InjectionPattern {
        name: "act_as",
        category: PatternCategory::RoleHijack,
        pattern: r"(?i)act\s+as\s+(if\s+you\s+are\s+)?a\b",
    },
    InjectionPattern {
        name: "pretend_to_be",
        category: PatternCategory::RoleHijack,
        pattern: r"(?i)pretend\s+(to\s+be|you\s+are)",
    },
    InjectionPattern {
        name: "from_now_on",
        category: PatternCategory::RoleHijack,
        pattern: r"(?i)from\s+now\s+on\s*,?\s*you\s+(are|will|must|should)",
    },
    // ---- Delimiter / context escape ------------------------------------
    InjectionPattern {
        name: "system_tag",
        category: PatternCategory::DelimiterEscape,
        pattern: r"(?i)<\s*/?\s*system\s*>",
    },
    InjectionPattern {
        name: "inst_tag",
        category: PatternCategory::DelimiterEscape,
        pattern: r"(?i)\[INST\]",
    },
    InjectionPattern {
        name: "sys_delimiter",
        category: PatternCategory::DelimiterEscape,
        pattern: r"(?i)<<\s*SYS\s*>>",
    },
    InjectionPattern {
        name: "role_header",
        category: PatternCategory::DelimiterEscape,
        pattern: r"(?i)###\s*(system|instruction|human|assistant)\s*:?",
    },
    // ---- Data exfiltration ---------------------------------------------
    InjectionPattern {
        name: "reveal_prompt",
        category: PatternCategory::DataExfiltration,
        pattern: r"(?i)(reveal|show|print|display|output)\s+(your\s+)?(system\s+)?prompt",
    },
    InjectionPattern {
        name: "what_instructions",
        category: PatternCategory::DataExfiltration,
        pattern: r"(?i)what\s+(are|were)\s+your\s+(initial\s+)?instructions",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for pat in PATTERNS {
            regex::Regex::new(pat.pattern)
                .unwrap_or_else(|e| panic!("pattern '{}' failed to compile: {e}", pat.name));
        }
    }

    #[test]
    fn names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for pat in PATTERNS {
            assert!(
                seen.insert(pat.name),
                "duplicate pattern name: {}",
                pat.name
            );
        }
    }
}
