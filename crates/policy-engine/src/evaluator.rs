use anyhow::{Context, Result};
use globset::Glob;
use regex::Regex;
use tracing::{debug, trace};

use crate::decision::{PolicyDecision, ResolvedAction};
use crate::schema::{
    DefaultAction, FileOp, Matcher, PolicyConfig, PolicyRule, RuleAction,
};

// ---------------------------------------------------------------------------
// Pre-compiled matcher representations
// ---------------------------------------------------------------------------

/// A pre-compiled version of a single [`Matcher`] for fast evaluation.
#[derive(Debug)]
#[allow(dead_code)]
enum CompiledMatcher {
    Command {
        regex: Regex,
    },
    FilePath {
        glob: globset::GlobMatcher,
        operations: Vec<FileOp>,
    },
    Network {
        destination_regex: Regex,
        ports: Vec<u16>,
    },
    Method {
        methods: Vec<String>,
    },
}

/// All compiled matchers for a single [`PolicyRule`], together with the index
/// into the sorted rule list.
#[derive(Debug)]
struct CompiledRule {
    rule_index: usize,
    compiled_matchers: Vec<CompiledMatcher>,
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

/// The main policy evaluation engine.
///
/// Construct via [`PolicyEngine::new`], which pre-compiles every matcher
/// pattern for efficient repeated evaluation.
pub struct PolicyEngine {
    config: PolicyConfig,
    /// Rules sorted by ascending priority (lowest number = highest precedence).
    sorted_rules: Vec<PolicyRule>,
    /// Compiled patterns parallel to `sorted_rules`.
    compiled: Vec<CompiledRule>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("version", &self.config.version)
            .field("default_action", &self.config.default_action)
            .field("num_rules", &self.sorted_rules.len())
            .finish()
    }
}

impl PolicyEngine {
    /// Create a new engine from a validated [`PolicyConfig`].
    ///
    /// All matcher patterns are compiled eagerly.  Returns an error if any
    /// regex or glob pattern is invalid.
    pub fn new(config: PolicyConfig) -> Result<Self> {
        // Sort rules by priority ascending (lower number = higher precedence).
        let mut sorted_rules = config.rules.clone();
        sorted_rules.sort_by_key(|r| r.priority);

        let mut compiled = Vec::with_capacity(sorted_rules.len());
        for (idx, rule) in sorted_rules.iter().enumerate() {
            let compiled_matchers = rule
                .matchers
                .iter()
                .map(|m| compile_matcher(m))
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("failed to compile matchers for rule '{}'", rule.name))?;
            compiled.push(CompiledRule {
                rule_index: idx,
                compiled_matchers,
            });
        }

        Ok(Self {
            config,
            sorted_rules,
            compiled,
        })
    }

    /// Return a reference to the underlying config.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    // -- Evaluate entry points ------------------------------------------------

    /// Evaluate a shell command string against all rules.
    pub fn evaluate_command(&self, command: &str) -> PolicyDecision {
        debug!(command, "evaluating command against policy");

        for cr in &self.compiled {
            let rule = &self.sorted_rules[cr.rule_index];

            // Skip rules that have no command matcher (they cannot match a
            // command evaluation request).
            if !has_matcher_kind(&rule.matchers, MatcherKind::Command) {
                continue;
            }

            let all_match = cr.compiled_matchers.iter().all(|cm| match cm {
                CompiledMatcher::Command { regex } => regex.is_match(command),
                // Non-command matchers are vacuously true in a command
                // evaluation context.
                _ => true,
            });

            if all_match {
                trace!(rule = rule.name, "rule matched command");
                return self.decision_from_rule(rule);
            }
        }

        self.default_decision("no rule matched the command")
    }

    /// Evaluate a JSON-RPC / tool method call.
    ///
    /// `params` can be inspected by future matcher types; currently unused
    /// beyond method-name matching.
    pub fn evaluate_method(&self, method: &str, _params: &serde_json::Value) -> PolicyDecision {
        debug!(method, "evaluating method against policy");

        for cr in &self.compiled {
            let rule = &self.sorted_rules[cr.rule_index];

            if !has_matcher_kind(&rule.matchers, MatcherKind::Method) {
                continue;
            }

            let all_match = cr.compiled_matchers.iter().all(|cm| match cm {
                CompiledMatcher::Method { methods } => {
                    methods.iter().any(|m| m == method)
                }
                _ => true,
            });

            if all_match {
                trace!(rule = rule.name, "rule matched method");
                return self.decision_from_rule(rule);
            }
        }

        self.default_decision("no rule matched the method")
    }

    /// Evaluate a file-system access request.
    pub fn evaluate_file_access(&self, path: &str, op: &FileOp) -> PolicyDecision {
        debug!(path, ?op, "evaluating file access against policy");

        for cr in &self.compiled {
            let rule = &self.sorted_rules[cr.rule_index];

            if !has_matcher_kind(&rule.matchers, MatcherKind::FilePath) {
                continue;
            }

            let all_match = cr.compiled_matchers.iter().all(|cm| match cm {
                CompiledMatcher::FilePath { glob, operations } => {
                    let path_matches = glob.is_match(path);
                    let op_matches = operations.is_empty() || operations.contains(op);
                    path_matches && op_matches
                }
                _ => true,
            });

            if all_match {
                trace!(rule = rule.name, "rule matched file access");
                return self.decision_from_rule(rule);
            }
        }

        self.default_decision("no rule matched the file access")
    }

    // -- Helpers --------------------------------------------------------------

    /// Convert a [`RuleAction`] into a [`PolicyDecision`].
    fn decision_from_rule(&self, rule: &PolicyRule) -> PolicyDecision {
        let action = match rule.action {
            RuleAction::AutoAllow => ResolvedAction::Allow,
            RuleAction::SoftGate => ResolvedAction::AllowWithWarning,
            RuleAction::HardGate => ResolvedAction::Block,
        };
        PolicyDecision {
            action,
            matched_rule: Some(rule.name.clone()),
            reason: rule
                .description
                .clone()
                .unwrap_or_else(|| format!("matched rule '{}'", rule.name)),
        }
    }

    /// Produce a decision from the config's `default_action`.
    fn default_decision(&self, reason: &str) -> PolicyDecision {
        let action = match self.config.default_action {
            DefaultAction::Allow => ResolvedAction::Allow,
            DefaultAction::Log => ResolvedAction::AllowWithWarning,
            DefaultAction::Block => ResolvedAction::Block,
        };
        PolicyDecision {
            action,
            matched_rule: None,
            reason: reason.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Compilation helpers
// ---------------------------------------------------------------------------

/// Discriminant-only enum used for fast "does this rule contain a matcher of
/// kind X" checks.
#[derive(PartialEq)]
enum MatcherKind {
    Command,
    FilePath,
    #[allow(dead_code)]
    Network,
    Method,
}

fn has_matcher_kind(matchers: &[Matcher], kind: MatcherKind) -> bool {
    matchers.iter().any(|m| match m {
        Matcher::Command { .. } => kind == MatcherKind::Command,
        Matcher::FilePath { .. } => kind == MatcherKind::FilePath,
        Matcher::Network { .. } => kind == MatcherKind::Network,
        Matcher::Method { .. } => kind == MatcherKind::Method,
    })
}

/// Compile a single [`Matcher`] into its pre-compiled form.
fn compile_matcher(m: &Matcher) -> Result<CompiledMatcher> {
    match m {
        Matcher::Command { pattern, is_regex } => {
            let regex = if *is_regex {
                Regex::new(pattern)
                    .with_context(|| format!("invalid command regex: {pattern}"))?
            } else {
                // Convert the simple glob/OR pattern into a single regex.
                let alternatives: Vec<String> = pattern
                    .split('|')
                    .map(|alt| glob_to_regex(alt.trim()))
                    .collect();
                let combined = format!("^(?:{})$", alternatives.join("|"));
                Regex::new(&combined)
                    .with_context(|| format!("failed to compile command glob pattern: {pattern}"))?
            };
            Ok(CompiledMatcher::Command { regex })
        }
        Matcher::FilePath { pattern, operations } => {
            let glob = Glob::new(pattern)
                .with_context(|| format!("invalid file-path glob: {pattern}"))?
                .compile_matcher();
            Ok(CompiledMatcher::FilePath {
                glob,
                operations: operations.clone(),
            })
        }
        Matcher::Network { destination, ports } => {
            // Convert destination glob (e.g. "*.evil.com") into a regex.
            let regex_str = format!("^{}$", glob_to_regex(destination));
            let destination_regex = Regex::new(&regex_str)
                .with_context(|| format!("invalid network destination pattern: {destination}"))?;
            Ok(CompiledMatcher::Network {
                destination_regex,
                ports: ports.clone(),
            })
        }
        Matcher::Method { pattern } => {
            let methods: Vec<String> = pattern
                .split('|')
                .map(|s| s.trim().to_string())
                .collect();
            Ok(CompiledMatcher::Method { methods })
        }
    }
}

/// Convert a simple glob pattern (with `*` as wildcard) into a regex fragment
/// (NOT anchored).
fn glob_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() * 2);
    for ch in pattern.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_policy_from_str;

    fn engine_from_yaml(yaml: &str) -> PolicyEngine {
        let config = load_policy_from_str(yaml).expect("test YAML should parse");
        PolicyEngine::new(config).expect("engine construction should succeed")
    }

    // -- Basic command evaluation --

    #[test]
    fn command_auto_allow() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: block
rules:
  - name: "allow-ls"
    action: auto_allow
    matchers:
      - type: command
        pattern: "ls *"
"#,
        );

        let d = engine.evaluate_command("ls -la");
        assert_eq!(d.action, ResolvedAction::Allow);
        assert_eq!(d.matched_rule.as_deref(), Some("allow-ls"));
    }

    #[test]
    fn command_default_block() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: block
rules:
  - name: "allow-ls"
    action: auto_allow
    matchers:
      - type: command
        pattern: "ls"
"#,
        );

        // "pwd" does not match the ls rule.
        let d = engine.evaluate_command("pwd");
        assert_eq!(d.action, ResolvedAction::Block);
        assert!(d.matched_rule.is_none());
    }

    #[test]
    fn command_hard_gate_blocks() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "block-rm-rf"
    priority: 1
    action: hard_gate
    matchers:
      - type: command
        pattern: "rm -rf /*"
"#,
        );

        let d = engine.evaluate_command("rm -rf /home");
        assert_eq!(d.action, ResolvedAction::Block);
        assert_eq!(d.matched_rule.as_deref(), Some("block-rm-rf"));
    }

    #[test]
    fn command_hard_gate_blocks_rm_rf_root() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "block-rm-rf-root"
    priority: 1
    action: hard_gate
    description: "Prevent catastrophic recursive deletion at root"
    matchers:
      - type: command
        pattern: "rm\\s+-rf\\s+/"
        is_regex: true
"#,
        );

        let d = engine.evaluate_command("rm -rf /");
        assert_eq!(d.action, ResolvedAction::Block);
        assert_eq!(d.matched_rule.as_deref(), Some("block-rm-rf-root"));
        assert_eq!(d.reason, "Prevent catastrophic recursive deletion at root");

        // Not matching a safe rm.
        let d2 = engine.evaluate_command("rm file.txt");
        assert_eq!(d2.action, ResolvedAction::Allow);
    }

    #[test]
    fn command_regex_matcher() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "block-sudo"
    action: hard_gate
    matchers:
      - type: command
        pattern: "^sudo\\b.*"
        is_regex: true
"#,
        );

        let d = engine.evaluate_command("sudo reboot");
        assert_eq!(d.action, ResolvedAction::Block);

        let d2 = engine.evaluate_command("echo sudo");
        assert_eq!(d2.action, ResolvedAction::Allow);
    }

    // -- Soft gate (warning) --

    #[test]
    fn soft_gate_gives_warning() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "warn-curl"
    action: soft_gate
    matchers:
      - type: command
        pattern: "curl *"
"#,
        );

        let d = engine.evaluate_command("curl https://example.com");
        assert_eq!(d.action, ResolvedAction::AllowWithWarning);
    }

    // -- Priority ordering --

    #[test]
    fn lower_priority_wins() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: block
rules:
  - name: "allow-git"
    priority: 50
    action: auto_allow
    matchers:
      - type: command
        pattern: "git *"
  - name: "block-git-push-force"
    priority: 10
    action: hard_gate
    matchers:
      - type: command
        pattern: "git push --force*"
"#,
        );

        // "git push --force" matches both, but priority 10 wins.
        let d = engine.evaluate_command("git push --force origin main");
        assert_eq!(d.action, ResolvedAction::Block);
        assert_eq!(d.matched_rule.as_deref(), Some("block-git-push-force"));

        // Normal git command allowed.
        let d2 = engine.evaluate_command("git status");
        assert_eq!(d2.action, ResolvedAction::Allow);
        assert_eq!(d2.matched_rule.as_deref(), Some("allow-git"));
    }

    // -- OR patterns in glob --

    #[test]
    fn command_or_pattern() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: block
rules:
  - name: "allow-read-cmds"
    action: auto_allow
    matchers:
      - type: command
        pattern: "cat *|head *|tail *|less *"
"#,
        );

        assert_eq!(
            engine.evaluate_command("cat /etc/passwd").action,
            ResolvedAction::Allow
        );
        assert_eq!(
            engine.evaluate_command("head -n 5 foo.txt").action,
            ResolvedAction::Allow
        );
        assert_eq!(
            engine.evaluate_command("vim foo.txt").action,
            ResolvedAction::Block
        );
    }

    // -- Method evaluation --

    #[test]
    fn method_evaluation() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: block
rules:
  - name: "allow-hover"
    action: auto_allow
    matchers:
      - type: method
        pattern: "textDocument/hover|textDocument/completion"
"#,
        );

        let d = engine.evaluate_method("textDocument/hover", &serde_json::json!({}));
        assert_eq!(d.action, ResolvedAction::Allow);

        let d2 = engine.evaluate_method("textDocument/rename", &serde_json::json!({}));
        assert_eq!(d2.action, ResolvedAction::Block);
    }

    // -- File-access evaluation --

    #[test]
    fn file_access_glob_and_ops() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "gate-etc-writes"
    priority: 5
    action: hard_gate
    matchers:
      - type: file_path
        pattern: "/etc/**"
        operations:
          - write
          - delete
"#,
        );

        // Writing to /etc is blocked.
        let d = engine.evaluate_file_access("/etc/nginx/nginx.conf", &FileOp::Write);
        assert_eq!(d.action, ResolvedAction::Block);

        // Reading /etc is allowed (op not in list).
        let d2 = engine.evaluate_file_access("/etc/passwd", &FileOp::Read);
        assert_eq!(d2.action, ResolvedAction::Allow);

        // Writing to /home is allowed (path doesn't match).
        let d3 = engine.evaluate_file_access("/home/user/.bashrc", &FileOp::Write);
        assert_eq!(d3.action, ResolvedAction::Allow);
    }

    #[test]
    fn file_access_no_ops_means_all_ops() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "block-secrets"
    action: hard_gate
    matchers:
      - type: file_path
        pattern: "/secrets/**"
"#,
        );

        // No operations specified means ANY operation matches.
        assert_eq!(
            engine
                .evaluate_file_access("/secrets/key.pem", &FileOp::Read)
                .action,
            ResolvedAction::Block
        );
        assert_eq!(
            engine
                .evaluate_file_access("/secrets/key.pem", &FileOp::Exec)
                .action,
            ResolvedAction::Block
        );
    }

    // -- Default action variants --

    #[test]
    fn default_action_log() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: log
rules: []
"#,
        );

        let d = engine.evaluate_command("anything");
        assert_eq!(d.action, ResolvedAction::AllowWithWarning);
    }

    #[test]
    fn default_action_allow() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules: []
"#,
        );

        let d = engine.evaluate_command("anything");
        assert_eq!(d.action, ResolvedAction::Allow);
    }

    // -- Engine construction errors --

    #[test]
    fn invalid_regex_rejected_at_construction() {
        let config = load_policy_from_str(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "bad-regex"
    action: hard_gate
    matchers:
      - type: command
        pattern: "[invalid"
        is_regex: true
"#,
        )
        .unwrap();

        let err = PolicyEngine::new(config).unwrap_err();
        assert!(
            err.to_string().contains("bad-regex"),
            "error should mention rule name: {err}"
        );
    }

    // -- Multiple matchers AND logic --

    #[test]
    fn multiple_matchers_require_all() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "block-combined"
    action: hard_gate
    matchers:
      - type: command
        pattern: "deploy *"
      - type: command
        pattern: "*--force*"
"#,
        );

        // Only "deploy" -> no match on second matcher.
        let d = engine.evaluate_command("deploy app");
        assert_eq!(d.action, ResolvedAction::Allow);

        // Both matchers satisfied.
        let d2 = engine.evaluate_command("deploy --force app");
        assert_eq!(d2.action, ResolvedAction::Block);
    }

    // -- Rule with no matchers matches everything of its kind --
    // Actually, rules with no matchers of the evaluated kind are skipped,
    // so a rule with zero matchers should never match.

    #[test]
    fn rule_with_no_matchers_is_skipped() {
        let engine = engine_from_yaml(
            r#"
version: "1.0"
default_action: allow
rules:
  - name: "empty-rule"
    action: hard_gate
"#,
        );

        // The rule has no command matchers, so it cannot match a command evaluation.
        let d = engine.evaluate_command("anything");
        assert_eq!(d.action, ResolvedAction::Allow);
    }
}
