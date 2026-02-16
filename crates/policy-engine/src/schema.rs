use serde::{Deserialize, Serialize};

/// Top-level policy configuration loaded from a YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Schema version; currently must be "1.0".
    pub version: String,
    /// Action taken when no rule matches.
    pub default_action: DefaultAction,
    /// List of allowed origin identifiers (e.g. IDE extension IDs).
    #[serde(default)]
    pub origin_allowlist: Vec<String>,
    /// Network binding / port settings for the proxy layer.
    #[serde(default)]
    pub network_policy: NetworkPolicy,
    /// Ordered list of policy rules evaluated against incoming messages.
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
    Log,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default = "default_localhost")]
    pub openclaw_bind: String,
    #[serde(default = "default_localhost")]
    pub listen_bind: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_upstream_port")]
    pub upstream_port: u16,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            openclaw_bind: default_localhost(),
            listen_bind: default_localhost(),
            listen_port: default_listen_port(),
            upstream_port: default_upstream_port(),
        }
    }
}

fn default_localhost() -> String {
    "127.0.0.1".to_string()
}
fn default_listen_port() -> u16 {
    18789
}
fn default_upstream_port() -> u16 {
    18790
}

/// A single policy rule consisting of a name, priority, action, and zero or
/// more matchers.  All matchers must match for the rule to fire (AND logic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable, unique rule name.
    pub name: String,
    /// Optional longer description.
    #[serde(default)]
    pub description: Option<String>,
    /// Lower numeric priority wins; evaluated first. Default 100.
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// What to do when the rule matches.
    pub action: RuleAction,
    /// List of matchers (all must match).
    #[serde(default)]
    pub matchers: Vec<Matcher>,
}

fn default_priority() -> i32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Silently allow the operation.
    AutoAllow,
    /// Allow but show a warning / confirmation prompt.
    SoftGate,
    /// Block the operation entirely.
    HardGate,
}

/// A typed matcher that the evaluator checks against an incoming request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    /// Match against a shell command string.
    Command {
        pattern: String,
        #[serde(default)]
        is_regex: bool,
    },
    /// Match against a filesystem path with optional operation filter.
    FilePath {
        pattern: String,
        #[serde(default)]
        operations: Vec<FileOp>,
    },
    /// Match against a network destination.
    Network {
        destination: String,
        #[serde(default)]
        ports: Vec<u16>,
    },
    /// Match against a JSON-RPC / tool method name.
    Method {
        pattern: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Read,
    Write,
    Delete,
    Exec,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_config() {
        let yaml = r#"
version: "1.0"
default_action: allow
rules: []
"#;
        let config: PolicyConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.default_action, DefaultAction::Allow);
        assert!(config.rules.is_empty());
        assert_eq!(config.network_policy.listen_port, 18789);
        assert_eq!(config.network_policy.upstream_port, 18790);
        assert_eq!(config.network_policy.listen_bind, "127.0.0.1");
    }

    #[test]
    fn deserialize_full_config() {
        let yaml = r#"
version: "1.0"
default_action: block
origin_allowlist:
  - "vscode-extension-abc"
  - "jetbrains-plugin-xyz"
network_policy:
  openclaw_bind: "0.0.0.0"
  listen_bind: "0.0.0.0"
  listen_port: 9000
  upstream_port: 9001
rules:
  - name: "block-dangerous-rm"
    description: "Block recursive force removal at root"
    priority: 1
    action: hard_gate
    matchers:
      - type: command
        pattern: "rm -rf /"
        is_regex: false
  - name: "allow-read-methods"
    priority: 50
    action: auto_allow
    matchers:
      - type: method
        pattern: "textDocument/hover|textDocument/completion"
  - name: "gate-write-to-etc"
    priority: 10
    action: soft_gate
    matchers:
      - type: file_path
        pattern: "/etc/**"
        operations:
          - write
          - delete
"#;
        let config: PolicyConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.default_action, DefaultAction::Block);
        assert_eq!(config.origin_allowlist.len(), 2);
        assert_eq!(config.network_policy.listen_port, 9000);
        assert_eq!(config.rules.len(), 3);

        let rule0 = &config.rules[0];
        assert_eq!(rule0.name, "block-dangerous-rm");
        assert_eq!(rule0.priority, 1);
        assert_eq!(rule0.action, RuleAction::HardGate);
        assert_eq!(rule0.matchers.len(), 1);

        match &rule0.matchers[0] {
            Matcher::Command { pattern, is_regex } => {
                assert_eq!(pattern, "rm -rf /");
                assert!(!is_regex);
            }
            other => panic!("expected Command matcher, got {:?}", other),
        }

        let rule2 = &config.rules[2];
        match &rule2.matchers[0] {
            Matcher::FilePath { pattern, operations } => {
                assert_eq!(pattern, "/etc/**");
                assert_eq!(operations, &[FileOp::Write, FileOp::Delete]);
            }
            other => panic!("expected FilePath matcher, got {:?}", other),
        }
    }

    #[test]
    fn deserialize_network_matcher() {
        let yaml = r#"
version: "1.0"
default_action: log
rules:
  - name: "block-external"
    action: hard_gate
    matchers:
      - type: network
        destination: "*.evil.com"
        ports: [80, 443]
"#;
        let config: PolicyConfig = serde_yml::from_str(yaml).unwrap();
        let rule = &config.rules[0];
        match &rule.matchers[0] {
            Matcher::Network { destination, ports } => {
                assert_eq!(destination, "*.evil.com");
                assert_eq!(ports, &[80, 443]);
            }
            other => panic!("expected Network matcher, got {:?}", other),
        }
    }

    #[test]
    fn default_priority_is_100() {
        let yaml = r#"
version: "1.0"
default_action: allow
rules:
  - name: "no-priority"
    action: soft_gate
"#;
        let config: PolicyConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.rules[0].priority, 100);
    }
}
