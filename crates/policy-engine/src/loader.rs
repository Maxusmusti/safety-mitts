use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::schema::PolicyConfig;

/// Load a [`PolicyConfig`] from a YAML file on disk.
///
/// Validates the config after deserialization (version check, unique rule names).
pub fn load_policy(path: impl AsRef<Path>) -> Result<PolicyConfig> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;
    load_policy_from_str(&contents)
        .with_context(|| format!("failed to parse policy file: {}", path.display()))
}

/// Parse and validate a [`PolicyConfig`] from a YAML string.
///
/// This is the primary entry point used in tests.
pub fn load_policy_from_str(yaml: &str) -> Result<PolicyConfig> {
    let config: PolicyConfig =
        serde_yml::from_str(yaml).context("YAML deserialization failed")?;
    validate(&config)?;
    Ok(config)
}

/// Run post-deserialization validation checks.
fn validate(config: &PolicyConfig) -> Result<()> {
    // Version gate
    if config.version != "1.0" {
        bail!(
            "unsupported policy version '{}'; only '1.0' is supported",
            config.version
        );
    }

    // Rule names must be unique
    let mut seen = HashSet::new();
    for rule in &config.rules {
        if rule.name.is_empty() {
            bail!("rule name must not be empty");
        }
        if !seen.insert(&rule.name) {
            bail!("duplicate rule name: '{}'", rule.name);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_minimal_policy() {
        let yaml = r#"
version: "1.0"
default_action: allow
rules: []
"#;
        let config = load_policy_from_str(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        assert!(config.rules.is_empty());
    }

    #[test]
    fn reject_wrong_version() {
        let yaml = r#"
version: "2.0"
default_action: allow
rules: []
"#;
        let err = load_policy_from_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unsupported policy version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_duplicate_rule_names() {
        let yaml = r#"
version: "1.0"
default_action: allow
rules:
  - name: "dup"
    action: auto_allow
  - name: "dup"
    action: hard_gate
"#;
        let err = load_policy_from_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate rule name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reject_empty_rule_name() {
        let yaml = r#"
version: "1.0"
default_action: allow
rules:
  - name: ""
    action: auto_allow
"#;
        let err = load_policy_from_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_from_nonexistent_file() {
        let err = load_policy("/does/not/exist.yaml").unwrap_err();
        assert!(
            err.to_string().contains("failed to read policy file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_complex_policy() {
        let yaml = r#"
version: "1.0"
default_action: block
origin_allowlist:
  - "trusted-origin"
rules:
  - name: "allow-ls"
    priority: 10
    action: auto_allow
    matchers:
      - type: command
        pattern: "ls *"
  - name: "block-rm-rf"
    priority: 1
    action: hard_gate
    matchers:
      - type: command
        pattern: "rm\\s+-rf\\s+/"
        is_regex: true
  - name: "gate-etc-writes"
    priority: 5
    action: soft_gate
    matchers:
      - type: file_path
        pattern: "/etc/**"
        operations:
          - write
"#;
        let config = load_policy_from_str(yaml).unwrap();
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.origin_allowlist, vec!["trusted-origin"]);
    }
}
