use std::collections::HashMap;
use std::net::SocketAddr;

use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors specific to network bind enforcement.
#[derive(Debug, Error)]
pub enum BindError {
    /// The process bound to all interfaces, which is a security risk.
    #[error(
        "security risk: port {port} is bound to {bound_addr} (all interfaces) \
         instead of {expected_addr} — OpenClaw must only listen on localhost"
    )]
    BoundToAllInterfaces {
        port: u16,
        bound_addr: String,
        expected_addr: SocketAddr,
    },

    /// Failed to execute the system command used to inspect bindings.
    #[error("failed to execute bind-check command: {0}")]
    CommandFailed(#[from] std::io::Error),

    /// The command produced output we could not interpret.
    #[error("failed to parse bind-check output: {reason}")]
    ParseError { reason: String },
}

/// Configuration for network binding enforcement.
#[derive(Debug, Clone)]
pub struct BindConfig {
    /// The address OpenClaw should bind to internally.
    pub internal_addr: SocketAddr,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            internal_addr: "127.0.0.1:18790".parse().unwrap(),
        }
    }
}

/// Computes environment variable overrides that force OpenClaw to bind
/// to the specified internal address only.
///
/// The returned map should be merged into the child-process environment
/// before spawning OpenClaw so that it never binds to `0.0.0.0`.
pub fn enforce_bind_env(config: &BindConfig) -> HashMap<String, String> {
    let ip = config.internal_addr.ip().to_string();
    let port = config.internal_addr.port().to_string();
    let full = config.internal_addr.to_string();

    let mut env = HashMap::new();

    // Gateway-specific overrides
    env.insert("OPENCLAW_GATEWAY_HOST".to_string(), ip.clone());
    env.insert("OPENCLAW_GATEWAY_PORT".to_string(), port);

    // Generic bind address override
    env.insert("OPENCLAW_BIND".to_string(), full);

    // Prevent binding to all interfaces
    env.insert("OPENCLAW_HOST".to_string(), ip);

    info!(
        addr = %config.internal_addr,
        env_count = env.len(),
        "computed bind-enforcement environment variables"
    );

    env
}

/// Verifies that a process is bound to the expected address.
///
/// Uses platform-specific commands (`lsof` on macOS, `ss` on Linux) to
/// inspect listening sockets.
///
/// # Returns
///
/// * `Ok(true)`  — the expected address is bound to localhost as required.
/// * `Ok(false)` — nothing is listening on the expected port yet.
/// * `Err(_)`    — the port is bound to a wildcard / all-interfaces address,
///                 the inspection command failed, or its output could not be
///                 parsed.
pub async fn verify_bind(expected: &SocketAddr) -> Result<bool, BindError> {
    let port = expected.port();

    debug!(port, "verifying bind address");

    if cfg!(target_os = "macos") {
        verify_bind_macos(expected, port).await
    } else if cfg!(target_os = "linux") {
        verify_bind_linux(expected, port).await
    } else {
        warn!("bind verification is not supported on this platform; skipping");
        Ok(false)
    }
}

/// macOS implementation using `lsof`.
async fn verify_bind_macos(expected: &SocketAddr, port: u16) -> Result<bool, BindError> {
    let output = tokio::process::Command::new("lsof")
        .args([
            "-i",
            &format!(":{port}"),
            "-sTCP:LISTEN",
            "-n",
            "-P",
        ])
        .output()
        .await?;

    // lsof exits with status 1 when no matching files are found — that is
    // not an error for our purposes; it simply means nothing is listening.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A genuine error contains output on stderr; an empty stderr with
        // exit-code 1 just means "no results".
        if stderr.trim().is_empty() {
            debug!(port, "lsof found no listeners on port");
            return Ok(false);
        }
        return Err(BindError::ParseError {
            reason: format!("lsof exited with {}: {}", output.status, stderr.trim()),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!(output = %stdout, "lsof output");

    parse_lsof_output(&stdout, expected, port)
}

/// Parses `lsof -i :PORT -sTCP:LISTEN -n -P` output.
///
/// Typical output lines look like:
///
/// ```text
/// COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
/// node    12345 user   22u  IPv4 0x1234      0t0  TCP 127.0.0.1:18790 (LISTEN)
/// node    12345 user   23u  IPv6 0x5678      0t0  TCP *:18790 (LISTEN)
/// ```
///
/// We inspect the NAME column for the bound address.
fn parse_lsof_output(
    stdout: &str,
    expected: &SocketAddr,
    port: u16,
) -> Result<bool, BindError> {
    let mut found_expected = false;

    for line in stdout.lines() {
        // Skip the header row.
        if line.starts_with("COMMAND") {
            continue;
        }

        // The NAME column is the last whitespace-delimited token (ignoring a
        // possible trailing "(LISTEN)").
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 9 {
            continue;
        }

        // NAME is typically the second-to-last token, with "(LISTEN)" last.
        // But it can also be the last token if "(LISTEN)" is absent.
        let name = if tokens.last() == Some(&"(LISTEN)") {
            tokens[tokens.len() - 2]
        } else {
            tokens[tokens.len() - 1]
        };

        // name is something like "127.0.0.1:18790", "*:18790",
        // "[::1]:18790", or "0.0.0.0:18790".
        let port_suffix = format!(":{port}");
        if !name.ends_with(&port_suffix) {
            continue;
        }

        let host_part = &name[..name.len() - port_suffix.len()];

        // Wildcard / all-interfaces patterns.
        if host_part == "*"
            || host_part == "0.0.0.0"
            || host_part == "[::]"
            || host_part == "::"
        {
            return Err(BindError::BoundToAllInterfaces {
                port,
                bound_addr: name.to_string(),
                expected_addr: *expected,
            });
        }

        // Check whether this is the address we expected.
        if let Ok(addr) = name.parse::<SocketAddr>() {
            if addr == *expected {
                found_expected = true;
            }
        } else {
            // Not a parseable socket addr — could be an IPv6 bracket form
            // or something unexpected. Try a simple string comparison.
            let expected_str = expected.to_string();
            if name == expected_str {
                found_expected = true;
            }
        }
    }

    if found_expected {
        info!(%expected, "bind verification succeeded — listening on localhost");
    } else {
        debug!(port, "no matching listener found on expected address");
    }

    Ok(found_expected)
}

/// Linux implementation using `ss`.
async fn verify_bind_linux(expected: &SocketAddr, port: u16) -> Result<bool, BindError> {
    let output = tokio::process::Command::new("ss")
        .args(["-tlnp", &format!("sport = :{port}")])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BindError::ParseError {
            reason: format!("ss exited with {}: {}", output.status, stderr.trim()),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!(output = %stdout, "ss output");

    parse_ss_output(&stdout, expected, port)
}

/// Parses `ss -tlnp` output.
///
/// Typical output:
///
/// ```text
/// State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
/// LISTEN 0      128     127.0.0.1:18790     0.0.0.0:*          users:(("node",pid=1234,fd=22))
/// ```
fn parse_ss_output(
    stdout: &str,
    expected: &SocketAddr,
    port: u16,
) -> Result<bool, BindError> {
    let mut found_expected = false;
    let port_suffix = format!(":{port}");

    for line in stdout.lines() {
        // Skip headers.
        if line.starts_with("State") || line.trim().is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        // The local address:port is typically the 4th column (index 3).
        if tokens.len() < 5 {
            continue;
        }

        let local = tokens[3];
        if !local.ends_with(&port_suffix) {
            continue;
        }

        let host_part = &local[..local.len() - port_suffix.len()];

        if host_part == "*" || host_part == "0.0.0.0" || host_part == "[::]" || host_part == "::" {
            return Err(BindError::BoundToAllInterfaces {
                port,
                bound_addr: local.to_string(),
                expected_addr: *expected,
            });
        }

        if let Ok(addr) = local.parse::<SocketAddr>() {
            if addr == *expected {
                found_expected = true;
            }
        } else {
            let expected_str = expected.to_string();
            if local == expected_str {
                found_expected = true;
            }
        }
    }

    if found_expected {
        info!(%expected, "bind verification succeeded — listening on localhost");
    } else {
        debug!(port, "no matching listener found on expected address");
    }

    Ok(found_expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_localhost() {
        let config = BindConfig::default();
        assert_eq!(config.internal_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(config.internal_addr.port(), 18790);
    }

    #[test]
    fn enforce_bind_env_sets_expected_keys() {
        let config = BindConfig::default();
        let env = enforce_bind_env(&config);

        assert_eq!(env.get("OPENCLAW_GATEWAY_HOST").unwrap(), "127.0.0.1");
        assert_eq!(env.get("OPENCLAW_GATEWAY_PORT").unwrap(), "18790");
        assert_eq!(env.get("OPENCLAW_BIND").unwrap(), "127.0.0.1:18790");
        assert_eq!(env.get("OPENCLAW_HOST").unwrap(), "127.0.0.1");
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn enforce_bind_env_custom_addr() {
        let config = BindConfig {
            internal_addr: "127.0.0.1:9999".parse().unwrap(),
        };
        let env = enforce_bind_env(&config);

        assert_eq!(env.get("OPENCLAW_GATEWAY_HOST").unwrap(), "127.0.0.1");
        assert_eq!(env.get("OPENCLAW_GATEWAY_PORT").unwrap(), "9999");
        assert_eq!(env.get("OPENCLAW_BIND").unwrap(), "127.0.0.1:9999");
        assert_eq!(env.get("OPENCLAW_HOST").unwrap(), "127.0.0.1");
    }

    #[test]
    fn parse_lsof_localhost_bound() {
        let output = "\
COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
node    12345 user   22u  IPv4 0x1234      0t0  TCP 127.0.0.1:18790 (LISTEN)
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_lsof_output(output, &expected, 18790).unwrap();
        assert!(result);
    }

    #[test]
    fn parse_lsof_wildcard_rejected() {
        let output = "\
COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
node    12345 user   22u  IPv4 0x1234      0t0  TCP *:18790 (LISTEN)
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_lsof_output(output, &expected, 18790);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BindError::BoundToAllInterfaces { .. }));
    }

    #[test]
    fn parse_lsof_all_interfaces_rejected() {
        let output = "\
COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
node    12345 user   22u  IPv4 0x1234      0t0  TCP 0.0.0.0:18790 (LISTEN)
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_lsof_output(output, &expected, 18790);
        assert!(result.is_err());
    }

    #[test]
    fn parse_lsof_no_listeners() {
        let output = "\
COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_lsof_output(output, &expected, 18790).unwrap();
        assert!(!result);
    }

    #[test]
    fn parse_lsof_wrong_port_ignored() {
        let output = "\
COMMAND   PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
node    12345 user   22u  IPv4 0x1234      0t0  TCP 127.0.0.1:9999 (LISTEN)
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_lsof_output(output, &expected, 18790).unwrap();
        assert!(!result);
    }

    #[test]
    fn parse_ss_localhost_bound() {
        let output = "\
State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN 0      128     127.0.0.1:18790     0.0.0.0:*          users:((\"node\",pid=1234,fd=22))
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_ss_output(output, &expected, 18790).unwrap();
        assert!(result);
    }

    #[test]
    fn parse_ss_wildcard_rejected() {
        let output = "\
State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN 0      128     0.0.0.0:18790       0.0.0.0:*          users:((\"node\",pid=1234,fd=22))
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_ss_output(output, &expected, 18790);
        assert!(result.is_err());
    }

    #[test]
    fn parse_ss_no_listeners() {
        let output = "\
State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
";
        let expected: SocketAddr = "127.0.0.1:18790".parse().unwrap();
        let result = parse_ss_output(output, &expected, 18790).unwrap();
        assert!(!result);
    }

    #[test]
    fn bind_error_messages_are_descriptive() {
        let err = BindError::BoundToAllInterfaces {
            port: 18790,
            bound_addr: "*:18790".to_string(),
            expected_addr: "127.0.0.1:18790".parse().unwrap(),
        };
        let msg = err.to_string();
        assert!(msg.contains("security risk"));
        assert!(msg.contains("all interfaces"));
        assert!(msg.contains("localhost"));
    }
}
