# safety-mitts

Security wrapper for [OpenClaw](https://github.com/topics/openclaw). Sits between clients and OpenClaw as a WebSocket reverse proxy, enforcing security policies and detecting prompt injection — without limiting the agent's autonomy.

## What it does

safety-mitts wraps OpenClaw as a parent process and proxies all WebSocket traffic through an inspection pipeline:

```
Client :18789 ──> safety-mitts proxy ──> OpenClaw :18790 (localhost only)
                       │
                  ┌────┴────┐
                  │ inspect │
                  ├─────────┤
                  │ policy  │  ← YAML-defined tiered rules
                  │ engine  │    (auto-allow / soft-gate / hard-gate)
                  ├─────────┤
                  │ prompt  │  ← 17 regex patterns for injection
                  │sanitizer│    detection (flag / strip / wrap)
                  ├─────────┤
                  │ audit   │  ← append-only JSON-lines log
                  │ logger  │    of every action
                  └─────────┘
```

**Key features:**

- **Command broker** — evaluates shell commands against tiered YAML rules. Blocks reverse shells, `rm -rf /`, crypto miners, credential access. Flags network requests, package installs, sudo.
- **Method-level policy** — blocks config tampering and approval disabling (CVE-2026-25253 kill chain).
- **Prompt injection firewall** — scans downstream content for 17 injection patterns (instruction override, role hijacking, delimiter escape, data exfiltration). Configurable: flag, strip, or wrap.
- **Network binding guard** — forces OpenClaw to bind to localhost only via environment variable injection. Verifies with `lsof`/`ss` after startup.
- **Origin validation** — rejects WebSocket connections from non-localhost origins (prevents cross-site WebSocket hijacking).
- **Process supervisor** — launches OpenClaw as a child process, monitors for crashes, auto-restarts with configurable limits, graceful SIGTERM→SIGKILL shutdown.
- **Audit trail** — every connection, command, block, and flag is logged to an append-only JSON-lines file.

## Quick start

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.70+)
- OpenClaw installed and accessible in your PATH

### Install

```bash
git clone https://github.com/Maxusmusti/safety-mitts.git
cd safety-mitts
cargo build --release
```

The binary is at `target/release/safety-mitts`.

### Run

The simplest way to start — safety-mitts will launch OpenClaw for you:

```bash
# Copy the default config and policy into your working directory
cp config/config.yaml .
cp config/default-policy.yaml policy.yaml

# Run (will spawn OpenClaw as a child process)
./target/release/safety-mitts
```

safety-mitts takes over port 18789 (OpenClaw's default). Point your clients (browser, Telegram, etc.) at `ws://localhost:18789` as before — everything is transparent.

### CLI options

```
safety-mitts [OPTIONS]

Options:
  -c, --config <PATH>         Config file [default: config.yaml]
  -p, --policy <PATH>         Policy file (overrides config)
      --openclaw-bin <PATH>   Path to OpenClaw binary (overrides config)
      --listen <ADDR>         Listen address (overrides config)
      --upstream <ADDR>       Upstream address (overrides config)
  -h, --help                  Print help
  -V, --version               Print version
```

### Examples

```bash
# Use a custom OpenClaw binary location
safety-mitts --openclaw-bin /usr/local/bin/openclaw

# Listen on a different port
safety-mitts --listen 127.0.0.1:9000

# Use a stricter policy file
safety-mitts --policy my-strict-policy.yaml

# If OpenClaw is already running, just point the proxy at it
safety-mitts --openclaw-bin /usr/bin/true --upstream 127.0.0.1:18790
```

## Configuration

### config.yaml

```yaml
openclaw:
  binary: "openclaw"              # Path to OpenClaw binary
  args: ["gateway", "start"]      # Arguments passed on startup
  max_restarts: 5                 # Auto-restart limit
  restart_delay_secs: 3           # Delay between restarts

network:
  listen_addr: "127.0.0.1:18789"  # External-facing proxy port
  upstream_addr: "127.0.0.1:18790" # Internal OpenClaw port

logging:
  level: "info"                   # trace/debug/info/warn/error
  audit_log_path: "./audit.jsonl" # Append-only audit log

policy_file: "./policy.yaml"      # Path to policy rules

sanitizer:
  enabled: true                   # Enable prompt injection scanning
  mode: "flag"                    # "flag" | "strip" | "wrap"
```

### Policy rules

The policy file defines tiered rules evaluated in priority order (lower number = higher priority):

| Action | Behavior |
|--------|----------|
| `auto_allow` | Pass silently, minimal logging |
| `soft_gate` | Allow but log a warning |
| `hard_gate` | Block entirely |

Each rule has matchers that can match on:

- **Command patterns** — glob (`rm -rf /*`) or regex (`bash\s+-i\s+>&\s+/dev/tcp/`)
- **File paths** — glob patterns with operation filters (`read`, `write`, `delete`, `exec`)
- **Method names** — pipe-separated exact matches (`config.set|config.patch`)
- **Network destinations** — hostname globs with optional port filters

See [`config/default-policy.yaml`](config/default-policy.yaml) for the full default ruleset.

### Prompt sanitizer modes

| Mode | Behavior |
|------|----------|
| `flag` | Log the detection, pass content through unchanged (default) |
| `strip` | Replace matched injection text with `[REDACTED]` |
| `wrap` | Surround matched text with `[UNTRUSTED_CONTENT_START]`/`[UNTRUSTED_CONTENT_END]` |

## Audit log

Every action is recorded in the audit log (`audit.jsonl`), one JSON object per line:

```json
{"id":"a1b2c3...","timestamp":"2026-02-16T23:02:59Z","event_type":"exec_blocked","source":{"component":"policy-engine","remote_addr":"127.0.0.1:51030"},"details":{"method":"agent.execute","command":"rm -rf /"},"policy_decision":{"action":"block","matched_rule":"block-destructive-commands","reason":"Block catastrophically destructive commands"}}
```

Event types: `connection_opened`, `connection_closed`, `origin_rejected`, `exec_blocked`, `exec_soft_gated`, `message_relayed`, `prompt_injection_detected`, `process_started`, `process_stopped`, `policy_reloaded`.

## Architecture

```
safety-mitts/
├── crates/
│   ├── audit-log/          # Async append-only JSON-lines logger
│   ├── net-guard/           # Localhost binding enforcement
│   ├── policy-engine/       # YAML policy loader + tiered rule evaluator
│   ├── prompt-sanitizer/    # Prompt injection pattern scanner
│   ├── ws-proxy/            # WebSocket reverse proxy with inspector chain
│   └── safety-mitts/        # Main binary: CLI, config, supervisor
├── config/
│   ├── config.yaml          # Runtime configuration
│   └── default-policy.yaml  # Default security rules (16 rules)
└── tests/
    ├── mock_openclaw.py     # Mock WebSocket server for testing
    ├── test_client.py       # 9 end-to-end test scenarios
    └── run_tests.sh         # Test orchestration script
```

## Testing

### Unit tests (98 tests)

```bash
cargo test
```

### Functional tests (9 scenarios)

Requires Python 3 with the `websockets` package:

```bash
# Set up the test venv (first time only)
python3 -m venv tests/.venv
tests/.venv/bin/pip install websockets

# Run all functional tests
./tests/run_tests.sh
```

The functional test suite verifies:
1. Basic WebSocket relay
2. Safe commands pass through
3. Dangerous commands blocked (`rm -rf /`)
4. Method-level blocking (`config.set`)
5. Soft-gated commands flagged but allowed (`curl`)
6. Prompt injection detection in downstream content
7. Non-JSON message passthrough
8. Reverse shell pattern blocking
9. Origin validation (rejects `https://evil.com`)

## License

MIT
