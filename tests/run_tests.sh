#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_LOG="$PROJECT_DIR/audit.jsonl"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
MOCK_PID=""
MITTS_PID=""

cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    [ -n "$MITTS_PID" ] && kill "$MITTS_PID" 2>/dev/null && echo "Stopped safety-mitts ($MITTS_PID)"
    [ -n "$MOCK_PID" ]  && kill "$MOCK_PID"  2>/dev/null && echo "Stopped mock server ($MOCK_PID)"
    # Give processes a moment to exit.
    sleep 1
    # Force-kill if still running.
    [ -n "$MITTS_PID" ] && kill -9 "$MITTS_PID" 2>/dev/null || true
    [ -n "$MOCK_PID" ]  && kill -9 "$MOCK_PID"  2>/dev/null || true
    echo ""
}
trap cleanup EXIT

# ── 1. Build safety-mitts ──────────────────────────────────────────────
echo "=== Building safety-mitts ==="
source "$HOME/.cargo/env"
cd "$PROJECT_DIR"
cargo build --release 2>&1 | tail -3
MITTS_BIN="$PROJECT_DIR/target/release/safety-mitts"
echo "Binary: $MITTS_BIN"
echo ""

# ── 2. Remove old audit log ───────────────────────────────────────────
rm -f "$AUDIT_LOG"

# ── 3. Start mock OpenClaw server ─────────────────────────────────────
echo "=== Starting mock OpenClaw server on :18790 ==="
"$VENV_PYTHON" "$SCRIPT_DIR/mock_openclaw.py" &
MOCK_PID=$!
sleep 1

if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "ERROR: Mock server failed to start"
    exit 1
fi
echo "Mock server PID: $MOCK_PID"
echo ""

# ── 4. Start safety-mitts (without supervisor, just the proxy) ────────
# We run the mock server ourselves, so we need safety-mitts to NOT try
# to launch OpenClaw as a child process. We'll use a dummy binary that
# exits immediately — the supervisor will restart it but the proxy still
# works because the mock is already listening on :18790.
#
# Actually, we can just point --openclaw-bin at /usr/bin/true which exits
# immediately. The supervisor will keep trying to restart it, but the
# proxy connects to whatever is on :18790 (our mock).

echo "=== Starting safety-mitts proxy ==="
"$MITTS_BIN" \
    --config "$PROJECT_DIR/config/config.yaml" \
    --policy "$PROJECT_DIR/config/default-policy.yaml" \
    --openclaw-bin /usr/bin/true \
    --listen "127.0.0.1:18789" \
    --upstream "127.0.0.1:18790" \
    2>"$PROJECT_DIR/test-mitts-stderr.log" &
MITTS_PID=$!
sleep 3

if ! kill -0 "$MITTS_PID" 2>/dev/null; then
    echo "ERROR: safety-mitts failed to start. Stderr:"
    cat "$PROJECT_DIR/test-mitts-stderr.log"
    exit 1
fi
echo "safety-mitts PID: $MITTS_PID"
echo ""

# ── 5. Run test client ───────────────────────────────────────────────
echo "=== Running functional tests ==="
"$VENV_PYTHON" "$SCRIPT_DIR/test_client.py"
TEST_EXIT=$?

# ── 6. Check audit log ──────────────────────────────────────────────
echo "=== Audit Log Summary ==="
if [ -f "$AUDIT_LOG" ]; then
    TOTAL=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
    BLOCKED=$(grep -c '"exec_blocked"' "$AUDIT_LOG" 2>/dev/null || echo 0)
    OPENED=$(grep -c '"connection_opened"' "$AUDIT_LOG" 2>/dev/null || echo 0)
    FLAGGED=$(grep -c '"message_relayed"' "$AUDIT_LOG" 2>/dev/null || echo 0)
    INJECTION=$(grep -c '"prompt_injection_detected"' "$AUDIT_LOG" 2>/dev/null || echo 0)
    echo "  Total entries:         $TOTAL"
    echo "  Connections opened:    $OPENED"
    echo "  Messages blocked:      $BLOCKED"
    echo "  Messages flagged:      $FLAGGED"
    echo "  Injections detected:   $INJECTION"
else
    echo "  (no audit log found at $AUDIT_LOG)"
fi
echo ""

exit $TEST_EXIT
