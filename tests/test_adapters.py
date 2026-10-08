"""Adapter response schemas, exercised as the hosts actually invoke them.

Each adapter is run as a real subprocess with JSON on stdin, because that is the
only thing Claude Code and Codex ever see. A schema regression here is silent:
the hook keeps exiting 0, the host cannot parse the decision, and every command
sails through. `review_payload` tests cannot catch that -- they stop one layer
short of the wire format.

The subprocess environment is scrubbed so these never make a network call: the
repository `.env` carries a real API key, and `dotenv_candidates()` includes the
project root, so an unscrubbed run would hit a live provider.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

HOOKS = Path(__file__).resolve().parent.parent / ".claude" / "hooks"
CLAUDE_ADAPTER = HOOKS / "safe-command-review-hook.py"
CODEX_ADAPTER = HOOKS / "codex-command-review-hook.py"


def run_adapter(adapter: Path, payload: Any, extra_env: Dict[str, str] | None = None,
                raw: bytes | None = None) -> Dict[str, Any]:
    env = {
        k: v for k, v in os.environ.items()
        if not k.startswith("CC_AI_REVIEW") and k not in {
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
            "CLAUDE_PROJECT_DIR", "CODEX_PROJECT_DIR",
        }
    }
    # "none" is a supported provider value; it keeps the run entirely local even
    # though the repo .env will still be found and its key loaded.
    env["CC_AI_REVIEW__REVIEWER__PROVIDER"] = "none"
    env.update(extra_env or {})

    stdin = raw if raw is not None else json.dumps(payload).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, str(adapter)], input=stdin, capture_output=True, env=env,
    )
    assert proc.returncode == 0, f"adapter exited {proc.returncode}: {proc.stderr[:400]!r}"
    text = proc.stdout.decode("utf-8").strip()
    assert text, f"adapter produced no stdout; stderr={proc.stderr[:400]!r}"
    out = json.loads(text)

    # Hermeticity guard. The repo `.env` holds a real key and the project root is
    # always a `.env` candidate, so a mistake in the scrubbing above turns this
    # whole file into a paid, network-dependent suite -- which is exactly what
    # happened once. `source` is "combined" only when a provider was actually
    # called, so assert it never is.
    source = out.get("metadata", {}).get("source")
    assert source != "combined", (
        "adapter reached a live provider; these tests must stay offline"
    )
    return out


def bash(command: str, event: str = "PreToolUse", tool: str = "Bash") -> Dict[str, Any]:
    return {"hook_event_name": event, "tool_name": tool,
            "tool_input": {"command": command}}


# ------------------------------------------------------- Claude Code adapter

@pytest.mark.parametrize("command,expected", [
    ("git status", "allow"),
    ("pip install requests", "ask"),
    ("git reset --hard", "deny"),
])
def test_claude_adapter_schema(command: str, expected: str) -> None:
    out = run_adapter(CLAUDE_ADAPTER, bash(command))
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == expected
    assert isinstance(hso["permissionDecisionReason"], str)
    assert hso["permissionDecisionReason"].strip()
    meta = out["metadata"]
    assert meta["tool_name"] == "Bash"
    assert isinstance(meta["flags"], list)
    assert isinstance(meta["dont_ask_again_safe"], bool)


def test_claude_adapter_preserves_permission_request_event_name() -> None:
    """The host matches the response to the event it sent; echoing the wrong
    name silently detaches the decision from the request."""
    out = run_adapter(CLAUDE_ADAPTER, bash("git status", event="PermissionRequest"))
    assert out["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"


# -------------------------------------------------------------- Codex adapter

def test_codex_pretooluse_allow_is_silent() -> None:
    """Allow carries no systemMessage on purpose: a message on every safe
    command is noise the user learns to ignore."""
    out = run_adapter(CODEX_ADAPTER, bash("git status"))
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert "systemMessage" not in out
    assert "decision" not in out


def test_codex_pretooluse_ask_surfaces_a_message() -> None:
    out = run_adapter(CODEX_ADAPTER, bash("pip install requests"))
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["systemMessage"].strip()
    assert "decision" not in out


def test_codex_pretooluse_deny_blocks_with_a_reason() -> None:
    out = run_adapter(CODEX_ADAPTER, bash("git reset --hard"))
    assert out["decision"] == "block"
    assert out["reason"].strip()
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


@pytest.mark.parametrize("command,behavior", [
    ("git status", "allow"),
    ("git reset --hard", "deny"),
])
def test_codex_permission_request_decision_block(command: str, behavior: str) -> None:
    out = run_adapter(CODEX_ADAPTER, bash(command, event="PermissionRequest"))
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PermissionRequest"
    assert hso["decision"]["behavior"] == behavior
    assert hso["decision"]["message"].strip()


def test_codex_permission_request_ask_has_no_decision() -> None:
    """Codex has no enforceable third state, so ask must not claim a decision --
    it advises via systemMessage and lets Codex's own gate run."""
    out = run_adapter(CODEX_ADAPTER, bash("pip install requests",
                                          event="PermissionRequest"))
    assert "decision" not in out["hookSpecificOutput"]
    assert out["systemMessage"].strip()


# ------------------------------------------------------------ failure modes

@pytest.mark.parametrize("adapter", [CLAUDE_ADAPTER, CODEX_ADAPTER])
def test_malformed_stdin_still_produces_parsable_json(adapter: Path) -> None:
    """A host that cannot parse the response has no decision at all. Whatever
    goes wrong, the adapter must still emit valid JSON."""
    out = run_adapter(adapter, None, raw=b"{not json at all")
    assert isinstance(out, dict)
    assert "hookSpecificOutput" in out


@pytest.mark.parametrize("adapter", [CLAUDE_ADAPTER, CODEX_ADAPTER])
def test_empty_stdin_still_produces_parsable_json(adapter: Path) -> None:
    out = run_adapter(adapter, None, raw=b"")
    assert isinstance(out, dict)
    assert "hookSpecificOutput" in out


def test_claude_adapter_denies_unparsable_input(tmp_path: Path) -> None:
    """A reviewer that cannot read the command cannot clear it."""
    out = run_adapter(CLAUDE_ADAPTER, None, raw=b"{not json at all")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_adapter_blocks_unparsable_input() -> None:
    """Codex treats `ask` on PreToolUse as advisory, so the previous `ask` let a
    corrupt payload run entirely unreviewed."""
    out = run_adapter(CODEX_ADAPTER, None, raw=b"{not json at all")
    assert out["decision"] == "block"


@pytest.mark.parametrize("adapter", [CLAUDE_ADAPTER, CODEX_ADAPTER])
def test_adapter_responses_are_pure_ascii(adapter: Path) -> None:
    """Emitted with ensure_ascii=True so a console on a legacy code page cannot
    fail part-way through the line. A half-written line is invalid JSON, and a
    response the host cannot parse is no decision at all."""
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "echo café ünïcode 日本語"}}
    proc = subprocess.run(
        [sys.executable, str(adapter)], input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        env={**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"},
    )
    assert proc.returncode == 0
    proc.stdout.decode("ascii")  # raises if any non-ASCII byte was written
    assert json.loads(proc.stdout.decode("ascii"))


@pytest.mark.parametrize("adapter", [CLAUDE_ADAPTER, CODEX_ADAPTER])
def test_stats_mode_does_not_read_stdin(adapter: Path, tmp_path: Path) -> None:
    """`sys.stdin.read()` blocks on a terminal, so arguments must be handled
    before the payload is read or `--stats` simply hangs. stdin is closed here,
    which is what an interactive invocation looks like to the adapter."""
    log = tmp_path / "reviews.jsonl"
    log.write_text(
        json.dumps({"ts": "2026-08-01T10:00:00+00:00", "decision": "allow",
                    "source": "local", "flags": ["readonly-or-test"]}) + "\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(adapter), "--stats", str(log)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "1 decisions" in proc.stdout
    assert "readonly-or-test" in proc.stdout


def test_claude_adapter_fails_closed_on_broken_config(tmp_path: Path) -> None:
    """A config file that cannot be honoured must not degrade to permissive
    defaults; it must surface as a prompt explaining what to fix."""
    bad = tmp_path / "config.yaml"
    bad.write_text("policy:\n  fail_mode: [unclosed\n", encoding="utf-8")
    out = run_adapter(CLAUDE_ADAPTER, bash("git status"),
                      extra_env={"CC_AI_REVIEW_CONFIG": str(bad)})
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "ask"
    assert "misconfigured" in hso["permissionDecisionReason"].lower()
    assert out["metadata"]["source"] == "config-error"


def test_quoted_boolean_in_config_is_rejected_not_silently_inverted(
    tmp_path: Path
) -> None:
    """`allow_readonly: "false"` must not read as True. bool("false") is True,
    which would quietly re-enable the allow-list the user meant to disable."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text('policy:\n  allow_readonly: "false"\n', encoding="utf-8")
    out = run_adapter(CLAUDE_ADAPTER, bash("git status"),
                      extra_env={"CC_AI_REVIEW_CONFIG": str(cfg)})
    # allow_readonly is genuinely off, so a read-only command now prompts
    # rather than being auto-allowed.
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
