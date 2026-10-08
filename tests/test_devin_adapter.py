"""Devin's PermissionRequest wire contract, including the undecided ask path."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from review_core import Review, ReviewResult

REPO = Path(__file__).resolve().parent.parent
ADAPTER = REPO / ".claude" / "hooks" / "devin-command-review-hook.py"
SPEC = importlib.util.spec_from_file_location("devin_adapter", ADAPTER)
assert SPEC and SPEC.loader
adapter_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter_module)


def payload_for(command: Any = "git diff") -> Dict[str, Any]:
    return {"hook_event_name": "PermissionRequest", "tool_name": "exec",
            "tool_input": {"command": command, "shell_id": "main"}}


def invoke(payload: Any, extra_env: Optional[Dict[str, str]] = None,
           raw: Optional[bytes] = None) -> Dict[str, Any]:
    env = {**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"}
    env.update(extra_env or {})
    proc = subprocess.run([sys.executable, str(ADAPTER)],
                          input=raw if raw is not None else json.dumps(payload).encode("utf-8"),
                          env=env, capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.decode("ascii"))


@pytest.mark.parametrize("command,decision", [
    ("git diff", "approve"),
    ('git diff --check -- "docs/TODO.md"', "approve"),
    ("git status --short --branch", "approve"),
    ("echo café 日本語", "approve"),
    ("rm *", None),
    ("pip install requests", None),
    ("git reset --hard", "block"),
])
def test_permission_decisions(command: str, decision: Optional[str], tmp_path: Path) -> None:
    log = tmp_path / "review.jsonl"
    response = invoke(payload_for(command), {"CC_AI_REVIEW_LOG": str(log)})
    if decision is None:
        assert "decision" not in response  # abstain so the user is still asked
        assert response["reason"].strip()
    else:
        assert response["decision"] == decision
    entry = json.loads(log.read_text(encoding="utf-8"))
    assert entry["source"] == "local"
    assert entry["command"] == command
    if command == "rm *":
        assert entry["decision"] == "ask"


@pytest.mark.parametrize("raw", [b"", b"null", b"[]", b"{bad json", b"\xff"])
def test_invalid_input_blocks(raw: bytes) -> None:
    assert invoke(None, raw=raw)["decision"] == "block"


@pytest.mark.parametrize("command", [None, "", "  ", {}, [], True, 12])
def test_invalid_command_blocks(command: Any) -> None:
    assert invoke(payload_for(command))["decision"] == "block"


@pytest.mark.parametrize("changes", [
    {"hook_event_name": "PreToolUse"},
    {"hook_event_name": "PostToolUse"},
    {"tool_name": "edit"},
    {"tool_input": {}},
    {"tool_input": []},
    {"tool_input": {"command": "git diff", "cwd": []}},
])
def test_wrong_envelope_blocks(changes: Dict[str, Any]) -> None:
    assert invoke({**payload_for(), **changes})["decision"] == "block"


def test_cwd_and_bom_are_preserved(tmp_path: Path) -> None:
    payload = payload_for()
    payload["tool_input"]["cwd"] = "/work/project"
    log = tmp_path / "review.jsonl"
    response = invoke(None, {"CC_AI_REVIEW_LOG": str(log)},
                      raw=b"\xef\xbb\xbf" + json.dumps(payload).encode())
    assert response["decision"] == "approve"
    assert json.loads(log.read_text())["cwd"] == "/work/project"


@pytest.mark.parametrize("fail_mode,expected", [("ask", None), ("deny", "block")])
def test_provider_failure_uses_configured_fallback(fail_mode: str, expected: Optional[str]) -> None:
    response = invoke(payload_for(), {"CC_AI_REVIEW__REVIEWER__PROVIDER": "invalid",
                                      "CC_AI_REVIEW__POLICY__FAIL_MODE": fail_mode})
    assert response.get("decision") == expected
    assert response["reason"].strip()


def test_bad_config_blocks(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("policy: [unclosed", encoding="utf-8")
    assert invoke(payload_for(), {"CC_AI_REVIEW_CONFIG": str(cfg)})["decision"] == "block"


@pytest.mark.parametrize("failure", [RuntimeError("review failed"), KeyboardInterrupt()])
def test_runtime_failure_blocks(monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for())
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])

    def fail(*args: Any, **kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(adapter_module, "review_payload", fail)
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    assert adapter_module.main() == 0
    assert json.loads(output.getvalue())["decision"] == "block"


@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
def test_broken_stdout_blocks(monkeypatch: pytest.MonkeyPatch, decision: str) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for())
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    result = ReviewResult("PermissionRequest", "git diff", "/project", "",
                          Review(decision=decision, headline="review"))
    monkeypatch.setattr(adapter_module, "review_payload", lambda *a, **kw: result)

    class BrokenStream(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError("broken pipe")

    monkeypatch.setattr(sys, "stdout", BrokenStream())
    assert adapter_module.main() == 2


def test_stats_does_not_read_stdin(tmp_path: Path) -> None:
    log = tmp_path / "reviews.jsonl"
    log.write_text(json.dumps({"ts": "2026-10-08T12:00:00+00:00", "decision": "ask",
                               "source": "local", "flags": []}) + "\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(ADAPTER), "--stats", str(log)],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert b"1 decisions" in proc.stdout


def test_shipped_example_approves() -> None:
    raw = (REPO / "examples/hook-input-devin-permission-request.json").read_bytes()
    assert invoke(None, raw=raw)["decision"] == "approve"
