"""Exercise the actual stdin/stderr/exit-code contract for both IDE agents."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from review_core import Review, ReviewResult

pytestmark = pytest.mark.usefixtures("headless_confirmation")

REPO = Path(__file__).resolve().parent.parent
ADAPTER = REPO / ".claude" / "hooks" / "windsurf-command-review-hook.py"
SPEC = importlib.util.spec_from_file_location("windsurf_adapter", ADAPTER)
assert SPEC and SPEC.loader
adapter_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter_module)


def payload_for(agent: str, command: Any = "git status") -> Dict[str, Any]:
    if agent == "cascade":
        return {"agent_action_name": "pre_run_command",
                "tool_info": {"command_line": command, "cwd": "/project"}}
    return {"hook_event_name": "PreToolUse", "tool_name": "exec",
            "tool_input": {"command": command, "shell_id": "main"}}


def invoke(payload: Any, extra_env: Optional[Dict[str, str]] = None,
           raw: Optional[bytes] = None) -> subprocess.CompletedProcess:
    # conftest isolates config discovery; disabling the provider also keeps the
    # repository's real .env key from causing an external call in the subprocess.
    env = {**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"}
    env.update(extra_env or {})
    proc = subprocess.run(
        [sys.executable, str(ADAPTER)],
        input=raw if raw is not None else json.dumps(payload).encode("utf-8"),
        capture_output=True, env=env, timeout=30,
    )
    assert proc.stdout == b""  # no foreign JSON decision or noisy allow output
    return proc


@pytest.mark.parametrize("agent", ["cascade", "devin"])
@pytest.mark.parametrize("command,code", [
    ("git status", 0),
    ("pip install requests", 2),  # no GUI available in the subprocess fixture
    ("git reset --hard", 2),
    ("rm report.txt", 2),
    ("cat ~/.ssh/id_rsa", 2),
    ("echo café 日本語", 0),
])
def test_decisions(agent: str, command: str, code: int, tmp_path: Path) -> None:
    log = tmp_path / "reviews.jsonl"
    proc = invoke(payload_for(agent, command), {"CC_AI_REVIEW_LOG": str(log)})
    assert proc.returncode == code, proc.stderr
    if code == 0:
        assert proc.stderr == b""
    else:
        assert proc.stderr.decode("utf-8").strip()
    entry = json.loads(log.read_text(encoding="utf-8"))
    assert entry["command"] == command
    assert entry["source"] == "local"
    assert entry["cwd"] == ("/project" if agent == "cascade" else str(Path.cwd()))
    if command == "pip install requests":
        assert entry["decision"] == "ask"
        expected = (b"Confirmation dialog unavailable" if agent == "cascade"
                    else b"Legacy Devin PreToolUse cannot prompt")
        assert expected in proc.stderr


@pytest.mark.parametrize("raw", [
    b"", b"{invalid json", b"[]", b"null", b"42", b'"text"', b"\xff",
])
def test_invalid_stdin_blocks(raw: bytes) -> None:
    proc = invoke(None, raw=raw)
    assert proc.returncode == 2
    assert b"failed closed" in proc.stderr


@pytest.mark.parametrize("agent", ["cascade", "devin"])
@pytest.mark.parametrize("command", [None, "", "  ", [], {}, 123, True])
def test_invalid_command_blocks(agent: str, command: Any) -> None:
    proc = invoke(payload_for(agent, command))
    assert proc.returncode == 2
    assert b"nonempty string" in proc.stderr


@pytest.mark.parametrize("payload", [
    {},
    {"agent_action_name": "pre_run_command"},
    {"agent_action_name": "pre_run_command", "tool_info": []},
    {"agent_action_name": "post_run_command", "tool_info": {"command_line": "git status"}},
    {"hook_event_name": "PostToolUse", "tool_name": "exec",
     "tool_input": {"command": "git status"}},
    {"hook_event_name": "PreToolUse", "tool_name": "edit",
     "tool_input": {"command": "git status"}},
    {"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": {}},
    {"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": "git status"},
])
def test_wrong_envelope_blocks(payload: Any) -> None:
    assert invoke(payload).returncode == 2


@pytest.mark.parametrize("agent", ["cascade", "devin"])
@pytest.mark.parametrize("cwd", [[], {}, 42, "", "  "])
def test_invalid_cwd_blocks(agent: str, cwd: Any) -> None:
    payload = payload_for(agent)
    payload["tool_info" if agent == "cascade" else "tool_input"]["cwd"] = cwd
    assert invoke(payload).returncode == 2


@pytest.mark.parametrize("agent", ["cascade", "devin"])
def test_bom_input(agent: str) -> None:
    raw = b"\xef\xbb\xbf" + json.dumps(payload_for(agent)).encode("utf-8")
    assert invoke(None, raw=raw).returncode == 0


@pytest.mark.parametrize("agent", ["cascade", "devin"])
def test_broken_config_blocks(agent: str, tmp_path: Path) -> None:
    cfg = tmp_path / "broken.yaml"
    cfg.write_text("policy: [unclosed", encoding="utf-8")
    proc = invoke(payload_for(agent), {"CC_AI_REVIEW_CONFIG": str(cfg)})
    assert proc.returncode == 2
    assert b"ConfigError" in proc.stderr


@pytest.mark.parametrize("agent", ["cascade", "devin"])
def test_reviewer_failure_blocks(agent: str) -> None:
    proc = invoke(payload_for(agent), {"CC_AI_REVIEW__REVIEWER__PROVIDER": "invalid"})
    assert proc.returncode == 2
    expected = (b"Confirmation dialog unavailable" if agent == "cascade"
                else b"Legacy Devin PreToolUse cannot prompt")
    assert expected in proc.stderr


@pytest.mark.parametrize("answer,code", [(True, 0), (False, 2), (None, 2), ("yes", 2)])
def test_ask_waits_for_explicit_approval(monkeypatch: pytest.MonkeyPatch,
                                        answer: Any, code: int) -> None:
    command = "bash scripts/test-db.sh EventDetailsJurisdictionTests"
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for("cascade", command))
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    result = ReviewResult("PreToolUse", command, "/project", "",
                          Review("ask", "Test script needs confirmation"))
    monkeypatch.setattr(adapter_module, "review_payload", lambda *a, **kw: result)
    calls = []

    def confirm(command: str, cwd: str, reason: str) -> Any:
        calls.append((command, cwd, reason))
        return answer

    monkeypatch.setattr(adapter_module, "confirm_command", confirm)
    assert adapter_module.main() == code
    assert len(calls) == 1
    assert calls[0][:2] == (command, "/project")
    assert "Test script needs confirmation" in calls[0][2]


@pytest.mark.parametrize("decision,code", [("allow", 0), ("deny", 2)])
def test_allow_and_deny_never_open_dialog(monkeypatch: pytest.MonkeyPatch,
                                         decision: str, code: int) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for("cascade"))
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    result = ReviewResult("PreToolUse", "git status", "/project", "", Review(decision, "review"))
    monkeypatch.setattr(adapter_module, "review_payload", lambda *a, **kw: result)
    calls = []
    monkeypatch.setattr(adapter_module, "confirm_command", lambda *args: calls.append(args))
    assert adapter_module.main() == code
    assert calls == []


def test_dialog_error_blocks_with_original_reason(monkeypatch: pytest.MonkeyPatch,
                                                  capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for("cascade", "rm *"))
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])

    def fail(*args: Any) -> bool:
        raise RuntimeError("display unavailable")

    monkeypatch.setattr(adapter_module, "confirm_command", fail)
    assert adapter_module.main() == 2
    error = capsys.readouterr().err
    assert "display unavailable" in error
    assert "delet" in error.lower()


@pytest.mark.parametrize("command,code", [("git diff", 0), ("rm *", 2)])
def test_incomplete_upgrade_never_passes_an_ask(command: str, code: int, tmp_path: Path) -> None:
    install = tmp_path / "incomplete_install"
    install.mkdir()
    for name in [ADAPTER.name, "review_core.py", "config.py", "providers.py",
                 "exception_grants.py"]:
        shutil.copyfile(ADAPTER.with_name(name), install / name)
    proc = subprocess.run(
        [sys.executable, str(install / ADAPTER.name)],
        input=json.dumps(payload_for("cascade", command)).encode(), capture_output=True,
        env={**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"}, timeout=30,
    )
    assert proc.returncode == code
    if code == 2:
        assert b"Confirmation dialog unavailable" in proc.stderr
        assert b"command_confirmation" in proc.stderr


@pytest.mark.parametrize("failure", [RuntimeError("review failed"), KeyboardInterrupt()])
def test_unexpected_failure_blocks(monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for("cascade"))

    def fail(*args: Any, **kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(adapter_module, "review_payload", fail)
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    assert adapter_module.main() == 2
    assert "failed closed" in stderr.getvalue()


def test_broken_stderr_still_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenStream(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError("broken pipe")

    monkeypatch.setattr(sys, "stderr", BrokenStream())
    assert adapter_module.block("reason") == 2


def test_stats_does_not_read_hook_stdin(tmp_path: Path) -> None:
    log = tmp_path / "reviews.jsonl"
    log.write_text(json.dumps({"ts": "2026-10-08T12:00:00+00:00", "decision": "ask",
                               "source": "local", "flags": []}) + "\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(ADAPTER), "--stats", str(log)],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert b"1 decisions" in proc.stdout


@pytest.mark.parametrize("filename", ["hook-input-windsurf.json", "hook-input-devin-pretool.json"])
def test_shipped_dangerous_examples_block(filename: str) -> None:
    assert invoke(None, raw=(REPO / "examples" / filename).read_bytes()).returncode == 2
