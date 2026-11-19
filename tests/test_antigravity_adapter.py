"""Antigravity's PreToolUse wire contract for run_command.

Antigravity runs the command when a hook exits 0 with empty stdout, so every
path must print a decision or exit nonzero. An `ask` review is settled in a
desktop dialog and returned as auto_approve or deny; subprocess tests run headless,
where the dialog cannot open and an ask must therefore deny.
"""
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
ADAPTER = REPO / ".claude" / "hooks" / "antigravity-command-review-hook.py"
SPEC = importlib.util.spec_from_file_location("antigravity_adapter", ADAPTER)
assert SPEC and SPEC.loader
adapter_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter_module)


def payload_for(command: Any = "git diff", **args: Any) -> Dict[str, Any]:
    return {
        "conversationId": "c",
        "workspacePaths": ["/work/project"],
        "stepIdx": 2,
        "toolCall": {"name": "run_command",
                     "args": {"CommandLine": command, "WaitMsBeforeAsync": 5000, **args}},
    }


def run(payload: Any, extra_env: Optional[Dict[str, str]] = None,
        raw: Optional[bytes] = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"}
    env.update(extra_env or {})
    return subprocess.run([sys.executable, str(ADAPTER)],
                          input=raw if raw is not None else json.dumps(payload).encode("utf-8"),
                          env=env, capture_output=True, timeout=30)


def invoke(payload: Any, extra_env: Optional[Dict[str, str]] = None,
           raw: Optional[bytes] = None) -> Dict[str, Any]:
    proc = run(payload, extra_env, raw)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.decode("ascii"))


@pytest.mark.parametrize("command,review", [
    ("git diff", "allow"),
    ("git status --short --branch", "allow"),
    ("echo café 日本語", "allow"),
    ("rm *", "ask"),
    ("pip install requests", "ask"),
    ("git reset --hard", "deny"),
])
def test_decisions(command: str, review: str, tmp_path: Path) -> None:
    log = tmp_path / "review.jsonl"
    response = invoke(payload_for(command), {"CC_AI_REVIEW_LOG": str(log)})
    assert response["decision"] == ("auto_approve" if review == "allow" else "deny")
    assert set(response) <= {"decision", "reason"}  # never overwrite the command
    if review == "ask":
        assert "Confirmation dialog unavailable" in response["reason"]
    if review != "allow":
        assert response["reason"].strip()
    entry = json.loads(log.read_text(encoding="utf-8"))
    assert entry["decision"] == review
    assert entry["command"] == command
    assert entry["cwd"] == "/work/project"


def test_explicit_cwd_wins(tmp_path: Path) -> None:
    log = tmp_path / "review.jsonl"
    invoke(payload_for(Cwd="/elsewhere"), {"CC_AI_REVIEW_LOG": str(log)})
    assert json.loads(log.read_text(encoding="utf-8"))["cwd"] == "/elsewhere"


def test_multi_file_git_diff_auto_approves(tmp_path: Path) -> None:
    command = (
        "git diff docs/reasoning-action-questions-decisions-assumptions.md "
        "docs/design-docs/reasoning-action-questions-decisions-assumptions.md "
        "docs/TODO.md docs/deployment-and-operations.md "
        "src/Involvant.Signal.Web.Server/Program.cs "
        "src/Involvant.Signal.Web.Server/appsettings.json"
    )
    log = tmp_path / "review.jsonl"
    response = invoke(payload_for(command), {"CC_AI_REVIEW_LOG": str(log)})
    # Plain "allow" delegates to agy's request-review policy and still prompts.
    assert response == {"decision": "auto_approve"}
    entry = json.loads(log.read_text(encoding="utf-8"))
    assert entry["decision"] == "allow"
    assert entry["command"] == command


@pytest.mark.parametrize("raw", [b"", b"null", b"[]", b"{bad json", b"\xff"])
def test_invalid_input_denies(raw: bytes) -> None:
    assert invoke(None, raw=raw)["decision"] == "deny"


@pytest.mark.parametrize("command", [None, "", "  ", {}, [], True, 12])
def test_invalid_command_denies(command: Any) -> None:
    assert invoke(payload_for(command))["decision"] == "deny"


@pytest.mark.parametrize("change", [
    lambda p: p.pop("toolCall"),
    lambda p: p.update(toolCall=[]),
    lambda p: p["toolCall"].update(name="view_file"),
    lambda p: p["toolCall"].update(args=[]),
    lambda p: p["toolCall"].pop("args"),
    lambda p: p["toolCall"]["args"].update(Cwd=""),
    lambda p: p["toolCall"]["args"].update(Cwd=[]),
    lambda p: p.update(workspacePaths=[3]),
])
def test_wrong_envelope_denies(change: Any) -> None:
    payload = payload_for()
    change(payload)
    assert invoke(payload)["decision"] == "deny"


def test_bom_is_accepted() -> None:
    raw = b"\xef\xbb\xbf" + json.dumps(payload_for()).encode()
    assert invoke(None, raw=raw)["decision"] == "auto_approve"


@pytest.mark.parametrize("fail_mode", ["ask", "deny"])
def test_provider_failure_blocks_without_a_dialog(fail_mode: str) -> None:
    response = invoke(payload_for(), {"CC_AI_REVIEW__REVIEWER__PROVIDER": "invalid",
                                      "CC_AI_REVIEW__POLICY__FAIL_MODE": fail_mode})
    assert response["decision"] == "deny"


def test_bad_config_denies(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("policy: [unclosed", encoding="utf-8")
    assert invoke(payload_for(), {"CC_AI_REVIEW_CONFIG": str(cfg)})["decision"] == "deny"


@pytest.mark.parametrize("failure", [RuntimeError("review failed"), KeyboardInterrupt()])
def test_runtime_failure_denies(monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for())
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])

    def fail(*args: Any, **kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(adapter_module, "review_payload", fail)
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    assert adapter_module.main() == 0
    assert json.loads(output.getvalue())["decision"] == "deny"


@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
def test_broken_stdout_exits_nonzero(monkeypatch: pytest.MonkeyPatch, decision: str) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for())
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    result = ReviewResult("PreToolUse", "git diff", "/project", "",
                          Review(decision=decision, headline="review"))
    monkeypatch.setattr(adapter_module, "review_payload", lambda *a, **kw: result)
    monkeypatch.setattr(adapter_module, "confirm_command", lambda *args: True)

    class BrokenStream(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError("broken pipe")

    monkeypatch.setattr(sys, "stdout", BrokenStream())
    assert adapter_module.main() == 2


def test_unknown_review_decision_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for())
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    result = ReviewResult("PreToolUse", "git diff", "/project", "",
                          Review(decision="maybe", headline="review"))
    monkeypatch.setattr(adapter_module, "review_payload", lambda *a, **kw: result)
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    assert adapter_module.main() == 0
    assert json.loads(output.getvalue())["decision"] == "deny"


@pytest.mark.parametrize("raw", [b"", b"{bad json", json.dumps(payload_for()).encode(),
                                 json.dumps(payload_for("rm *")).encode()])
def test_never_succeeds_with_empty_stdout(raw: bytes) -> None:
    proc = run(None, raw=raw)
    assert proc.returncode != 0 or json.loads(proc.stdout)["decision"]


def run_main_with_review(monkeypatch: pytest.MonkeyPatch, decision: str,
                         confirm: Any, command: str = "rm build.log") -> Dict[str, Any]:
    monkeypatch.setattr(adapter_module, "read_hook_input", lambda: payload_for(command))
    monkeypatch.setattr(sys, "argv", [str(ADAPTER)])
    result = ReviewResult("PreToolUse", command, "/work/project", "",
                          Review(decision=decision, headline="Deletes a file"))
    monkeypatch.setattr(adapter_module, "review_payload", lambda *a, **kw: result)
    monkeypatch.setattr(adapter_module, "confirm_command", confirm)
    output = io.StringIO()
    monkeypatch.setattr(sys, "stdout", output)
    assert adapter_module.main() == 0
    return json.loads(output.getvalue())


@pytest.mark.parametrize("answer,decision", [(True, "auto_approve"), (False, "deny"),
                                             (None, "deny"), ("yes", "deny"), (1, "deny")])
def test_ask_waits_for_explicit_approval(monkeypatch: pytest.MonkeyPatch,
                                         answer: Any, decision: str) -> None:
    calls = []

    def confirm(command: str, cwd: str, reason: str) -> Any:
        calls.append((command, cwd, reason))
        return answer

    response = run_main_with_review(monkeypatch, "ask", confirm)
    assert response["decision"] == decision
    assert len(calls) == 1
    assert calls[0][:2] == ("rm build.log", "/work/project")
    assert "Deletes a file" in calls[0][2]
    if decision == "deny":
        assert "cancelled in the confirmation dialog" in response["reason"]
        assert "Deletes a file" in response["reason"]


@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_allow_and_deny_never_open_dialog(monkeypatch: pytest.MonkeyPatch, decision: str) -> None:
    calls = []
    response = run_main_with_review(monkeypatch, decision, lambda *a: calls.append(a))
    assert response["decision"] == ("auto_approve" if decision == "allow" else "deny")
    assert calls == []


@pytest.mark.parametrize("failure", [RuntimeError("display unavailable"), ImportError("no tk")])
def test_dialog_failure_denies_with_reason(monkeypatch: pytest.MonkeyPatch,
                                           failure: Exception) -> None:
    def fail(*args: Any) -> bool:
        raise failure

    response = run_main_with_review(monkeypatch, "ask", fail)
    assert response["decision"] == "deny"
    assert str(failure) in response["reason"]
    assert "Deletes a file" in response["reason"]


def test_dialog_uses_antigravity_title(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}
    fake = type(sys)("command_confirmation")
    fake.confirm_command = lambda command, cwd, reason, title: seen.update(title=title) or True
    monkeypatch.setitem(sys.modules, "command_confirmation", fake)
    assert adapter_module.confirm_command("rm x", "/w", "why") is True
    assert seen["title"] == "AI Command Review - Antigravity"


@pytest.mark.parametrize("command,decision", [("git diff", "auto_approve"), ("rm *", "deny")])
def test_incomplete_upgrade_never_passes_an_ask(command: str, decision: str,
                                                tmp_path: Path) -> None:
    install = tmp_path / "incomplete_install"
    install.mkdir()
    for name in [ADAPTER.name, "review_core.py", "config.py", "providers.py",
                 "exception_grants.py"]:
        shutil.copyfile(ADAPTER.with_name(name), install / name)
    proc = subprocess.run(
        [sys.executable, str(install / ADAPTER.name)],
        input=json.dumps(payload_for(command)).encode(), capture_output=True,
        env={**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"}, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    response = json.loads(proc.stdout)
    assert response["decision"] == decision
    if decision == "deny":
        assert "command_confirmation" in response["reason"]


def test_stats_does_not_read_stdin(tmp_path: Path) -> None:
    log = tmp_path / "reviews.jsonl"
    log.write_text(json.dumps({"ts": "2026-10-08T12:00:00+00:00", "decision": "ask",
                               "source": "local", "flags": []}) + "\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(ADAPTER), "--stats", str(log)],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert b"1 decisions" in proc.stdout


def test_shipped_example_allows() -> None:
    raw = (REPO / "examples/hook-input-antigravity.json").read_bytes()
    assert invoke(None, raw=raw)["decision"] == "auto_approve"


def test_shipped_hooks_example_matches_contract() -> None:
    cfg = json.loads((REPO / ".agents/hooks.json.example").read_text(encoding="utf-8"))
    (group,) = cfg["cc-ai-review"]["PreToolUse"]
    assert group["matcher"] == "^run_command$"
    (hook,) = group["hooks"]
    assert hook["command"].endswith("antigravity-command-review-hook.py")
    assert hook["timeout"] == 600  # leaves time to answer the dialog
    assert '"' not in hook["command"]  # quotes break under Windows cmd /c
