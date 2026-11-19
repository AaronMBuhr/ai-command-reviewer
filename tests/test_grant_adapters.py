"""Exception grants end to end through every host adapter (plan Phase 4).

For each adapter: a denied command's reason carries the help block; the block,
with a name filled in and converted the way the writer converts it, becomes a
grant; the same payload then gets the adapter's own "allow" output.

Windows only, because grants are. The store's integrity check is replaced by a
test-only wrapper script, since a temp folder can never pass it. The real check
is covered in test_grant_integrity.py, and nothing here changes production code.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import pytest
from grant_fixtures import canonical_line

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="exception grants are Windows-only"),
    pytest.mark.usefixtures("headless_confirmation"),
]

HOOKS = Path(__file__).resolve().parent.parent / ".claude" / "hooks"
COMMAND = "git reset --hard"
WIN_CWD = "C:\\work\\proj"

WRAPPER = """\
import runpy, sys
hooks, adapter = sys.argv[1], sys.argv[2]
sys.path.insert(0, hooks)
import exception_grants
exception_grants.check_store = lambda *args, **kwargs: []   # test-only
sys.argv = [adapter] + sys.argv[3:]
runpy.run_path(adapter, run_name="__main__")
"""


def run(tmp_path: Path, adapter: str, payload: Dict[str, Any],
        grants: Path) -> subprocess.CompletedProcess:
    wrapper = tmp_path / "run_adapter.py"
    wrapper.write_text(WRAPPER, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("CC_AI_REVIEW")}
    env.update({
        "CC_AI_REVIEW__REVIEWER__PROVIDER": "none",
        "CC_AI_REVIEW__EXCEPTIONS__ENABLED": "true",
        "CC_AI_REVIEW__EXCEPTIONS__GRANTS_PATH": str(grants),
        "CC_AI_REVIEW_LOG": str(tmp_path / "decisions.jsonl"),
    })
    return subprocess.run(
        [sys.executable, str(wrapper), str(HOOKS), str(HOOKS / adapter)],
        input=json.dumps(payload).encode("utf-8"), capture_output=True, env=env, timeout=60,
    )


def stdout_json(proc: subprocess.CompletedProcess) -> Dict[str, Any]:
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.decode("utf-8"))


# Each host: (adapter file, payload, reason-on-deny extractor, is-allow check).
Host = Tuple[str, Dict[str, Any], Callable[[subprocess.CompletedProcess], str],
             Callable[[subprocess.CompletedProcess], bool]]

HOSTS: Dict[str, Host] = {
    "claude": (
        "safe-command-review-hook.py",
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": WIN_CWD,
         "tool_input": {"command": COMMAND}},
        lambda p: stdout_json(p)["hookSpecificOutput"]["permissionDecisionReason"],
        lambda p: stdout_json(p)["hookSpecificOutput"]["permissionDecision"] == "allow",
    ),
    "codex": (
        "codex-command-review-hook.py",
        {"hook_event_name": "PreToolUse", "tool_name": "shell", "cwd": "/home/dev/proj",
         "tool_input": {"command": COMMAND}},
        lambda p: stdout_json(p)["reason"],
        lambda p: "decision" not in stdout_json(p),
    ),
    "cursor": (
        "cursor-command-review-hook.py",
        {"hook_event_name": "beforeShellExecution", "command": COMMAND, "cwd": WIN_CWD},
        lambda p: stdout_json(p)["agent_message"],
        lambda p: stdout_json(p)["permission"] == "allow",
    ),
    "windsurf": (
        "windsurf-command-review-hook.py",
        {"agent_action_name": "pre_run_command",
         "tool_info": {"command_line": COMMAND, "cwd": WIN_CWD}},
        lambda p: p.stderr.decode("utf-8"),
        lambda p: p.returncode == 0 and p.stdout == b"",
    ),
    "devin": (
        "devin-command-review-hook.py",
        {"hook_event_name": "PermissionRequest", "tool_name": "exec",
         "tool_input": {"command": COMMAND, "cwd": WIN_CWD}},
        lambda p: stdout_json(p)["reason"],
        lambda p: stdout_json(p).get("decision") == "approve",
    ),
    "antigravity": (
        "antigravity-command-review-hook.py",
        {"conversationId": "c", "workspacePaths": [WIN_CWD], "stepIdx": 1,
         "toolCall": {"name": "run_command",
                      "args": {"CommandLine": COMMAND, "Cwd": WIN_CWD}}},
        lambda p: stdout_json(p)["reason"],
        lambda p: stdout_json(p)["decision"] == "auto_approve",
    ),
}


def help_block(reason: str) -> Dict[str, Any]:
    for line in reason.splitlines():
        if line.startswith('{"v":1,'):
            return json.loads(line)
    raise AssertionError(f"no help block in reason:\n{reason}")


def stored_grant(request: Dict[str, Any], user: str, path: Optional[str]) -> Dict[str, Any]:
    """Mirror the writer's conversion for a request that passed validation."""
    return {"v": 1, "type": "grant", "id": "g-20261119T170000Z-0000abcd",
            "name": request["name"], "ts": "2026-11-19T17:00:00Z", "user": user,
            "user_display": "PC\\user", "commands": request["commands"],
            "tool": request["tool"], "where": request["where"], "path": path,
            "hosts": request["hosts"], "expires": "2099-01-01T00:00:00Z",
            "why": request["why"]}


@pytest.mark.parametrize("host", sorted(HOSTS))
def test_help_block_round_trips_into_an_allow(host: str, tmp_path: Path) -> None:
    import exception_grants as eg

    adapter, payload, reason_of, is_allow = HOSTS[host]
    grants = tmp_path / "store" / "grants.jsonl"
    grants.parent.mkdir()
    grants.write_bytes(b"")

    denied = run(tmp_path, adapter, payload, grants)
    reason = reason_of(denied)
    request = help_block(reason)
    assert request["commands"] == [COMMAND]
    assert request["hosts"] == [host]

    request["name"] = "reset"
    if request["cwd"] == "":
        # D4: a non-Windows cwd is never guessed. The user fills it in, or here,
        # widens the grant to any folder on purpose.
        assert "not a Windows path" in reason
        request["where"] = "any"
        del request["cwd"]
    now = eg.parse_stored_timestamp("2026-11-19T18:00:00Z")
    assert now is not None
    assert eg.validate_request(request, now) is None

    record = stored_grant(request, eg.current_user_sid(), request.get("cwd"))
    grants.write_bytes((canonical_line(record) + "\n").encode("utf-8"))

    allowed = run(tmp_path, adapter, payload, grants)
    assert is_allow(allowed), (allowed.stdout, allowed.stderr)
    log_lines = (tmp_path / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
    last = json.loads(log_lines[-1])
    assert last["source"] == "grant"
    assert "exception-grant-id:g-20261119T170000Z-0000abcd" in last["flags"]
