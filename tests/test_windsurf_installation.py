"""Verify installers copy the adapter and print runnable host configuration."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

REPO = Path(__file__).resolve().parent.parent


def printed_config(output: str, marker: str) -> Dict[str, Any]:
    section = output.split(marker, 1)[1]
    value, _ = json.JSONDecoder().raw_decode(section[section.index("{"):])
    return value


def test_installer_commands_preserve_blocking_exit_code(tmp_path: Path) -> None:
    # Paths with spaces exercise the quoting the generated host commands need.
    task_home = tmp_path / "test user"
    task_home.mkdir()
    env = {
        **os.environ,
        "HOME": str(task_home),
        "USERPROFILE": str(task_home),
        "APPDATA": str(task_home / "AppData"),
        "XDG_CONFIG_HOME": str(task_home / ".config"),
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
        "CC_AI_REVIEW__REVIEWER__PROVIDER": "none",
    }
    windows = sys.platform == "win32"
    shell = shutil.which("powershell" if windows else "bash")
    if not shell:
        pytest.skip("Installer shell is unavailable")
    args = ([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(REPO / "install.ps1")]
            if windows else [shell, str(REPO / "install.sh")])
    installed = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
    assert installed.returncode == 0, installed.stderr
    script = task_home / ".claude" / "hooks" / "cc-ai-review" / "windsurf-command-review-hook.py"
    assert script.read_bytes() == (REPO / ".claude" / "hooks" / script.name).read_bytes()

    cascade = printed_config(installed.stdout, "Using Cascade in Devin/Windsurf?")
    hook = cascade["hooks"]["pre_run_command"][0]
    assert hook["show_output"] is True
    command = hook["powershell" if windows else "command"]
    if windows:
        assert "exit $LASTEXITCODE" in command
    devin = printed_config(installed.stdout, "Using Devin Local instead?")
    assert "hooks" not in devin
    assert devin["PermissionRequest"][0]["matcher"] == "^exec$"
    assert devin["PermissionRequest"][0]["hooks"][0]["timeout"] == 60

    for agent in ("cascade", "devin"):
        agent_command = (command if agent == "cascade"
                         else devin["PermissionRequest"][0]["hooks"][0]["command"])
        for tool_command in ("git status", "rm *", "git reset --hard"):
            payload = (
                {"agent_action_name": "pre_run_command",
                 "tool_info": {"command_line": tool_command, "cwd": str(tmp_path)}}
                if agent == "cascade" else
                {"hook_event_name": "PermissionRequest", "tool_name": "exec",
                 "tool_input": {"command": tool_command}}
            )
            if windows and agent == "cascade":
                launch = [shell, "-NoProfile", "-Command", agent_command]
            elif windows:
                launch = agent_command
            else:
                launch = [shell, "-c", agent_command]
            proc = subprocess.run(launch, input=json.dumps(payload).encode("utf-8"),
                                  env=env, capture_output=True, timeout=30,
                                  shell=windows and agent == "devin")
            if agent == "cascade":
                expected_code = 0 if tool_command == "git status" else 2
                assert proc.returncode == expected_code, proc.stderr
                assert proc.stdout == b""
                assert bool(proc.stderr) == (expected_code == 2)
            else:
                assert proc.returncode == 0, proc.stderr
                response = json.loads(proc.stdout)
                expected = {"git status": "approve", "rm *": None, "git reset --hard": "block"}
                assert response.get("decision") == expected[tool_command]


def test_shipped_hook_configuration_shapes() -> None:
    cascade = json.loads((REPO / ".windsurf" / "hooks.json.example").read_text())
    entry = cascade["hooks"]["pre_run_command"][0]
    assert "windsurf-command-review-hook.py" in entry["command"]
    assert "windsurf-command-review-hook.py" in entry["powershell"]
    assert entry["powershell"].endswith("; exit $LASTEXITCODE")
    devin = json.loads((REPO / ".devin" / "hooks.v1.json.example").read_text())
    assert "hooks" not in devin
    entry = devin["PermissionRequest"][0]
    assert entry["matcher"] == "^exec$"
    assert "devin-command-review-hook.py" in entry["hooks"][0]["command"]
