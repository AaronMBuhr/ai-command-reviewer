"""The installers' Antigravity snippet must launch under the host's shell."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

REPO = Path(__file__).resolve().parent.parent
MARKER = "Using Google Antigravity"
WINDOWS = sys.platform == "win32"


def install(home: Path) -> subprocess.CompletedProcess:
    shell = shutil.which("powershell" if WINDOWS else "bash")
    if not shell:
        pytest.skip("Installer shell is unavailable")
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
    }
    args = ([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(REPO / "install.ps1")]
            if WINDOWS else [shell, str(REPO / "install.sh")])
    proc = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc


def host_launch(command: str) -> List[str]:
    # Antigravity runs hooks via `cmd /c` on Windows and `sh -c` elsewhere.
    return ["cmd", "/c", command] if WINDOWS else ["sh", "-c", command]


@pytest.mark.usefixtures("headless_confirmation")
def test_printed_command_runs_under_host_shell(tmp_path: Path) -> None:
    home = tmp_path / "agyhome"  # no spaces: Windows cmd /c cannot take quotes
    home.mkdir()
    if WINDOWS and " " in sys.executable:
        pytest.skip("Interpreter path contains a space")
    out = install(home).stdout
    script = home / ".claude" / "hooks" / "cc-ai-review" / "antigravity-command-review-hook.py"
    assert script.read_bytes() == (REPO / ".claude" / "hooks" / script.name).read_bytes()

    section = out.split(MARKER, 1)[1]
    cfg, _ = json.JSONDecoder().raw_decode(section[section.index("{"):])
    (group,) = cfg["cc-ai-review"]["PreToolUse"]
    assert group["matcher"] == "^run_command$"
    (hook,) = group["hooks"]
    assert hook["timeout"] == 600
    dialog = script.with_name("command_confirmation.py")
    assert dialog.read_bytes() == (REPO / ".claude" / "hooks" / dialog.name).read_bytes()
    if WINDOWS:
        assert '"' not in hook["command"]

    env: Dict[str, str] = {**os.environ, "CC_AI_REVIEW__REVIEWER__PROVIDER": "none"}
    # No dialog can open in the headless fixture, so the ask for "rm *" denies.
    expected = {"git status": "auto_approve", "rm *": "deny", "git reset --hard": "deny"}
    for command, decision in expected.items():
        payload = {"workspacePaths": [str(tmp_path)],
                   "toolCall": {"name": "run_command", "args": {"CommandLine": command}}}
        proc = subprocess.run(host_launch(hook["command"]), input=json.dumps(payload).encode(),
                              env=env, capture_output=True, timeout=30, cwd=str(home))
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout)["decision"] == decision


@pytest.mark.skipif(not WINDOWS, reason="cmd /c quoting limitation is Windows-only")
def test_windows_installer_warns_about_spaces(tmp_path: Path) -> None:
    home = tmp_path / "test user"
    home.mkdir()
    proc = install(home)
    assert "Antigravity cannot launch a hook whose Python or script path contains a space" \
        in proc.stdout + proc.stderr
