"""The installers must copy every hook module a hook imports (plan A17, PLAN-001).

Parsed statically, so this runs on every OS without installing anything.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Set

REPO = Path(__file__).resolve().parent.parent
HOOKS = REPO / ".claude" / "hooks"


def ps1_copy_list() -> List[str]:
    text = (REPO / "install.ps1").read_text(encoding="utf-8")
    match = re.search(r'foreach \(\$f in @\((.*?)\)\)', text, re.DOTALL)
    assert match, "copy loop not found in install.ps1"
    return re.findall(r'"([^"]+)"', match.group(1))


def sh_copy_list() -> List[str]:
    text = (REPO / "install.sh").read_text(encoding="utf-8")
    match = re.search(r"for f in (.*?); do", text, re.DOTALL)
    assert match, "copy loop not found in install.sh"
    return [token for token in match.group(1).split() if token != "\\"]


def local_imports(path: Path) -> Set[str]:
    """Top-level modules imported by `path` that are files in .claude/hooks."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return {name for name in names if (HOOKS / f"{name}.py").is_file()}


def test_both_installers_copy_the_same_python_files() -> None:
    ps1 = {name for name in ps1_copy_list() if name.endswith(".py")}
    sh = {name for name in sh_copy_list() if name.endswith(".py")}
    assert ps1 == sh


def test_every_imported_hook_module_is_installed() -> None:
    for copy_list in (ps1_copy_list(), sh_copy_list()):
        installed = set(copy_list)
        pending = [name for name in installed if name.endswith(".py")]
        seen: Set[str] = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            for module in local_imports(HOOKS / name):
                file_name = f"{module}.py"
                assert file_name in installed, f"{name} imports {module}, which is not copied"
                pending.append(file_name)


def test_the_installed_file_set_runs_on_its_own(tmp_path: Path) -> None:
    """Run the Claude Code adapter from a folder holding only the copied files."""
    target = tmp_path / "installed"
    target.mkdir()
    for name in ps1_copy_list():
        shutil.copy2(HOOKS / name, target / name)
    payload = (REPO / "examples" / "hook-input-safe-readonly.json").read_bytes()
    proc = subprocess.run([sys.executable, "-E", "-s", str(target / "safe-command-review-hook.py")],
                          input=payload, capture_output=True, timeout=60, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    decision = json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]
    assert decision in ("allow", "ask", "deny")
