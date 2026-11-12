"""Shared pytest fixtures.

The hook modules live in `.claude/hooks/` rather than an installed package,
because a hook must run under whatever interpreter the host is configured with.
Tests put that directory on `sys.path` the same way Python does when the hook is
executed as a script.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest

HOOKS_DIR = Path(__file__).resolve().parent.parent / ".claude" / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

# Environment variables that leak real credentials or user config into tests.
_LEAKY_PREFIXES = ("CC_AI_REVIEW",)
_LEAKY_NAMES = (
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "CLAUDE_PROJECT_DIR", "CODEX_PROJECT_DIR",
)


@pytest.fixture
def headless_confirmation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Exercise the real no-GUI failure path in subprocess tests, without windows."""
    no_gui = tmp_path / "no_gui"
    no_gui.mkdir()
    (no_gui / "tkinter.py").write_text(
        "raise ImportError('No Tk in this headless test')\n", encoding="utf-8"
    )
    monkeypatch.setenv("PYTHONPATH", str(no_gui))


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Run every test with no inherited config, keys, or discoverable files.

    Without this, a developer's real `.env` or `~/.config/cc-ai-review/config.yaml`
    would change test outcomes, and the suite could make live API calls.
    """
    # Note: the hook modules are deliberately NOT reloaded here. Test modules
    # bind them at import time, so replacing sys.modules entries would leave the
    # tests holding a different module object than the one patched below --
    # which silently reintroduces the developer's real .env. The modules read
    # os.environ at call time, so patching the environment is sufficient.
    for name in _LEAKY_NAMES:
        monkeypatch.delenv(name, raising=False)
    import os
    for name in list(os.environ):
        if name.startswith(_LEAKY_PREFIXES):
            monkeypatch.delenv(name, raising=False)

    # Point config discovery at empty scratch directories.
    home = tmp_path / "home"
    (home / ".config").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.chdir(tmp_path)

    # `dotenv_candidates` includes this repository's own root, which holds a
    # real `.env` during development. Restrict discovery to the scratch cwd so
    # tests cannot pick up a developer's live API key -- which would both make
    # results machine-dependent and risk live API calls.
    import config as config_module
    monkeypatch.setattr(
        config_module, "dotenv_candidates", lambda: [Path.cwd() / ".env"]
    )
    yield
