"""Check the dialog's actual callbacks without requiring a desktop in CI."""
from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest
from command_confirmation import confirm_command


@pytest.fixture
def dialog(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    state = SimpleNamespace(action="Cancel", buttons={}, bindings={}, protocols={},
                            text="", destroyed=False, waiting=False, focused=None, timers=[])

    class Widget:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.options = kwargs
            if "command" in kwargs:
                state.buttons[kwargs["text"]] = kwargs["command"]

        def pack(self, **kwargs: Any) -> None:
            pass

        def insert(self, index: str, text: str) -> None:
            state.text = text

        def configure(self, **kwargs: Any) -> None:
            state.readonly = kwargs["state"] == "disabled"

        def focus_set(self) -> None:
            state.focused = self.options["text"]

    class Root:
        def withdraw(self) -> None:
            pass

        title = geometry = minsize = lift = attributes = deiconify = lambda *args: None

        def protocol(self, name: str, callback: Any) -> None:
            state.protocols[name] = callback

        def bind(self, name: str, callback: Any) -> None:
            state.bindings[name] = callback

        def after(self, delay: int, callback: Any) -> None:
            state.timers.append((delay, callback))

        def mainloop(self) -> None:
            state.waiting = True
            if state.action in state.buttons:
                state.buttons[state.action]()
            elif state.action == "close":
                state.protocols["WM_DELETE_WINDOW"]()
            elif state.action == "callback_error":
                self.report_callback_exception(RuntimeError, RuntimeError("UI failed"), None)
            elif state.action == "loop_error":
                raise RuntimeError("mainloop failed")
            elif state.action == "timeout":
                state.timers[0][1]()
            elif state.action != "unexpected_return":
                state.bindings[state.action](None)

        def quit(self) -> None:
            assert state.waiting  # no approval before the event loop receives an action

        def destroy(self) -> None:
            state.destroyed = True

    monkeypatch.setitem(sys.modules, "tkinter", SimpleNamespace(
        Tk=Root, TclError=RuntimeError,
        ttk=SimpleNamespace(Frame=Widget, Label=Widget, Button=Widget),
    ))
    monkeypatch.setitem(sys.modules, "tkinter.scrolledtext", SimpleNamespace(ScrolledText=Widget))
    return state


@pytest.mark.parametrize("action,expected", [
    ("Allow once", True), ("Cancel", False), ("close", False),
    ("<Escape>", False), ("<Return>", False), ("unexpected_return", False),
])
def test_only_allow_once_approves(dialog: SimpleNamespace, action: str, expected: bool) -> None:
    dialog.action = action
    command = "echo café 日本語\n" + "x" * 20000
    assert confirm_command(command, "C:/a project", "Review this script") is expected
    assert command in dialog.text  # no truncation, interpolation, or execution
    assert "C:/a project" in dialog.text
    assert "Review this script" in dialog.text
    assert dialog.readonly
    assert dialog.focused == "Cancel"
    assert dialog.destroyed


def test_dialog_timeout_cancels_without_approval(dialog: SimpleNamespace) -> None:
    dialog.action = "timeout"
    assert confirm_command("dotnet test", "/project", "Review", timeout_seconds=120) is False
    assert dialog.timers[0][0] == 120000
    assert dialog.destroyed


def test_dialog_timeout_does_not_prevent_explicit_approval(dialog: SimpleNamespace) -> None:
    dialog.action = "Allow once"
    assert confirm_command("dotnet test", "/project", "Review", timeout_seconds=120) is True
    assert dialog.destroyed


@pytest.mark.parametrize("action", ["callback_error", "loop_error"])
def test_ui_failure_propagates_and_closes(dialog: SimpleNamespace, action: str) -> None:
    dialog.action = action
    with pytest.raises(RuntimeError):
        confirm_command("probe", "/project", "review")
    assert dialog.destroyed
