#!/usr/bin/env python3
"""Shell review for Cascade pre_run_command and Devin Local PreToolUse.

Both hosts accept exit 0 to proceed and exit 2 to block. Cascade asks through
a synchronous desktop dialog; only Allow once releases that invocation. Legacy
Devin PreToolUse registrations should migrate to the PermissionRequest adapter.
"""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import Any, Dict

from review_core import read_hook_input, render_reason, review_payload, stats_main


def confirm_command(command: str, cwd: str, reason: str) -> bool:
    # Load inside main's blocking boundary. An incomplete upgrade missing the
    # GUI helper must not exit 1, which Cascade treats as nonblocking.
    from command_confirmation import confirm_command as show_confirmation

    return show_confirmation(command, cwd, reason)


def normalize_payload(payload: Any) -> Dict[str, Any]:
    """Validate the host envelope and translate it to the shared shell schema.

    Only the documented shell pre-hooks are supported. In particular, a missing
    Devin `exec` command must not be mistaken for an out-of-scope tool and allowed
    by the shared reviewer's generic tool handling.
    """
    if not isinstance(payload, dict):
        raise ValueError("Hook input must be a JSON object.")
    if payload.get("_parse_error"):
        raise ValueError(f"Cannot parse hook input: {payload['_parse_error']}")

    if "agent_action_name" in payload:
        if payload["agent_action_name"] != "pre_run_command":
            raise ValueError("Register this adapter only for Cascade pre_run_command.")
        tool_input = payload.get("tool_info")
        command_key = "command_line"
    else:
        if (payload.get("hook_event_name") != "PreToolUse"
                or payload.get("tool_name") != "exec"):
            raise ValueError("Register this adapter for Devin PreToolUse with matcher ^exec$.")
        tool_input = payload.get("tool_input")
        command_key = "command"

    if not isinstance(tool_input, dict):
        raise ValueError("Hook input is missing the shell arguments object.")
    command = tool_input.get(command_key)
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"Hook input requires a nonempty string {command_key}.")
    cwd = tool_input.get("cwd", payload.get("cwd"))
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        raise ValueError("Hook cwd must be a nonempty string when provided.")

    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "shell",
        "tool_input": {"command": command, "cwd": cwd},
    }


def block(reason: str) -> int:
    """Keep the blocking exit code even if the diagnostic stream is broken."""
    try:
        sys.stderr.write(reason + "\n")
        sys.stderr.flush()
    except Exception:
        with contextlib.suppress(Exception):
            sys.stderr.write("Command review failed. Blocking this command.\n")
            sys.stderr.flush()
    return 2


def main() -> int:
    # --stats must not wait for a hook payload on stdin.
    if "--stats" in sys.argv[1:]:
        return stats_main(sys.argv[1:])

    with contextlib.suppress(Exception):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")

    try:
        host_payload = read_hook_input()
        payload = normalize_payload(host_payload)
        result = review_payload(payload, host="windsurf")
        if result.review.decision == "allow":
            return 0
        reason = render_reason(result.review)
        if result.review.decision == "ask":
            if "agent_action_name" not in host_payload:
                return block("Legacy Devin PreToolUse cannot prompt. Register "
                             "devin-command-review-hook.py for PermissionRequest instead.\n"
                             + reason)
            command = payload["tool_input"]["command"]
            cwd = payload["tool_input"]["cwd"] or str(Path.cwd())
            try:
                approved = confirm_command(command, cwd, reason)
            except Exception as exc:
                return block(f"Confirmation dialog unavailable or failed; command blocked. "
                             f"{type(exc).__name__}: {exc}\n{reason}")
            if approved is True:
                return 0
            return block("Command cancelled in the confirmation dialog.\n" + reason)
        return block(reason)
    except BaseException as exc:  # noqa: BLE001
        # As with the existing adapters, an interruption/config/runtime failure
        # must not become a nonblocking exit 1 in the host.
        return block(f"Devin/Windsurf command review failed closed: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
