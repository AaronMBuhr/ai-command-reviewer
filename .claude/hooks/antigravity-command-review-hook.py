#!/usr/bin/env python3
"""Google Antigravity PreToolUse adapter: auto-approve, confirm, or deny.

Antigravity (CLI `agy`, the IDE, and Antigravity 2.0) reads a JSON decision from
stdout. Observed with agy 1.4.12:

* `deny`, malformed JSON, an unknown decision, a nonzero exit, and a hook that
  overruns its `timeout` all block the tool call, in every permission mode.
* Exit 0 with *empty* stdout lets the command run. Every path here therefore
  either writes a complete JSON decision or exits nonzero.

Current hosts support `auto_approve` (use agy 1.5.3 or newer): unlike `allow`,
it skips the default `request-review` prompt while honoring explicit user rules.

As with Cascade, an `ask` review is settled here in a desktop Allow once /
Cancel dialog and returned as `auto_approve` or `deny`. Keep `request-review`:
approved commands run, ask waits for the dialog, deny blocks.
"""
from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from typing import Any, Dict

from review_core import (
    ReviewResult,
    read_hook_input,
    render_reason,
    review_payload,
    stats_main,
)

TOOL_NAME = "run_command"
DIALOG_TITLE = "AI Command Review - Antigravity"


def confirm_command(command: str, cwd: str, reason: str) -> bool:
    # Import here so a missing helper (an incomplete upgrade) becomes a deny
    # inside main's error handling rather than a crash with empty output.
    from command_confirmation import confirm_command as show_confirmation

    return show_confirmation(command, cwd, reason, title=DIALOG_TITLE)


def normalize_payload(payload: Any) -> Dict[str, Any]:
    """Accept only a well-formed `run_command` PreToolUse payload.

    The hook process runs in the directory holding hooks.json, not the
    workspace, so the working directory comes from the payload: the tool's
    `Cwd` argument when present, else the first workspace path.
    """
    if not isinstance(payload, dict):
        raise ValueError("Hook input must be a JSON object.")
    if payload.get("_parse_error"):
        raise ValueError(f"Cannot parse hook input: {payload['_parse_error']}")
    tool_call = payload.get("toolCall")
    if not isinstance(tool_call, dict) or tool_call.get("name") != TOOL_NAME:
        raise ValueError(f"Register this adapter for Antigravity PreToolUse with "
                         f"matcher ^{TOOL_NAME}$.")
    args = tool_call.get("args")
    if not isinstance(args, dict):
        raise ValueError("Hook input is missing the run_command arguments object.")
    command = args.get("CommandLine")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Hook input requires a nonempty string CommandLine.")

    cwd = args.get("Cwd")
    if cwd is None:
        workspaces = payload.get("workspacePaths")
        if isinstance(workspaces, list) and workspaces:
            cwd = workspaces[0]
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        raise ValueError("Hook cwd must be a nonempty string when provided.")
    return {
        "hook_event_name": "PreToolUse",
        # Validate first, then use the shared engine's shell vocabulary.
        "tool_name": "shell",
        "tool_input": {"command": command, "cwd": cwd},
    }


def hook_response(result: ReviewResult, command: str, cwd: str) -> Dict[str, Any]:
    decision = result.review.decision
    if decision == "allow":
        # "allow" only delegates to the host policy, which can still prompt.
        return {"decision": "auto_approve"}
    reason = render_reason(result.review)
    if decision == "deny":
        return {"decision": "deny", "reason": reason}
    if decision != "ask":
        raise ValueError(f"Unsupported reviewer decision: {decision!r}")
    try:
        approved = confirm_command(command, cwd, reason)
    except Exception as exc:  # noqa: BLE001 - any dialog failure must block
        return {"decision": "deny",
                "reason": f"Confirmation dialog unavailable or failed; command blocked. "
                          f"{type(exc).__name__}: {exc}\n{reason}"}
    if approved is True:
        return {"decision": "auto_approve"}
    return {"decision": "deny",
            "reason": "Command cancelled in the confirmation dialog.\n" + reason}


def emit(response: Dict[str, Any]) -> None:
    # ASCII JSON avoids partial output on Windows legacy console encodings.
    sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def main() -> int:
    if "--stats" in sys.argv[1:]:
        return stats_main(sys.argv[1:])
    try:
        payload = normalize_payload(read_hook_input())
        tool_input = payload["tool_input"]
        response = hook_response(review_payload(payload, host="antigravity"),
                                 tool_input["command"], tool_input["cwd"] or str(Path.cwd()))
    except BaseException as exc:  # noqa: BLE001
        response = {
            "decision": "deny",
            "reason": f"Antigravity command review failed closed: {type(exc).__name__}: {exc}",
        }
    try:
        emit(response)
    except BaseException:  # noqa: BLE001
        # Empty or partial stdout is not a safe outcome: empty output lets the
        # command run. A nonzero exit is a block in Antigravity.
        with contextlib.suppress(Exception):
            sys.stderr.write("Command review could not emit its decision. Blocking.\n")
            sys.stderr.flush()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
