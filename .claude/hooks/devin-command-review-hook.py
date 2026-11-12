#!/usr/bin/env python3
"""Devin Local PermissionRequest adapter: approve, defer to the user, or block.

Keep shell execution subject to the host's normal approval gate. Only an explicit
reviewer allow resolves that gate automatically. By default an ask leaves the
native prompt pending. With --desktop-review, an ask requires Allow once in a
desktop dialog showing the review, then resolves that same permission request.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
from typing import Any, Dict

from review_core import (
    ReviewResult,
    read_hook_input,
    render_reason,
    review_payload,
    stats_main,
)


def normalize_payload(payload: Any) -> Dict[str, Any]:
    """Accept only a well-formed shell permission request."""
    if not isinstance(payload, dict):
        raise ValueError("Hook input must be a JSON object.")
    if payload.get("_parse_error"):
        raise ValueError(f"Cannot parse hook input: {payload['_parse_error']}")
    if (payload.get("hook_event_name") != "PermissionRequest"
            or payload.get("tool_name") != "exec"):
        raise ValueError("Register this adapter for Devin PermissionRequest with matcher ^exec$.")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("Hook input is missing the shell arguments object.")
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Hook input requires a nonempty string command.")
    cwd = tool_input.get("cwd", payload.get("cwd"))
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        raise ValueError("Hook cwd must be a nonempty string when provided.")
    return {
        "hook_event_name": "PermissionRequest",
        # The shared engine otherwise treats an exec with a missing command as
        # out of scope. Validate first, then use its existing shell vocabulary.
        "tool_name": "shell",
        "tool_input": {"command": command, "cwd": cwd},
    }


def hook_response(result: ReviewResult) -> Dict[str, Any]:
    decision = result.review.decision
    reason = render_reason(result.review)
    if decision == "allow":
        return {"decision": "approve", "reason": reason}
    if decision == "ask":
        # No `decision` means the hook did not resolve the permission request.
        # Do not emit "ask" or "block": the host should show its normal prompt.
        return {"reason": reason}
    if decision == "deny":
        return {"decision": "block", "reason": reason}
    raise ValueError(f"Unsupported reviewer decision: {decision!r}")


def desktop_feedback(payload: Dict[str, Any], response: Dict[str, Any]) -> None:
    from devin_feedback import publish_feedback

    arguments = payload.get("tool_input", {})
    decision = {"approve": "allow", "block": "deny"}.get(response.get("decision"), "ask")
    publish_feedback(arguments.get("command", "(invalid hook input)"),
                     arguments.get("cwd") or os.getcwd(), decision, response["reason"])


def confirm_review(command: str, cwd: str, reason: str) -> bool:
    from command_confirmation import confirm_command

    return confirm_command(command, cwd, reason, title="AI Command Review - Devin: Approval",
                           timeout_seconds=120)


def desktop_review(payload: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
    if "decision" not in response:
        arguments = payload["tool_input"]
        approved = confirm_review(arguments["command"], arguments.get("cwd") or os.getcwd(),
                                  response["reason"])
        if approved is True:
            return {"decision": "approve", "reason": "Approved once by you.\n" + response["reason"]}
        return {"decision": "block", "reason": "Not approved: cancelled, closed, or timed out.\n"
                + response["reason"]}
    try:
        desktop_feedback(payload, response)
    except Exception as exc:
        # Informational display errors cannot change a completed review verdict.
        warning = f"Desktop review feedback unavailable: {type(exc).__name__}: {exc}"
        response["reason"] += "\n" + warning
        with contextlib.suppress(Exception):
            sys.stderr.write(warning + "\n")
    return response


def emit(response: Dict[str, Any]) -> None:
    # ASCII JSON avoids partial output on Windows legacy console encodings.
    sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def main() -> int:
    if "--stats" in sys.argv[1:]:
        return stats_main(sys.argv[1:])
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")
    payload: Dict[str, Any] = {}
    try:
        payload = normalize_payload(read_hook_input())
        response = hook_response(review_payload(payload, host="devin"))
    except BaseException as exc:  # noqa: BLE001
        response = {
            "decision": "block",
            "reason": f"Devin command review failed closed: {type(exc).__name__}: {exc}",
        }
    if "--desktop-review" in sys.argv[1:]:
        try:
            response = desktop_review(payload, response)
        except BaseException as exc:  # noqa: BLE001
            response = {"decision": "block", "reason": "Desktop approval failed; command blocked. "
                        f"{type(exc).__name__}: {exc}\n" + response["reason"]}
    try:
        emit(response)
    except Exception:
        # A partial/unwritable response cannot convey approval. Exit 2 also
        # preserves a deny when JSON serialization or the pipe fails.
        with contextlib.suppress(Exception):
            sys.stderr.write("Command review could not emit its decision. Blocking.\n")
            sys.stderr.flush()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
