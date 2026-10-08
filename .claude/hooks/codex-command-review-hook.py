#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import json
import sys
from typing import Any, Dict, List

from review_core import read_hook_input, render_reason, review_payload, stats_main

#: Emitted when `json.dumps` or stdout itself fails. A pre-serialised ASCII
#: literal so producing it cannot hit the encoder or the formatter that just
#: failed. Blocks, because Codex treats `ask` on PreToolUse as advisory -- an
#: unemitted decision must not become a silent pass.
_LAST_RESORT_JSON = (
    '{"decision":"block","reason":'
    '"Command review could not emit its result, so this command was not '
    'reviewed. Blocking rather than running it unreviewed.",'
    '"hookSpecificOutput":{"hookEventName":"PreToolUse"}}'
)


def pre_tool_use_response(result: Any) -> Dict[str, Any]:
    reason = render_reason(result.review)
    hook_specific_output: Dict[str, Any] = {"hookEventName": "PreToolUse"}

    if result.review.decision == "deny":
        return {
            "decision": "block",
            "reason": reason,
            "hookSpecificOutput": hook_specific_output,
        }

    if result.review.decision == "ask":
        return {
            "hookSpecificOutput": hook_specific_output,
            "systemMessage": reason,
        }

    return {
        "hookSpecificOutput": hook_specific_output,
    }


def permission_request_response(result: Any) -> Dict[str, Any]:
    reason = render_reason(result.review)
    hook_specific_output: Dict[str, Any] = {"hookEventName": "PermissionRequest"}

    if result.review.decision == "deny":
        hook_specific_output["decision"] = {
            "behavior": "deny",
            "message": reason,
        }
        return {"hookSpecificOutput": hook_specific_output}

    if result.review.decision == "allow":
        hook_specific_output["decision"] = {
            "behavior": "allow",
            "message": reason,
        }
        return {"hookSpecificOutput": hook_specific_output}

    return {
        "hookSpecificOutput": hook_specific_output,
        "systemMessage": reason,
    }


def hook_response(result: Any) -> Dict[str, Any]:
    if result.event_name == "PermissionRequest":
        return permission_request_response(result)
    return pre_tool_use_response(result)


def fallback_response(event_name: str, message: str) -> Dict[str, Any]:
    if event_name == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": message,
                },
            }
        }

    return {
        "decision": "block",
        "reason": message,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
        },
    }


def emit(response: Dict[str, Any]) -> None:
    """Write the hook response to stdout as one line.

    `ensure_ascii=True` deliberately -- see the matching note in the Claude Code
    adapter. A partially written line is invalid JSON, and a response Codex
    cannot parse is no decision at all.
    """
    sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def main() -> int:
    # Argument handling comes first: `read_hook_input()` blocks on a terminal, so
    # parsing after it would hang `--stats` instead of answering it.
    args: List[str] = sys.argv[1:]
    if "--stats" in args:
        return stats_main(args)

    # Not all stream objects support reconfigure (older Pythons, wrapped stdout).
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")

    event_name = "PreToolUse"
    try:
        payload = read_hook_input()
        event_name = str(payload.get("hook_event_name")
                         or payload.get("hookEventName") or "PreToolUse")
        response = hook_response(review_payload(payload, host="codex"))
    except BaseException as exc:  # noqa: BLE001
        # BaseException, not Exception -- see the matching note in the Claude
        # Code adapter. An interrupted hook must still emit a decision.
        message = f"Codex hook adapter failed closed: {type(exc).__name__}: {exc}"
        response = fallback_response(event_name, message)

    try:
        emit(response)
    except Exception:
        # stdout is unusable, or the decision could not be serialised. Try the
        # smallest possible literal, then exit non-zero rather than exiting 0
        # with no parsable decision on stdout.
        try:
            sys.stdout.write(_LAST_RESORT_JSON + "\n")
            sys.stdout.flush()
        except Exception:
            with contextlib.suppress(Exception):
                sys.stderr.write(
                    "cc-ai-review could not write its decision. Blocking rather "
                    "than letting the command run unreviewed.\n"
                )
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
