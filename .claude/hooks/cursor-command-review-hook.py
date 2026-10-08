#!/usr/bin/env python3
"""Cursor adapter for the shared command reviewer.

Cursor speaks a different dialect from Claude Code and Codex: it wants a flat
`permission` verb plus two message fields, not a nested `hookSpecificOutput`.
Feeding it a Claude-shaped response is why the earlier wiring failed -- Cursor
could not find a decision in the reply and treated the hook as broken.

`ask` is enforced on Cursor (it raises a real prompt), so this host stays out of
`ADVISORY_ASK_HOSTS` and inherits the same delete policy as Claude Code.
"""
from __future__ import annotations

import contextlib
import json
import sys
from typing import Any, Dict, List

from review_core import read_hook_input, render_reason, review_payload, stats_main

#: Emitted when `json.dumps` or stdout itself fails. A pre-serialised ASCII
#: literal so producing it cannot hit the encoder or the formatter that just
#: failed. Denies, because a decision Cursor cannot read is no decision at all.
_LAST_RESORT_JSON = (
    '{"permission":"deny",'
    '"user_message":"Command review could not emit its result, so this '
    'command was not reviewed. Blocking rather than running it unreviewed.",'
    '"agent_message":"The command reviewer failed to emit a decision."}'
)


def hook_response(result: Any) -> Dict[str, Any]:
    """Map a ReviewResult onto Cursor's permission schema.

    Cursor accepts `permission` plus `user_message`/`agent_message` on
    `beforeShellExecution` and `preToolUse`. An `allow` carries no message so a
    cleared command stays silent instead of narrating itself.
    """
    reason = render_reason(result.review)
    decision = result.review.decision

    if decision == "deny":
        return {
            "permission": "deny",
            "user_message": reason,
            "agent_message": reason,
        }

    if decision == "ask":
        return {
            "permission": "ask",
            "user_message": reason,
            "agent_message": reason,
        }

    return {"permission": "allow"}


def fallback_response(message: str) -> Dict[str, Any]:
    return {
        "permission": "deny",
        "user_message": message,
        "agent_message": message,
    }


def emit(response: Dict[str, Any]) -> None:
    """Write the hook response to stdout as one line.

    `ensure_ascii=True` deliberately -- see the matching note in the Claude Code
    adapter. A partially written line is invalid JSON, and a response Cursor
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

    try:
        payload = read_hook_input()
        response = hook_response(review_payload(payload, host="cursor"))
    except BaseException as exc:  # noqa: BLE001
        # BaseException, not Exception -- see the matching note in the Claude
        # Code adapter. An interrupted hook must still emit a decision.
        message = f"Cursor hook adapter failed closed: {type(exc).__name__}: {exc}"
        response = fallback_response(message)

    try:
        emit(response)
    except Exception:
        # stdout is unusable, or the decision could not be serialised. Try the
        # smallest possible literal, then exit 2 -- the code Cursor treats as a
        # block -- rather than exiting 0 with no parsable decision on stdout.
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
