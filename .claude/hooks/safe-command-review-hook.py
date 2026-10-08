#!/usr/bin/env python3
"""Claude Code adapter for the shared command safety reviewer.

Reads a Claude Code hook payload on stdin and writes a Claude Code hook
response on stdout.
"""
from __future__ import annotations

import contextlib
import json
import sys
from typing import Any, Dict, List

from review_core import (
    ConfigError,
    ReviewResult,
    read_hook_input,
    render_reason,
    review_payload,
    stats_main,
    tool_name,
)

#: Emitted when `json.dumps` or stdout itself fails. A pre-serialised ASCII
#: literal so producing it cannot hit the encoder or the formatter that just
#: failed.
_LAST_RESORT_JSON = (
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
    '"permissionDecision":"ask","permissionDecisionReason":'
    '"Command review could not emit its result, so this command was not '
    'reviewed. Read it yourself before approving."},'
    '"metadata":{"source":"emit-failure","flags":["emit-failure"],'
    '"dont_ask_again_safe":false}}'
)


def hook_response(result: ReviewResult, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": result.event_name,
            "permissionDecision": result.review.decision,
            "permissionDecisionReason": render_reason(result.review),
        },
        "metadata": {
            "source": result.review.source,
            "flags": result.review.flags,
            "dont_ask_again_safe": result.review.dont_ask_again_safe,
            "tool_name": tool_name(payload),
        },
    }


def config_error_response(payload: Dict[str, Any], message: str) -> Dict[str, Any]:
    """Fail closed on a broken config.

    A config file the user wrote but that cannot be honoured must never degrade
    to permissive defaults, because those defaults may be laxer than what they
    asked for. 'ask' is the safe floor here: nothing auto-runs, and the reason
    tells them exactly what to fix. Denying outright would strand the agent.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                f"Command review is misconfigured, so no automatic safety check ran. "
                f"{message}"
            ),
        },
        "metadata": {
            "source": "config-error",
            "flags": ["config-error"],
            "dont_ask_again_safe": False,
            "tool_name": tool_name(payload),
        },
    }


def emit(response: Dict[str, Any]) -> None:
    """Write the hook response to stdout as one line.

    `ensure_ascii=True` deliberately. The host decodes the \\uXXXX escapes back to
    the original characters, so nothing is lost -- but the bytes written here are
    pure ASCII, which a console left on a legacy code page cannot fail to encode.
    That matters because `sys.stdout.write` can emit part of a line before
    raising UnicodeEncodeError: a retry would then append to a half-written line
    and produce invalid JSON, and a response the host cannot parse is no decision
    at all. The explicit flush is what turns a broken pipe into an exception the
    caller can still act on, rather than an error at interpreter shutdown.
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

    payload: Dict[str, Any] = {}
    try:
        payload = read_hook_input()
        response = hook_response(review_payload(payload, host="claude"), payload)
    except ConfigError as exc:
        response = config_error_response(payload, str(exc))
    except BaseException as exc:  # noqa: BLE001
        # BaseException, not Exception: a KeyboardInterrupt during a slow
        # provider call would otherwise escape as a traceback with nothing on
        # stdout, and a hook that exits non-zero without a decision is treated
        # as not having run -- the command then goes through unreviewed.
        response = config_error_response(
            payload, f"Hook failed: {type(exc).__name__}: {exc}"
        )

    try:
        emit(response)
    except Exception:
        # stdout is unusable, or the decision could not be serialised. Try the
        # smallest possible literal; if even that fails, exit 2 -- the one code
        # Claude Code treats as blocking. Exiting 0 here would leave the host
        # with no parsable decision, which it treats as "no hook ran" and lets
        # the command through unreviewed.
        try:
            sys.stdout.write(_LAST_RESORT_JSON + "\n")
            sys.stdout.flush()
        except Exception:
            with contextlib.suppress(Exception):
                # Claude Code feeds a PreToolUse hook's stderr to the model on
                # exit 2, so this is what explains the block.
                sys.stderr.write(
                    "cc-ai-review could not write its decision. Blocking rather "
                    "than letting the command run unreviewed.\n"
                )
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
