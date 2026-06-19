"""
Stub for adding a `review_shell_command` tool to your existing AI MCP server.

This is intentionally not wired to any specific MCP framework because your server already exists.
Copy the policy and contract into the framework style you are using.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

SYSTEM_PROMPT = """
You are a conservative shell-command safety reviewer for Claude Code.
Return only JSON with: decision, reason, dont_ask_again_safe, flags.
Use allow only for clearly safe read-only/test commands.
Use ask for opaque commands such as python -c, node -e, powershell -Command, file writes, deletes, downloads, and dependency installs.
Use deny for destructive, exfiltrating, encoded, or web-piped execution commands.
Always explicitly say whether broad 'don't ask again' approval is safe.
""".strip()


def build_review_prompt(payload: Dict[str, Any]) -> str:
    return "Review this Claude Code shell command:\n\n" + json.dumps(payload, indent=2)


async def review_shell_command(
    command: str,
    cwd: str = "",
    description: str = "",
    local_decision: str = "ask",
    local_reason: str = "",
    local_flags: List[str] | None = None,
    dont_ask_again_safe_local: bool = False,
) -> Dict[str, Any]:
    """
    Replace `call_your_ai_model(...)` with your existing AI MCP server's query path.
    """
    payload = {
        "command": command,
        "cwd": cwd,
        "description": description,
        "local_decision": local_decision,
        "local_reason": local_reason,
        "local_flags": local_flags or [],
        "dont_ask_again_safe_local": dont_ask_again_safe_local,
    }

    # Example only:
    # raw = await call_your_ai_model(system=SYSTEM_PROMPT, user=build_review_prompt(payload), temperature=0.1)
    # data = json.loads(raw)
    # return data

    return {
        "decision": "ask",
        "reason": "MCP stub is not wired to an AI model yet. Review manually.",
        "dont_ask_again_safe": False,
        "flags": ["stub-not-wired"],
    }
