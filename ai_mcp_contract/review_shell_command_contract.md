# AI MCP Tool Contract: `review_shell_command`

This is the tool your existing AI MCP server can expose so the Claude Code hook can ask for command validation.

## Tool name

```text
review_shell_command
```

## Input

```json
{
  "command": "python -c \"...\"",
  "cwd": "E:/Source/Mine/DocxRendererMcpServer",
  "description": "End-to-end Node render success path",
  "local_decision": "ask",
  "local_reason": "Inline Python is opaque and may run arbitrary code.",
  "local_flags": ["inline-python"],
  "dont_ask_again_safe_local": false
}
```

## Simple output accepted by the hook

```json
{
  "decision": "ask",
  "reason": "The current command appears limited to a temporary generated-docx-test folder, but it executes inline Python and generated Node code. Approve this exact command only. Do not choose the broad python -c wildcard.",
  "dont_ask_again_safe": false,
  "flags": ["inline-python", "generated-node", "temp-output-cleanup"]
}
```

## Full Claude Code hook output also accepted

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "The current command appears limited to a temporary generated-docx-test folder, but it executes inline Python and generated Node code. Approve this exact command only. Do not choose the broad python -c wildcard."
  },
  "dont_ask_again_safe": false,
  "flags": ["inline-python", "generated-node", "temp-output-cleanup"]
}
```

## Recommended MCP implementation behavior

- Use a low-temperature model.
- Force JSON output.
- Keep the answer short enough to display in Claude Code's permission prompt.
- Be conservative.
- Do not allow wildcard approvals for opaque interpreters.
- If the command is too long or too complex to fully assess, return `ask`, not `allow`.
