# Claude Code AI Validate PreTool Hook

A conservative Claude Code `PreToolUse` Bash hook that reviews shell commands before they run.

It is meant for exactly the annoying case where Claude Code proposes a huge command like `python -c "..."` and you do not want to manually decipher it every time.

The hook can:

- read the command Claude Code is about to run;
- run local safety heuristics;
- optionally ask your AI reviewer service / AI MCP wrapper for a second opinion;
- return a Claude Code hook decision: `allow`, `ask`, or `deny`;
- explain in plain English whether "Yes, and don't ask again" is safe.

The default behavior is intentionally conservative: ambiguous commands become `ask`, not `allow`.

## Included files

```text
.claude/
  settings.local.json.example
  hooks/
    safe-command-review-hook.py
prompts/
  command_safety_review.md
ai_mcp_contract/
  review_shell_command_contract.md
  mcp_tool_stub.py
dev/
  mock-review-server.py
examples/
  hook-input-python-c.json
  hook-input-dangerous.json
  hook-input-safe-readonly.json
install.ps1
install.sh
```

## Quick install in one repo

Unzip this project into the root of the repo where you use Claude Code.

Then copy the example settings file:

### PowerShell

```powershell
Copy-Item .\.claude\settings.local.json.example .\.claude\settings.local.json -ErrorAction Stop
```

### Bash / WSL

```bash
cp .claude/settings.local.json.example .claude/settings.local.json
```

Then start Claude Code from that repo.

## Test without Claude Code

PowerShell:

```powershell
Get-Content .\examples\hook-input-python-c.json -Raw | python .\.claude\hooks\safe-command-review-hook.py
Get-Content .\examples\hook-input-dangerous.json -Raw | python .\.claude\hooks\safe-command-review-hook.py
Get-Content .\examples\hook-input-safe-readonly.json -Raw | python .\.claude\hooks\safe-command-review-hook.py
```

Bash:

```bash
python .claude/hooks/safe-command-review-hook.py < examples/hook-input-python-c.json
python .claude/hooks/safe-command-review-hook.py < examples/hook-input-dangerous.json
python .claude/hooks/safe-command-review-hook.py < examples/hook-input-safe-readonly.json
```

## Optional: connect to an AI reviewer HTTP endpoint

Set this environment variable before launching Claude Code:

PowerShell:

```powershell
$env:CC_AI_REVIEW_URL = "http://127.0.0.1:8765/review"
```

Bash:

```bash
export CC_AI_REVIEW_URL="http://127.0.0.1:8765/review"
```

The hook will POST JSON like this:

```json
{
  "command": "python -c \"...\"",
  "cwd": "E:/Source/Mine/DocxRendererMcpServer",
  "description": "End-to-end Node render success path",
  "local_decision": "ask",
  "local_flags": ["inline-python"],
  "local_reason": "Inline interpreter code is opaque. Review before approving."
}
```

Your endpoint can return either the simple contract:

```json
{
  "decision": "ask",
  "reason": "Likely safe, but do not approve the broad python -c wildcard."
}
```

or a full Claude Code hook response:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "Likely safe, but do not approve the broad python -c wildcard."
  }
}
```

## Optional: connect to any local command instead of HTTP

Set `CC_AI_REVIEW_COMMAND` to a command that reads the review JSON from stdin and prints review JSON to stdout.

Example:

```powershell
$env:CC_AI_REVIEW_COMMAND = "python E:\Source\Mine\AiMcpServer\review_command_cli.py"
```

The hook will call that command with the same JSON payload described above.

## Safety model

The hook has a local risk floor:

- local hard-deny findings override the AI reviewer;
- by default, local `ask` findings cannot be downgraded to `allow` by the external reviewer;
- if the external reviewer fails, times out, or returns malformed JSON, the hook returns `ask` by default.

You can loosen this, but I would not do so initially.

Environment variables:

| Variable | Default | Meaning |
|---|---:|---|
| `CC_AI_REVIEW_URL` | unset | HTTP endpoint to call with review JSON. |
| `CC_AI_REVIEW_COMMAND` | unset | Local command to call with review JSON on stdin. |
| `CC_AI_REVIEW_TIMEOUT_SECONDS` | `20` | Timeout for HTTP/command reviewer. |
| `CC_AI_REVIEW_FAIL_MODE` | `ask` | What to do if reviewer fails: `ask` or `deny`. |
| `CC_AI_REVIEW_ALLOW_EXTERNAL_OVERRIDE` | `0` | If `1`, external reviewer may downgrade local `ask` to `allow`. Hard-deny still wins. |
| `CC_AI_REVIEW_ALLOW_READONLY` | `1` | If `1`, obvious read-only commands may be auto-allowed. |

## What I recommend for Aaron

Use this initially:

```powershell
$env:CC_AI_REVIEW_FAIL_MODE = "ask"
$env:CC_AI_REVIEW_ALLOW_EXTERNAL_OVERRIDE = "0"
$env:CC_AI_REVIEW_ALLOW_READONLY = "1"
```

That gives you useful explanations without silently granting broad permissions.

For commands like:

```text
python -c "... giant one-liner ..."
```

this hook should return `ask` with a reason like:

```text
Inline Python is opaque. The command appears limited to the project and temporary output, but do not choose "don't ask again" for python -c * because that would approve arbitrary future Python.
```

## Notes

This is a guardrail, not a sandbox. It helps you decide whether to approve commands; it does not isolate the filesystem or prevent every possible bad action after approval.
