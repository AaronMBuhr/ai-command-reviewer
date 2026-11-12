#!/usr/bin/env bash
# Install the command safety reviewer once, for all repos.
#
# The reviewer is deliberately NOT vendored into each project: it is a tool you
# run, not part of any one codebase, and copies drift out of sync.
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
hook_dir="${HOME}/.claude/hooks/cc-ai-review"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/cc-ai-review"

echo "Installing hook scripts to $hook_dir"
mkdir -p "$hook_dir"
for f in review_core.py config.py providers.py \
         safe-command-review-hook.py codex-command-review-hook.py \
         windsurf-command-review-hook.py devin-command-review-hook.py \
         command_confirmation.py antigravity-command-review-hook.py devin_feedback.py; do
  cp "$src/.claude/hooks/$f" "$hook_dir/$f"
done

mkdir -p "$config_dir"
if [[ -f "$config_dir/config.yaml" ]]; then
  echo "Keeping existing $config_dir/config.yaml"
else
  cp "$src/config.example.yaml" "$config_dir/config.yaml"
  echo "Created $config_dir/config.yaml"
fi

# Resolve an interpreter for the printed settings snippet. The hook reads its
# payload from stdin, and a command that fails to launch makes the host skip the
# hook silently -- which looks exactly like the hook not working.
python_bin=""
for candidate in python3 python; do
  resolved="$(command -v "$candidate" 2>/dev/null || true)"
  [[ -z "$resolved" ]] && continue
  # On Windows, PATH usually contains a Microsoft Store shim that is not a real
  # interpreter: it launches the Store instead of running your script. Skip it
  # by path rather than by executing it.
  case "$resolved" in
    */WindowsApps/*) continue ;;
  esac
  python_bin="$resolved"
  break
done

if [[ -z "$python_bin" ]]; then
  echo >&2
  echo "WARNING: no usable python found on PATH." >&2
  echo "Replace PYTHON below with a real interpreter path, e.g. a conda env's" >&2
  echo "python.exe. Do not use 'conda run' -- it does not forward stdin, so the" >&2
  echo "hook would receive an empty payload." >&2
  python_bin="PYTHON"
fi

if [[ "$python_bin" != "PYTHON" ]] && ! "$python_bin" -c "import yaml" 2>/dev/null; then
  echo
  echo "NOTE: PyYAML is not installed for $python_bin."
  echo "      A config file requires it. Install with: $python_bin -m pip install pyyaml"
  echo "      (or delete $config_dir/config.yaml to run on environment variables alone)"
fi

cat <<EOF

Done. Add this to ~/.claude/settings.json:

  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash|PowerShell",
          "hooks": [
            {
              "type": "command",
              "command": "$python_bin \\"$hook_dir/safe-command-review-hook.py\\""
            }
          ]
        }
      ]
    }
  }

Using Codex as well? Add this to ~/.codex/hooks.json:

  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash|shell",
          "hooks": [
            {
              "type": "command",
              "command": "$python_bin \\"$hook_dir/codex-command-review-hook.py\\"",
              "timeout": 60
            }
          ]
        }
      ],
      "PermissionRequest": [
        {
          "matcher": "*",
          "hooks": [
            {
              "type": "command",
              "command": "$python_bin \\"$hook_dir/codex-command-review-hook.py\\"",
              "timeout": 60
            }
          ]
        }
      ]
    }
  }

Codex requires you to review and trust hook changes with /hooks afterwards.

Using Cascade in Devin/Windsurf? Merge this into ~/.codeium/windsurf/hooks.json:

  {
    "hooks": {
      "pre_run_command": [
        {
          "command": "\\"$python_bin\\" \\"$hook_dir/windsurf-command-review-hook.py\\"",
          "show_output": true
        }
      ]
    }
  }

Using Devin Local instead? Put this in your project's .devin/hooks.v1.json
(the standalone file has no outer "hooks" key):

  {
    "PermissionRequest": [
      {
        "matcher": "^exec$",
        "hooks": [
          {
            "type": "command",
            "command": "\\"$python_bin\\" \\"$hook_dir/devin-command-review-hook.py\\"",
            "timeout": 60
          }
        ]
      }
    ]
  }

Devin Local: allow auto-approves, ask keeps the normal prompt, deny blocks.
Keep exec subject to approval (permissions.ask: ["exec"]). Remove the old
windsurf-command-review-hook.py PreToolUse entry from Devin Local when migrating.
Cascade: allow proceeds; ask opens a desktop Allow once / Cancel dialog; deny blocks.
The dialog requires Python with Tk and an interactive desktop. If it cannot open,
the command is blocked. Select Cascade Terminal Auto Execution = Turbo to avoid
a second IDE approval click after the hook allows a command. First verify the
hook and dialog load: Turbo can execute unreviewed commands if hooks are skipped.

Using Google Antigravity (agy CLI, IDE, or Antigravity 2.0)? Merge this into
~/.gemini/config/hooks.json for all projects, or a project's .agents/hooks.json:

  {
    "cc-ai-review": {
      "PreToolUse": [
        {
          "matcher": "^run_command\$",
          "hooks": [
            {
              "type": "command",
              "command": "\\"$python_bin\\" \\"$hook_dir/antigravity-command-review-hook.py\\"",
              "timeout": 600
            }
          ]
        }
      ]
    }
  }

Antigravity: use agy 1.5.3 or newer with auto_approve hook support. Keep tool
permission at request-review (/config). Approved commands return auto_approve;
ask opens a desktop Allow once / Cancel dialog; deny blocks. If you previously
selected always-proceed, switch back to request-review. The 600-second timeout
leaves time to answer the dialog; a timeout blocks. Restart agy after editing hooks.json.
On Windows the command runs through cmd /c: use install.ps1, which prints an
unquoted command, and keep the paths free of spaces.
Keep unrelated hooks when merging. See README.md for details.

Then set an API key for the provider you want:

  export ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY / GEMINI_API_KEY

Verify it works:

  $python_bin "$hook_dir/safe-command-review-hook.py" < "$src/examples/hook-input-dangerous.json"
EOF
