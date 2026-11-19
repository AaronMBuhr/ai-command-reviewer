# Install the command safety reviewer once, for all repos.
#
# The reviewer is deliberately NOT vendored into each project: it is a tool you
# run, not part of any one codebase, and copies drift out of sync.
$ErrorActionPreference = "Stop"

$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$hookDir = Join-Path $env:USERPROFILE ".claude\hooks\cc-ai-review"
$configDir = Join-Path $env:APPDATA "cc-ai-review"

Write-Host "Installing hook scripts to $hookDir"
New-Item -ItemType Directory -Force -Path $hookDir | Out-Null
foreach ($f in @("review_core.py", "config.py", "providers.py", "exception_grants.py",
                 "safe-command-review-hook.py", "codex-command-review-hook.py",
                 "windsurf-command-review-hook.py", "devin-command-review-hook.py",
                 "command_confirmation.py", "antigravity-command-review-hook.py",
                 "devin_feedback.py", "aiallow.py", "setup-grants.ps1")) {
    Copy-Item (Join-Path $src ".claude\hooks\$f") (Join-Path $hookDir $f) -Force
}
# The writer's source copy. `aiallow setup` installs it into the admin-only
# grants folder; only that protected copy ever runs elevated for grants.
Copy-Item (Join-Path $src "grant-writer\grant-writer.ps1") (Join-Path $hookDir "grant-writer.ps1") -Force

New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$configTarget = Join-Path $configDir "config.yaml"
if (Test-Path $configTarget) {
    Write-Host "Keeping existing $configTarget"
} else {
    Copy-Item (Join-Path $src "config.example.yaml") $configTarget
    Write-Host "Created $configTarget"
}

# A bare "python" that is not on PATH makes the host silently skip the hook,
# which looks exactly like the hook not working. Resolve a real interpreter.
$pythonBin = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonBin) {
    Write-Warning "No python found on PATH. Edit the command below to point at a real python.exe, or the hook will be skipped silently."
    $pythonBin = "C:\Path\To\python.exe"
} else {
    try { & $pythonBin -c "import yaml" 2>$null } catch {}
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "NOTE: PyYAML is not installed for $pythonBin."
        Write-Host "      A config file requires it. Install with: $pythonBin -m pip install pyyaml"
        Write-Host "      (or delete $configTarget to run on environment variables alone)"
    }
}

$hookPath = Join-Path $hookDir "safe-command-review-hook.py"

# aiallow.cmd runs the exception-grant CLI with the resolved interpreter.
# This installer never elevates; `aiallow setup` asks for UAC itself.
$aiallowCmd = Join-Path $hookDir "aiallow.cmd"
[System.IO.File]::WriteAllText($aiallowCmd, "@`"$pythonBin`" `"%~dp0aiallow.py`" %*`r`n")

# JSON has no idea about Windows paths: a lone backslash starts an escape
# sequence, so "C:\Python311\python.exe" pasted into settings.json is a parse
# error (\P and \p are not valid escapes). Double them for the snippet below.
$codexPath = Join-Path $hookDir "codex-command-review-hook.py"
$pythonJson = $pythonBin -replace '\\', '\\'
$hookJson = $hookPath -replace '\\', '\\'
$codexJson = $codexPath -replace '\\', '\\'
$codexWindowsCommand = "set CC_AI_REVIEW__REVIEWER__PROVIDER=none&&$pythonJson $codexJson"

# Cascade runs Windows hooks through PowerShell. Forward the native exit code:
# otherwise powershell -Command can turn Python's blocking 2 into a nonblocking 1.
$windsurfPath = Join-Path $hookDir "windsurf-command-review-hook.py"
$windsurfPython = $pythonBin.Replace("'", "''")
$windsurfScript = $windsurfPath.Replace("'", "''")
$windsurfCommandJson = ConvertTo-Json -Compress ("& '$windsurfPython' '$windsurfScript'; exit " + '$LASTEXITCODE')
$devinPath = Join-Path $hookDir "devin-command-review-hook.py"
$devinCommandJson = ConvertTo-Json -Compress ('"' + $pythonBin + '" "' + $devinPath + '"')

# Antigravity runs Windows hooks through cmd /c with embedded quotes escaped as
# \", which cmd cannot parse. The command must be unquoted, so neither path may
# contain a space.
$antigravityPath = Join-Path $hookDir "antigravity-command-review-hook.py"
$antigravityCommandJson = ConvertTo-Json -Compress ($pythonBin + " " + $antigravityPath)
if ($pythonBin.Contains(" ") -or $antigravityPath.Contains(" ")) {
    Write-Warning "Antigravity cannot launch a hook whose Python or script path contains a space. Use paths without spaces in the Antigravity command below."
}

# Write-Output rather than Write-Host so the snippet can be piped or redirected
# to a file; Write-Host bypasses the output stream entirely.
Write-Output @"

Done. Add this to $env:USERPROFILE\.claude\settings.json:

  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash|PowerShell",
          "hooks": [
            {
              "type": "command",
              "command": "\"$pythonJson\" \"$hookJson\""
            }
          ]
        }
      ]
    }
  }

Note: 'Bash|PowerShell', not just 'Bash'. PowerShell is a separate tool on
Windows, and omitting it lets every PowerShell command bypass review.

Using Codex as well? Add this to $env:USERPROFILE\.codex\hooks.json:

  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash|shell",
          "hooks": [
            {
              "type": "command",
              "command": "python \"`$HOME/.claude/hooks/cc-ai-review/codex-command-review-hook.py\"",
              "commandWindows": "$codexWindowsCommand",
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
              "command": "python \"`$HOME/.claude/hooks/cc-ai-review/codex-command-review-hook.py\"",
              "commandWindows": "$codexWindowsCommand",
              "timeout": 60
            }
          ]
        }
      ]
    }
  }

Codex requires you to review and trust hook changes with /hooks afterwards.
Keep the commandWindows value free of quotes. Current Codex Windows builds can
report a quoted hook command as completed without executing it, so the resolved
Python and hook paths used there must not contain spaces.

Also add this top-level setting to $env:USERPROFILE\.codex\config.toml so Codex
reviews approval requests that the deterministic local rules leave unresolved:

  approvals_reviewer = "auto_review"

Using Cascade in Devin/Windsurf? Merge this into
$env:USERPROFILE\.codeium\windsurf\hooks.json:

  {
    "hooks": {
      "pre_run_command": [
        {
          "powershell": $windsurfCommandJson,
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
            "command": $devinCommandJson,
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
$env:USERPROFILE\.gemini\config\hooks.json for all projects, or a project's
.agents\hooks.json:

  {
    "cc-ai-review": {
      "PreToolUse": [
        {
          "matcher": "^run_command`$",
          "hooks": [
            {
              "type": "command",
              "command": $antigravityCommandJson,
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
Keep the command free of quotes and spaces: Windows runs it through cmd /c.
Keep unrelated hooks when merging. See README.md for details.

Then set an API key for the provider you want:

  `$env:ANTHROPIC_API_KEY = "..."   # or OPENAI_API_KEY / GEMINI_API_KEY

Verify it works:

  Get-Content "$src\examples\hook-input-dangerous.json" -Raw | & "$pythonBin" "$hookPath"

Optional: exception grants. Run '$aiallowCmd setup' (UAC prompt), then set exceptions.enabled: true.
"@
