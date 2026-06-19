$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$settingsExample = Join-Path $root ".claude\settings.local.json.example"
$settingsTarget = Join-Path $root ".claude\settings.local.json"

if (!(Test-Path $settingsExample)) {
    throw "Missing $settingsExample. Run this script from the extracted project root."
}

if (Test-Path $settingsTarget) {
    Write-Host "Keeping existing $settingsTarget"
} else {
    Copy-Item $settingsExample $settingsTarget
    Write-Host "Created $settingsTarget"
}

Write-Host ""
Write-Host "Test the hook with:"
Write-Host "Get-Content .\examples\hook-input-python-c.json -Raw | python .\.claude\hooks\safe-command-review-hook.py"
Write-Host ""
Write-Host "Optional AI reviewer URL for this PowerShell session:"
Write-Host '$env:CC_AI_REVIEW_URL = "http://127.0.0.1:8765/review"'
