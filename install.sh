#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
settings_example="$root/.claude/settings.local.json.example"
settings_target="$root/.claude/settings.local.json"

if [[ ! -f "$settings_example" ]]; then
  echo "Missing $settings_example. Run this script from the extracted project root." >&2
  exit 1
fi

if [[ -f "$settings_target" ]]; then
  echo "Keeping existing $settings_target"
else
  cp "$settings_example" "$settings_target"
  echo "Created $settings_target"
fi

echo
echo "Test the hook with:"
echo "python .claude/hooks/safe-command-review-hook.py < examples/hook-input-python-c.json"
echo
echo "Optional AI reviewer URL for this shell session:"
echo 'export CC_AI_REVIEW_URL="http://127.0.0.1:8765/review"'
