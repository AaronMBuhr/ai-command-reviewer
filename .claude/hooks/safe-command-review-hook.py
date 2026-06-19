#!/usr/bin/env python3
"""
Claude Code PreToolUse Bash command safety reviewer.

Reads a Claude Code hook JSON payload from stdin and writes a Claude Code hook
response JSON to stdout.

This script is intentionally dependency-free.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

VALID_DECISIONS = {"allow", "ask", "deny"}
DECISION_RANK = {"allow": 0, "ask": 1, "deny": 2}


@dataclass
class Review:
    decision: str
    reason: str
    flags: List[str]
    dont_ask_again_safe: bool = False
    source: str = "local"

    def clamp(self) -> "Review":
        if self.decision not in VALID_DECISIONS:
            self.decision = "ask"
        if not self.reason:
            self.reason = "No review reason was provided."
        return self


def getenv_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def getenv_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def read_hook_input() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "_parse_error": str(exc),
            "_raw_stdin_prefix": raw[:500],
        }


def extract_command(payload: Dict[str, Any]) -> Tuple[str, str, str]:
    """Return command, cwd, description from a Claude Code hook payload."""
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}

    command = (
        tool_input.get("command")
        or payload.get("command")
        or payload.get("tool_command")
        or ""
    )
    cwd = (
        payload.get("cwd")
        or tool_input.get("cwd")
        or os.getcwd()
    )
    description = (
        tool_input.get("description")
        or payload.get("description")
        or ""
    )
    return str(command), str(cwd), str(description)


def normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip())


def contains_any(text: str, patterns: List[str]) -> Optional[str]:
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            return p
    return None


def local_review(command: str, cwd: str, description: str) -> Review:
    normalized = normalize_command(command)
    lower = normalized.lower()
    flags: List[str] = []
    reasons: List[str] = []

    if not normalized:
        return Review(
            decision="deny",
            reason="Blocked: no shell command was found in the hook payload.",
            flags=["missing-command"],
            dont_ask_again_safe=False,
        )

    # High-confidence destructive or suspicious commands.
    hard_deny_patterns = [
        r"\brm\s+-[^\n;|&]*[rf][^\n;|&]*\s+/(\s|$)",
        r"\brm\s+-[^\n;|&]*[rf][^\n;|&]*\s+~(\s|/|$)",
        r"\brm\s+-[^\n;|&]*[rf][^\n;|&]*\s+\$HOME(\s|/|$)",
        r"\bdel\s+.*\s/[sq]\b",
        r"\brmdir\s+.*\s/[sq]\b",
        r"\bformat\s+[a-z]:",
        r"\bdiskpart\b",
        r"\bmkfs(\.|\s|$)",
        r"\bdd\s+.*\bof=/dev/",
        r"\bgit\s+clean\s+.*-[^\n;|&]*[fxd]",
        r"\bgit\s+reset\s+--hard\b",
        r"\bchmod\s+-r\s+777\b",
        r"\bcurl\b.*\|\s*(sh|bash|zsh|python|python3|powershell|pwsh)\b",
        r"\bwget\b.*\|\s*(sh|bash|zsh|python|python3|powershell|pwsh)\b",
        r"\binvoke-expression\b",
        r"\biex\b.*(curl|wget|invoke-webrequest|iwr)",
        r"\b-encodedcommand\b",
        r"\bfrombase64string\b.*\b(invoke-expression|iex|powershell|pwsh|cmd)\b",
        r"\bpowershell(\.exe)?\b.*\b-executionpolicy\s+bypass\b",
        r"\bpwsh\b.*\b-executionpolicy\s+bypass\b",
        r"\breg\s+delete\b",
        r"\btakeown\b",
        r"\bicacls\b.*\b/grant\b",
        r"\bicacls\b.*\b/reset\b",
        r"\bicacls\b.*\bremove\b",
        r"\bRemove-Item\b.*\b-Recurse\b.*\b-Force\b",
        r"\bRemove-Item\b.*\b-Force\b.*\b-Recurse\b",
    ]
    matched = contains_any(lower, hard_deny_patterns)
    if matched:
        return Review(
            decision="deny",
            reason=(
                "Blocked: command matched a high-risk destructive or opaque-execution pattern. "
                "Review manually and replace it with a narrower command if it is intentional."
            ),
            flags=["hard-deny", matched],
            dont_ask_again_safe=False,
        )

    # Opaque execution forms should generally be ask, not allow.
    ask_patterns = [
        (r"\bpython\s+-c\b", "inline-python", "Inline Python is opaque and may run arbitrary code."),
        (r"\bpython3\s+-c\b", "inline-python", "Inline Python is opaque and may run arbitrary code."),
        (r"\bnode\s+-e\b", "inline-node", "Inline Node.js is opaque and may run arbitrary code."),
        (r"\bpowershell(\.exe)?\s+.*-command\b", "inline-powershell", "Inline PowerShell is opaque and may run arbitrary code."),
        (r"\bpwsh\s+.*-command\b", "inline-powershell", "Inline PowerShell is opaque and may run arbitrary code."),
        (r"\b(cmd\.exe|cmd)\s+/c\b", "cmd-c", "cmd /c can hide multiple operations behind one shell invocation."),
        (r"\b(sh|bash|zsh)\s+-c\b", "shell-c", "Shell -c can hide multiple operations behind one string."),
        (r"\bsudo\b", "sudo", "sudo can modify system-level files or settings."),
        (r"\bpip\s+install\b", "dependency-install", "Installing dependencies changes the environment."),
        (r"\bnpm\s+install\b", "dependency-install", "Installing dependencies changes the environment."),
        (r"\buv\s+add\b", "dependency-install", "Adding dependencies changes the project environment."),
        (r"\bpoetry\s+add\b", "dependency-install", "Adding dependencies changes the project environment."),
        (r"\bInvoke-WebRequest\b|\biwr\b|\bcurl\b|\bwget\b", "network-download", "Network downloads should be reviewed before execution."),
        (r"\bRemove-Item\b|\brm\b|\bdel\b|\brmdir\b", "delete-or-remove", "The command removes files or directories."),
        (r"\bmove\b|\bmv\b", "move-files", "The command moves files or directories."),
        (r"\bcp\b|\bcopy\b|\bCopy-Item\b", "copy-files", "The command copies files or directories."),
        (r">\s*[^\s]+", "redirect-write", "The command writes output to a file."),
        (r"\bpowershell(\.exe)?\b", "powershell", "PowerShell can perform broad system or filesystem changes."),
        (r"\bpwsh\b", "powershell", "PowerShell can perform broad system or filesystem changes."),
        (r"\breg\b", "registry", "Registry commands can change Windows system or application behavior."),
        (r"\bNew-Item\b|\bSet-Content\b|\bAdd-Content\b", "powershell-write", "The command writes or creates files."),        
    ]
    for pattern, flag, reason in ask_patterns:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            if flag not in flags:
                flags.append(flag)
                reasons.append(reason)

    # Relative safety allow-list for common read-only or test commands.
    allow_readonly = getenv_bool("CC_AI_REVIEW_ALLOW_READONLY", True)
    readonly_patterns = [
        r"^pwd$",
        r"^ls(\s|$)",
        r"^dir(\s|$)",
        r"^git\s+status(\s|$)",
        r"^git\s+diff(\s|$)",
        r"^git\s+log(\s|$)",
        r"^python\s+--version$",
        r"^python\s+-V$",
        r"^python3\s+--version$",
        r"^node\s+--version$",
        r"^npm\s+--version$",
        r"^dotnet\s+--version$",
        r"^pytest(\s|$)",
        r"^python\s+-m\s+pytest(\s|$)",
        r"^python3\s+-m\s+pytest(\s|$)",
        r"^dotnet\s+test(\s|$)",
        r"^npm\s+test(\s|$)",
    ]

    if reasons:
        # Mention "don't ask again" explicitly for broad opaque forms.
        daa = " Do not choose a broad 'don't ask again' rule for this command shape."
        return Review(
            decision="ask",
            reason="Review recommended: " + " ".join(reasons[:3]) + daa,
            flags=flags,
            dont_ask_again_safe=False,
        )

    if allow_readonly and contains_any(normalized, readonly_patterns):
        return Review(
            decision="allow",
            reason="Allowed: command appears to be a common read-only or test command.",
            flags=["readonly-or-test"],
            dont_ask_again_safe=True,
        )

    return Review(
        decision="ask",
        reason="Review recommended: command is not obviously read-only, and no external reviewer overrode the local default.",
        flags=["default-ask"],
        dont_ask_again_safe=False,
    )


def build_external_payload(command: str, cwd: str, description: str, local: Review) -> Dict[str, Any]:
    return {
        "command": command,
        "cwd": cwd,
        "description": description,
        "local_decision": local.decision,
        "local_reason": local.reason,
        "local_flags": local.flags,
        "dont_ask_again_safe_local": local.dont_ask_again_safe,
        "required_output_contract": {
            "decision": "allow|ask|deny",
            "reason": "plain English explanation for Aaron",
            "dont_ask_again_safe": "boolean"
        },
    }


def parse_external_review(data: Any, source: str) -> Review:
    if not isinstance(data, dict):
        raise ValueError("Reviewer output was not a JSON object.")

    # Full Claude hook response accepted.
    hso = data.get("hookSpecificOutput")
    if isinstance(hso, dict):
        decision = str(hso.get("permissionDecision") or "ask").lower()
        reason = str(hso.get("permissionDecisionReason") or "External reviewer returned no reason.")
        return Review(
            decision=decision,
            reason=reason,
            flags=list(data.get("flags") or [source]),
            dont_ask_again_safe=bool(data.get("dont_ask_again_safe", False)),
            source=source,
        ).clamp()

    decision = str(data.get("decision") or data.get("permissionDecision") or "ask").lower()
    reason = str(data.get("reason") or data.get("permissionDecisionReason") or "External reviewer returned no reason.")
    flags = data.get("flags")
    if not isinstance(flags, list):
        flags = [source]
    return Review(
        decision=decision,
        reason=reason,
        flags=[str(x) for x in flags],
        dont_ask_again_safe=bool(data.get("dont_ask_again_safe", False)),
        source=source,
    ).clamp()


def call_http_reviewer(payload: Dict[str, Any], timeout: int) -> Review:
    url = os.environ.get("CC_AI_REVIEW_URL", "").strip()
    if not url:
        raise RuntimeError("CC_AI_REVIEW_URL is not set.")
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return parse_external_review(json.loads(raw), "http-reviewer")


def call_command_reviewer(payload: Dict[str, Any], timeout: int) -> Review:
    cmd = os.environ.get("CC_AI_REVIEW_COMMAND", "").strip()
    if not cmd:
        raise RuntimeError("CC_AI_REVIEW_COMMAND is not set.")
    proc = subprocess.run(
        cmd,
        input=json.dumps(payload),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Reviewer command exited {proc.returncode}: {proc.stderr[:500]}")
    return parse_external_review(json.loads(proc.stdout), "command-reviewer")


def combine_reviews(local: Review, external: Optional[Review], external_error: Optional[str]) -> Review:
    allow_external_override = getenv_bool("CC_AI_REVIEW_ALLOW_EXTERNAL_OVERRIDE", False)
    fail_mode = os.environ.get("CC_AI_REVIEW_FAIL_MODE", "ask").strip().lower()
    if fail_mode not in {"ask", "deny"}:
        fail_mode = "ask"

    if local.decision == "deny":
        return local

    if external_error:
        return Review(
            decision=fail_mode,
            reason=f"External reviewer unavailable or invalid; using fail mode '{fail_mode}'. Error: {external_error}",
            flags=local.flags + ["reviewer-failed"],
            dont_ask_again_safe=False,
            source="combined",
        )

    if external is None:
        return local

    # Hard-deny from external always wins.
    if external.decision == "deny":
        return external

    # Local ask is a floor unless explicitly overridden.
    if local.decision == "ask" and external.decision == "allow" and not allow_external_override:
        return Review(
            decision="ask",
            reason=(
                f"External reviewer thought this was safe, but local policy still requires review. "
                f"External reason: {external.reason} Local reason: {local.reason}"
            ),
            flags=list(dict.fromkeys(local.flags + external.flags + ["local-risk-floor"])),
            dont_ask_again_safe=False,
            source="combined",
        )

    # Otherwise use the stricter of the two decisions.
    if DECISION_RANK[local.decision] >= DECISION_RANK[external.decision]:
        chosen = local
        other = external
    else:
        chosen = external
        other = local

    return Review(
        decision=chosen.decision,
        reason=f"{chosen.reason} Other reviewer note: {other.reason}",
        flags=list(dict.fromkeys(chosen.flags + other.flags)),
        dont_ask_again_safe=chosen.dont_ask_again_safe and other.dont_ask_again_safe,
        source="combined",
    ).clamp()


def hook_response(review: Review) -> Dict[str, Any]:
    reason = review.reason
    if not review.dont_ask_again_safe:
        reason += " Don't use a broad 'Yes, and don't ask again' approval for this command pattern."
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": review.decision,
            "permissionDecisionReason": reason,
        },
        "metadata": {
            "source": review.source,
            "flags": review.flags,
            "dont_ask_again_safe": review.dont_ask_again_safe,
        },
    }


def main() -> int:
    payload = read_hook_input()
    if payload.get("_parse_error"):
        review = Review(
            decision="ask",
            reason=f"Could not parse Claude Code hook input JSON: {payload['_parse_error']}",
            flags=["hook-input-parse-error"],
            dont_ask_again_safe=False,
        )
        print(json.dumps(hook_response(review), ensure_ascii=False))
        return 0

    command, cwd, description = extract_command(payload)
    local = local_review(command, cwd, description)

    external: Optional[Review] = None
    external_error: Optional[str] = None
    timeout = getenv_int("CC_AI_REVIEW_TIMEOUT_SECONDS", 20)

    try:
        ext_payload = build_external_payload(command, cwd, description, local)
        if os.environ.get("CC_AI_REVIEW_URL"):
            external = call_http_reviewer(ext_payload, timeout)
        elif os.environ.get("CC_AI_REVIEW_COMMAND"):
            external = call_command_reviewer(ext_payload, timeout)
    except Exception as exc:  # Fail closed-ish via combine_reviews.
        external_error = str(exc)

    final = combine_reviews(local, external, external_error).clamp()
    print(json.dumps(hook_response(final), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
