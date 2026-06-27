#!/usr/bin/env python3
"""
Claude Code PreToolUse Bash command safety reviewer.

Reads a Claude Code hook JSON payload from stdin and writes a Claude Code hook
response JSON to stdout.

This script is intentionally dependency-free.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

VALID_DECISIONS = {"allow", "ask", "deny"}
DECISION_RANK = {"allow": 0, "ask": 1, "deny": 2}

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5"
ANTHROPIC_SYSTEM_PROMPT = (
    "You are a conservative shell-command safety reviewer for Claude Code.\n"
    "Return ONLY a JSON object with keys: decision, headline, particulars,\n"
    "dont_ask_again_safe, flags.\n"
    "- decision must be one of: allow, ask, deny.\n"
    "- Use allow only for clearly safe read-only or test commands.\n"
    "- Use ask for opaque commands such as python -c, node -e, powershell -Command,\n"
    "  file writes, deletes, downloads, and dependency installs.\n"
    "- Use deny for destructive, exfiltrating, encoded, or web-piped execution commands.\n"
    "- headline is ONE short sentence stating the command's apparent intent and its\n"
    "  overall risk. This is the heading the user reads first.\n"
    "- particulars is an array of short strings, each a SPECIFIC concrete observation.\n"
    "  Name packages being installed and URLs being fetched. Write, delete, move, and\n"
    "  copy target paths are already extracted separately, so do not merely restate file\n"
    "  paths; instead describe what is being changed or why it is risky. Use [] when\n"
    "  nothing is notable. No generic boilerplate and do not repeat the headline.\n"
    "- dont_ask_again_safe is a boolean: true only if a broad 'don't ask again'\n"
    "  approval for this command shape would be safe.\n"
    "- flags is an array of short tag strings.\n"
    "Do not include any text outside the JSON object."
)


def load_dotenv_files() -> None:
    """Load KEY=VALUE pairs from .env into os.environ without overriding existing
    variables. Dependency-free and best-effort; never raises.

    Looks in the Claude Code project dir, this hook's project root, and the cwd,
    so an ANTHROPIC_API_KEY (or other config) placed in a project .env is picked
    up even though the hook process inherits a minimal environment.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(here))  # .claude/hooks -> root
    candidates = [
        os.path.join(os.environ.get("CLAUDE_PROJECT_DIR", ""), ".env"),
        os.path.join(project_root, ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]
    seen = set()
    for path in candidates:
        try:
            if not path or not os.path.isfile(path):
                continue
            norm = os.path.normcase(os.path.abspath(path))
            if norm in seen:
                continue
            seen.add(norm)
            with open(path, "r", encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("export "):
                        line = line[len("export "):].strip()
                    if "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                        value = value[1:-1]
                    if key and key not in os.environ:
                        os.environ[key] = value
        except Exception:
            # Never let .env parsing break the hook.
            pass


@dataclass
class Review:
    decision: str
    # headline: one short sentence the user reads first (intent + overall risk).
    # particulars: specific concrete observations (filenames, packages, URLs...).
    # The rendered prompt is headline + bulleted particulars + footer caution.
    headline: str
    particulars: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    dont_ask_again_safe: bool = False
    source: str = "local"

    def clamp(self) -> "Review":
        if self.decision not in VALID_DECISIONS:
            self.decision = "ask"
        if not self.headline:
            self.headline = "No review reason was provided."
        return self


def merge_particulars(*lists: List[str]) -> List[str]:
    """Concatenate particular-lists, trimming blanks and case-insensitive dupes."""
    out: List[str] = []
    seen = set()
    for lst in lists:
        for item in lst or []:
            text = str(item).strip()
            key = text.lower()
            if text and key not in seen:
                seen.add(key)
                out.append(text)
    return out


# Bullet marker that still reads as a list if the permission UI flattens the
# newlines to spaces ("headline - a - b footer"), so the format degrades safely
# whether or not line breaks survive in the terminal. Kept ASCII so it can never
# trip a console encoding that lacks a fancier glyph.
_BULLET = " - "
_FOOTER = "Avoid a broad 'Yes, and don't ask again' approval for this command shape."


def render_reason(review: Review, max_particulars: int = 10) -> str:
    """Assemble the displayed reason: headline, bulleted particulars, footer."""
    head = (review.headline or "Command review.").strip()
    lines = [head]
    for item in merge_particulars(review.particulars)[:max_particulars]:
        lines.append(_BULLET + item)
    if not review.dont_ask_again_safe:
        lines.append(_FOOTER)
    return "\n".join(lines)


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


def _strip_quotes(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        token = token[1:-1]
    return token


def _quoted_spans(command: str) -> List[Tuple[int, int]]:
    """Index ranges covered by single/double-quoted strings (best-effort)."""
    return [(mm.start(), mm.end())
            for mm in re.finditer(r"\"[^\"]*\"|'[^']*'", command)]


def _inside_quotes(pos: int, spans: List[Tuple[int, int]]) -> bool:
    """True if pos falls within any quoted span. Used to ignore write/delete/move
    keywords that appear inside a string (e.g. git commit -m "move foo to bar"),
    which would otherwise be named as bogus targets."""
    return any(start <= pos < end for start, end in spans)


# Best-effort patterns for the *file path* a command writes to. These name the
# target; they do NOT decide whether a write happens (that stays with the
# detection flags, which must fail toward 'ask' even when no name parses).
_TARGET = r"(\"[^\"]+\"|'[^']+'|[^\s;|&<>()\"']+)"
_WRITE_TARGET_PATTERNS = [
    # Shell redirections to a file. Excludes fd dups (2>&1, >&1, 1>&2) via the
    # negative lookahead; tolerates an optional clobber pipe (>| file).
    r"(?:\d+|&)?>>?\|?\s*(?!&)" + _TARGET,
    # tee / tee -a FILE
    r"\btee\b(?:\s+-a\b)?\s+" + _TARGET,
    # PowerShell write cmdlets with an explicit path parameter.
    r"\b(?:Out-File|Set-Content|Add-Content|New-Item|Tee-Object)\b[^;|]*?"
    r"-(?:File|Literal)?Path\s+" + _TARGET,
    # PowerShell write cmdlets with a positional path (e.g. | Out-File log.txt).
    r"\b(?:Out-File|Set-Content|Add-Content|Tee-Object)\s+(?!-)" + _TARGET,
]


def extract_write_targets(command: str, max_targets: int = 5, max_len: int = 60) -> List[str]:
    """Best-effort extraction of the file paths a command writes to.

    Surfaces the concrete redirect / tee / PowerShell-cmdlet targets so a
    permission prompt can say *which* file will be written even when the write
    is buried in a long command. Literal $VAR / %VAR% / Windows paths are
    surfaced as-is; variables are intentionally left unresolved (a wrong
    resolution would be worse than the literal). Naming only -- never gates
    detection.
    """
    targets: List[str] = []
    spans = _quoted_spans(command)
    for pattern in _WRITE_TARGET_PATTERNS:
        for match in re.finditer(pattern, command, flags=re.IGNORECASE):
            # Ignore an operator/cmdlet sitting inside a quoted string
            # (e.g. echo "a > b") -- that is text, not a real redirection.
            if _inside_quotes(match.start(), spans):
                continue
            # Strip matched quotes, then any stray trailing/leading punctuation a
            # bare token may have swept up when the path abuts a quote/comma in
            # surrounding code, JSON, or a list (e.g. ...x.cs",  ->  x.cs).
            token = _strip_quotes(match.group(1)).strip("\"',;")
            if not token:
                continue
            if len(token) > max_len:
                token = token[: max_len - 3] + "..."
            if token not in targets:
                targets.append(token)
                if len(targets) >= max_targets:
                    return targets
    return targets


# Keyword-anchored extraction for commands whose targets are positional
# arguments (deletes, moves) rather than a redirect operator. Like the write
# extractor this only *names* targets; detection stays with the flags.
_DELETE_KEYWORDS = r"\b(?:Remove-Item|rm|del|rmdir)\b"
_MOVE_KEYWORDS = r"\b(?:Move-Item|move|mv)\b"
_COPY_KEYWORDS = r"\b(?:Copy-Item|copy|cp)\b"
_ARG_TOKEN = re.compile(r"\"[^\"]+\"|'[^']+'|\S+")
# A token that begins a redirection (>, 2>, 2>&1) or another command
# (; | & &&) ends the current command's argument list.
_ARG_STOP = re.compile(r"\d*[<>&|;]")


def _paths_after_keyword(command: str, keyword_regex: str,
                         max_targets: int = 6, max_len: int = 60) -> List[str]:
    """Collect the path-like positional args following each keyword match, up to
    the next shell separator. Option flags (-x, --x, single-letter /x) are
    skipped. Best-effort and naming-only -- never gates detection.
    """
    paths: List[str] = []
    spans = _quoted_spans(command)
    for keyword in re.finditer(keyword_regex, command, flags=re.IGNORECASE):
        # Ignore the keyword when it appears inside a quoted string
        # (e.g. git commit -m "move foo to bar") -- not an actual command.
        if _inside_quotes(keyword.start(), spans):
            continue
        for tok_match in _ARG_TOKEN.finditer(command[keyword.end():]):
            tok = tok_match.group(0)
            if _ARG_STOP.match(tok):        # redirection / next command: stop
                break
            if tok.startswith("-"):         # POSIX / PowerShell option flag
                continue
            if re.fullmatch(r"/[A-Za-z]", tok):  # cmd-style switch (/q /s /f)
                continue
            cleaned = _strip_quotes(tok).strip("\"',;")
            if not cleaned:
                continue
            if len(cleaned) > max_len:
                cleaned = cleaned[: max_len - 3] + "..."
            if cleaned not in paths:
                paths.append(cleaned)
                if len(paths) >= max_targets:
                    return paths
    return paths


def extract_delete_targets(command: str) -> List[str]:
    """Best-effort: paths an rm / del / rmdir / Remove-Item command would delete."""
    return _paths_after_keyword(command, _DELETE_KEYWORDS)


def extract_move_targets(command: str) -> List[str]:
    """Best-effort: source/destination paths of an mv / move / Move-Item command."""
    return _paths_after_keyword(command, _MOVE_KEYWORDS)


def extract_copy_targets(command: str) -> List[str]:
    """Best-effort: source/destination paths of a cp / copy / Copy-Item command."""
    return _paths_after_keyword(command, _COPY_KEYWORDS)


def local_review(command: str, cwd: str, description: str) -> Review:
    normalized = normalize_command(command)
    lower = normalized.lower()
    flags: List[str] = []
    reasons: List[str] = []

    if not normalized:
        return Review(
            decision="deny",
            headline="Blocked: no shell command was found in the hook payload.",
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
            headline="Blocked: command matches a high-risk destructive or opaque-execution pattern.",
            particulars=["Review manually and replace it with a narrower command if it is intentional."],
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
        (r"(?:\d+|&)?>>?(?!&)", "redirect-write", "The command writes output to a file."),
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
        # One particular per matched flag. For a detected write/delete/move, name
        # the target path(s) so the prompt is actionable even when the action is
        # buried in a long command. Naming is additive: if extraction finds
        # nothing the detection flag still holds the line (the action is still
        # reported, just unnamed).
        write_reasons = {
            "The command writes output to a file.",
            "The command writes or creates files.",
        }
        delete_reason = "The command removes files or directories."
        move_reason = "The command moves files or directories."
        copy_reason = "The command copies files or directories."
        write_targets = (
            extract_write_targets(normalized)
            if ("redirect-write" in flags or "powershell-write" in flags)
            else []
        )
        delete_targets = (
            extract_delete_targets(normalized) if "delete-or-remove" in flags else []
        )
        move_targets = (
            extract_move_targets(normalized) if "move-files" in flags else []
        )
        copy_targets = (
            extract_copy_targets(normalized) if "copy-files" in flags else []
        )

        def named(label: str, found: List[str], unnamed: str) -> str:
            return f"{label}: " + ", ".join(found) if found else unnamed

        particulars: List[str] = []
        write_added = False
        for r in reasons:
            if r in write_reasons:
                if write_added:
                    continue
                write_added = True
                particulars.append(named(
                    "Writes to file(s)", write_targets,
                    "Writes to a file (target not identified from the command).",
                ))
            elif r == delete_reason:
                particulars.append(named(
                    "Deletes", delete_targets,
                    "Removes files or directories (target not identified from the command).",
                ))
            elif r == move_reason:
                particulars.append(named(
                    "Moves", move_targets,
                    "Moves files or directories (target not identified from the command).",
                ))
            elif r == copy_reason:
                particulars.append(named(
                    "Copies", copy_targets,
                    "Copies files or directories (target not identified from the command).",
                ))
            else:
                particulars.append(r)
        return Review(
            decision="ask",
            headline="Local safety checks flagged this command for review.",
            particulars=particulars,
            flags=flags,
            dont_ask_again_safe=False,
        )

    if allow_readonly and contains_any(normalized, readonly_patterns):
        return Review(
            decision="allow",
            headline="Looks like a common read-only or test command.",
            flags=["readonly-or-test"],
            dont_ask_again_safe=True,
        )

    return Review(
        decision="ask",
        headline="Command isn't recognized as read-only; no external reviewer overrode the local default.",
        flags=["default-ask"],
        dont_ask_again_safe=False,
    )


def build_external_payload(command: str, cwd: str, description: str, local: Review) -> Dict[str, Any]:
    return {
        "command": command,
        "cwd": cwd,
        "description": description,
        "local_decision": local.decision,
        "local_headline": local.headline,
        "local_particulars": local.particulars,
        "local_flags": local.flags,
        "dont_ask_again_safe_local": local.dont_ask_again_safe,
        "required_output_contract": {
            "decision": "allow|ask|deny",
            "headline": "one sentence: the command's apparent intent and overall risk",
            "particulars": ["specific observations; name exact filenames/paths/packages/URLs"],
            "dont_ask_again_safe": "boolean",
        },
    }


def _as_str_list(value: Any) -> List[str]:
    """Coerce a reviewer's particulars field into a clean list of strings."""
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def parse_external_review(data: Any, source: str) -> Review:
    if not isinstance(data, dict):
        raise ValueError("Reviewer output was not a JSON object.")

    # Full Claude hook response accepted.
    hso = data.get("hookSpecificOutput")
    if isinstance(hso, dict):
        decision = str(hso.get("permissionDecision") or "ask").lower()
        headline = str(hso.get("permissionDecisionReason") or "External reviewer returned no reason.")
        return Review(
            decision=decision,
            headline=headline,
            particulars=_as_str_list(data.get("particulars")),
            flags=list(data.get("flags") or [source]),
            dont_ask_again_safe=bool(data.get("dont_ask_again_safe", False)),
            source=source,
        ).clamp()

    decision = str(data.get("decision") or data.get("permissionDecision") or "ask").lower()
    # Prefer the structured headline; fall back to a legacy flat 'reason'.
    headline = str(
        data.get("headline")
        or data.get("reason")
        or data.get("permissionDecisionReason")
        or "External reviewer returned no reason."
    )
    flags = data.get("flags")
    if not isinstance(flags, list):
        flags = [source]
    return Review(
        decision=decision,
        headline=headline,
        particulars=_as_str_list(data.get("particulars")),
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


def extract_anthropic_text(data: Dict[str, Any]) -> str:
    """Join the text blocks of an Anthropic Messages API response."""
    parts: List[str] = []
    for block in data.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "".join(parts).strip()


def call_anthropic_reviewer(payload: Dict[str, Any], timeout: int) -> Review:
    """Ask Claude directly (no SDK, stdlib only) for a second opinion.

    This is the zero-config default reviewer: set ANTHROPIC_API_KEY and it works.
    CC_AI_REVIEW_URL / CC_AI_REVIEW_COMMAND take precedence if you prefer to route
    through your own service or a different provider.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")
    model = os.environ.get("CC_AI_REVIEW_ANTHROPIC_MODEL", "").strip() or DEFAULT_ANTHROPIC_MODEL
    body = json.dumps({
        "model": model,
        "max_tokens": 512,
        "temperature": 0,
        "system": ANTHROPIC_SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": "Review this Claude Code shell command:\n\n" + json.dumps(payload, indent=2),
            }
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    text = extract_anthropic_text(json.loads(raw))
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # Be forgiving if the model wrapped the JSON in prose or code fences.
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError(f"Anthropic reviewer returned no JSON object: {text[:200]}")
        obj = json.loads(match.group(0))
    return parse_external_review(obj, "anthropic")


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
            headline=f"External reviewer unavailable; using fail mode '{fail_mode}'.",
            particulars=merge_particulars(local.particulars, [f"Reviewer error: {external_error}"]),
            flags=local.flags + ["reviewer-failed"],
            dont_ask_again_safe=False,
            source="combined",
        )

    if external is None:
        return local

    # Hard-deny from external always wins; keep local particulars for context.
    if external.decision == "deny":
        return Review(
            decision="deny",
            headline=external.headline,
            particulars=merge_particulars(external.particulars, local.particulars),
            flags=list(dict.fromkeys(external.flags + local.flags)),
            dont_ask_again_safe=False,
            source="combined",
        )

    # Local ask is a floor unless explicitly overridden. Keep the external
    # intent as the headline and record the floor itself as a particular.
    if local.decision == "ask" and external.decision == "allow" and not allow_external_override:
        return Review(
            decision="ask",
            headline=external.headline or "Local policy requires review for this command.",
            particulars=merge_particulars(
                local.particulars,
                external.particulars,
                ["Local policy requires review for this command shape (external reviewer rated it safe)."],
            ),
            flags=list(dict.fromkeys(local.flags + external.flags + ["local-risk-floor"])),
            dont_ask_again_safe=False,
            source="combined",
        )

    # Otherwise use the stricter of the two decisions. Prefer the external
    # one-sentence intent for the headline when it is available.
    if DECISION_RANK[local.decision] >= DECISION_RANK[external.decision]:
        chosen = local
        other = external
    else:
        chosen = external
        other = local

    return Review(
        decision=chosen.decision,
        headline=external.headline or chosen.headline,
        particulars=merge_particulars(chosen.particulars, other.particulars),
        flags=list(dict.fromkeys(chosen.flags + other.flags)),
        dont_ask_again_safe=chosen.dont_ask_again_safe and other.dont_ask_again_safe,
        source="combined",
    ).clamp()


def log_review(command: str, cwd: str, description: str, review: Review) -> None:
    """Append one JSON line per invocation when CC_AI_REVIEW_LOG is set.

    Logging is opt-in and must never break the hook, so all errors are
    swallowed. Claude Code only surfaces a PreToolUse decision back to the
    model on 'deny', so this log is the only record of 'allow'/'ask' outcomes.
    """
    log_path = os.environ.get("CC_AI_REVIEW_LOG", "").strip()
    if not log_path:
        return
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "decision": review.decision,
        "source": review.source,
        "flags": review.flags,
        "dont_ask_again_safe": review.dont_ask_again_safe,
        "command": command,
        "cwd": cwd,
        "description": description,
        "headline": review.headline,
        "particulars": review.particulars,
    }
    try:
        path = os.path.expanduser(os.path.expandvars(log_path))
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # A logging failure must not change the review decision.
        pass


def hook_response(review: Review) -> Dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": review.decision,
            "permissionDecisionReason": render_reason(review),
        },
        "metadata": {
            "source": review.source,
            "flags": review.flags,
            "dont_ask_again_safe": review.dont_ask_again_safe,
        },
    }


def main() -> int:
    # JSON is emitted with ensure_ascii=False and may carry non-ASCII paths from
    # the AI reviewer; force UTF-8 stdout so a narrow console encoding can never
    # raise mid-print and break the hook.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    load_dotenv_files()

    payload = read_hook_input()
    if payload.get("_parse_error"):
        review = Review(
            decision="ask",
            headline=f"Could not parse Claude Code hook input JSON: {payload['_parse_error']}",
            flags=["hook-input-parse-error"],
            dont_ask_again_safe=False,
        )
        log_review("", os.getcwd(), "", review)
        print(json.dumps(hook_response(review), ensure_ascii=False))
        return 0

    command, cwd, description = extract_command(payload)
    local = local_review(command, cwd, description)

    external: Optional[Review] = None
    external_error: Optional[str] = None
    timeout = getenv_int("CC_AI_REVIEW_TIMEOUT_SECONDS", 20)

    # A local hard-deny already wins in combine_reviews, so don't spend a
    # network round-trip (and API cost) asking an external reviewer about it.
    if local.decision != "deny":
        try:
            ext_payload = build_external_payload(command, cwd, description, local)
            if os.environ.get("CC_AI_REVIEW_URL"):
                external = call_http_reviewer(ext_payload, timeout)
            elif os.environ.get("CC_AI_REVIEW_COMMAND"):
                external = call_command_reviewer(ext_payload, timeout)
            elif os.environ.get("ANTHROPIC_API_KEY"):
                external = call_anthropic_reviewer(ext_payload, timeout)
        except Exception as exc:  # Fail closed-ish via combine_reviews.
            external_error = str(exc)

    final = combine_reviews(local, external, external_error).clamp()
    log_review(command, cwd, description, final)
    print(json.dumps(hook_response(final), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
