"""Exception grants: read, validate, and match user-approved command exceptions.

See exception-grants-design.md and exception-grants-implementation-plan.md.

The pure functions come first and run on every OS. The Windows calls live in
the "Windows" section at the bottom and are used only on ``sys.platform ==
"win32"``. Nothing Windows-specific runs at import time, because the hook core
imports this module on every platform.

The PowerShell writer (grant-writer/grant-writer.ps1) implements the same
validation rules. Shared fixtures under tests/fixtures/ keep the two in step,
so a change to a rule here must be made there too, in the same order.
"""
from __future__ import annotations

import json
import ntpath
import os
import re
import stat
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

MAX_FILE_BYTES = 1_048_576
KNOWN_HOSTS = ("claude", "codex", "cursor", "windsurf", "devin", "antigravity")

# Every pattern is anchored with \A and \Z, not ^ and $: in Python (and .NET)
# `$` also matches just before a trailing newline, so "push\n" would pass a
# `^...$` name check. Character classes spell out [0-9] because `\d` matches
# every Unicode digit, not just ASCII ones.
NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9-]{0,39}\Z")
DURATION_RE = re.compile(r"\A([1-9][0-9]{0,3})([mhd])\Z")
REQUEST_TS_RE = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(Z|([+-])([0-9]{2}):([0-9]{2}))\Z"
)
STORED_TS_RE = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z"
)
SID_RE = re.compile(r"\AS-1-(0|[1-9][0-9]{0,14})((-(0|[1-9][0-9]{0,9})){1,15})\Z")
SID_MAX_AUTHORITY = 2 ** 48 - 1
SID_MAX_SUBAUTHORITY = 4294967295
GRANT_ID_RE = re.compile(r"\Ag-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
REVOKE_ID_RE = re.compile(r"\Ar-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z")
DRIVE_PATH_RE = re.compile(r"\A[A-Za-z]:[\\/]")

MAX_COMMANDS = 20
MAX_COMMAND_CHARS = 8000
MAX_TOOL_CHARS = 40
MAX_WHY_CHARS = 1000
MAX_USER_DISPLAY_CHARS = 256

WHERE_VALUES = ("dir", "repo", "any")

#: Characters that make a command "whitespace-only". Spelled out rather than
#: relying on str.isspace(), because .NET's Char.IsWhiteSpace uses a different
#: set (it excludes U+001C..U+001F) and both sides must agree. This is exactly
#: the set Python's str.isspace() accepts.
WHITESPACE_CHARS = frozenset(
    "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)

#: Field tables, in validation order. The order is part of the contract: the
#: first error reported must be the same in Python and in the writer.
REQUEST_FIELDS = ("v", "name", "commands", "tool", "where", "cwd", "hosts", "expires", "why")
REQUEST_REQUIRED = tuple(f for f in REQUEST_FIELDS if f != "cwd")
GRANT_FIELDS = ("v", "type", "id", "name", "ts", "user", "user_display", "commands",
                "tool", "where", "path", "hosts", "expires", "why")
REVOKE_FIELDS = ("v", "type", "id", "ts", "user", "name")


# --------------------------------------------------------------------------
# Errors and records
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationError:
    code: str
    field: Optional[str] = None
    line: Optional[int] = None

    def describe(self) -> str:
        where = f"line {self.line}: " if self.line is not None else ""
        what = f" in '{self.field}'" if self.field is not None else ""
        return f"{where}{self.code}{what}"

    def with_line(self, line: int) -> "ValidationError":
        return ValidationError(self.code, self.field, line)


class GrantFileInvalid(Exception):
    def __init__(self, error: ValidationError) -> None:
        super().__init__(error.describe())
        self.error = error


class _JsonError(Exception):
    def __init__(self, code: str, field: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.field = field


@dataclass(frozen=True)
class Grant:
    id: str
    name: str
    ts: datetime
    user: str
    user_display: str
    commands: Tuple[str, ...]
    tool: str
    where: str                 # "dir" | "repo" | "any"
    path: Optional[str]
    hosts: Optional[Tuple[str, ...]]
    expires: Optional[datetime]
    why: str
    line: int


@dataclass(frozen=True)
class Revoke:
    id: str
    ts: datetime
    user: str
    name: str                  # a grant name, or "*"
    line: int


# --------------------------------------------------------------------------
# Small helpers shared by request and record validation
# --------------------------------------------------------------------------

def _is_json_int(value: Any) -> bool:
    # `type(...) is int`, because isinstance(True, int) is True in Python.
    return type(value) is int


def _has_lone_surrogate(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def _parse_timestamp(match: "re.Match[str]") -> Optional[datetime]:
    """Build an aware datetime from a REQUEST_TS_RE or STORED_TS_RE match.

    Returns None when a field is out of range (month 13, second 60, offset
    hour 24...). Parsed by hand rather than with strptime, so the rules are
    exactly the ones the writer applies.
    """
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    tz: timezone = timezone.utc
    groups = match.groups()
    if len(groups) > 6 and groups[6] != "Z":
        sign = 1 if groups[7] == "+" else -1
        offset_hours = int(groups[8])
        offset_minutes = int(groups[9])
        if offset_hours > 23 or offset_minutes > 59:
            return None
        tz = timezone(sign * timedelta(hours=offset_hours, minutes=offset_minutes))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except ValueError:
        return None


def parse_stored_timestamp(text: str) -> Optional[datetime]:
    match = STORED_TS_RE.match(text)
    return _parse_timestamp(match) if match else None


def parse_request_timestamp(text: str) -> Optional[datetime]:
    match = REQUEST_TS_RE.match(text)
    return _parse_timestamp(match) if match else None


def format_stored_timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_valid_sid(text: str) -> bool:
    """Decision D19: a regex plus numeric limits, identical in the writer."""
    match = SID_RE.match(text)
    if not match:
        return False
    if int(match.group(1)) > SID_MAX_AUTHORITY:
        return False
    sub_authorities = match.group(2)[1:].split("-")
    return all(int(part) <= SID_MAX_SUBAUTHORITY for part in sub_authorities)


def _path_error(value: Any, field: str) -> Optional[ValidationError]:
    """Shared rule for a request `cwd` and a stored `path`: drive-absolute,
    with no `.` or `..` components."""
    if not isinstance(value, str):
        return ValidationError("bad-type", field)
    if not DRIVE_PATH_RE.match(value) or _has_lone_surrogate(value):
        return ValidationError("bad-value", field)
    components = re.split(r"[\\/]", value)
    if any(part in (".", "..") for part in components):
        return ValidationError("bad-value", field)
    return None


def _v_error(value: Any) -> Optional[ValidationError]:
    if _is_json_int(value):
        return None if value == 1 else ValidationError("bad-value", "v")
    return ValidationError("bad-type", "v")


def _name_error(value: Any, allow_star: bool = False) -> Optional[ValidationError]:
    if not isinstance(value, str):
        return ValidationError("bad-type", "name")
    if allow_star and value == "*":
        return None
    if not NAME_RE.match(value):
        return ValidationError("bad-value", "name")
    return None


def _commands_error(value: Any) -> Optional[ValidationError]:
    if not isinstance(value, list):
        return ValidationError("bad-type", "commands")
    if not 1 <= len(value) <= MAX_COMMANDS:
        return ValidationError("bad-value", "commands")
    seen = set()
    for item in value:
        if not isinstance(item, str):
            return ValidationError("bad-type", "commands")
        if not 1 <= len(item) <= MAX_COMMAND_CHARS:
            return ValidationError("bad-value", "commands")
        if "\x00" in item:
            return ValidationError("bad-value", "commands")
        if all(ch in WHITESPACE_CHARS for ch in item):
            return ValidationError("bad-value", "commands")
        if _has_lone_surrogate(item):
            return ValidationError("bad-value", "commands")
        if item in seen:
            return ValidationError("bad-value", "commands")
        seen.add(item)
    return None


def _bounded_text_error(value: Any, field: str, low: int, high: int) -> Optional[ValidationError]:
    if not isinstance(value, str):
        return ValidationError("bad-type", field)
    if not low <= len(value) <= high:
        return ValidationError("bad-value", field)
    if _has_lone_surrogate(value):
        return ValidationError("bad-value", field)
    return None


def _where_error(value: Any) -> Optional[ValidationError]:
    if not isinstance(value, str):
        return ValidationError("bad-type", "where")
    if value not in WHERE_VALUES:
        return ValidationError("bad-value", "where")
    return None


def _hosts_error(value: Any) -> Optional[ValidationError]:
    if value is None:
        return None
    if not isinstance(value, list):
        return ValidationError("bad-type", "hosts")
    if not value:
        return ValidationError("bad-value", "hosts")
    seen = set()
    for item in value:
        if not isinstance(item, str):
            return ValidationError("bad-type", "hosts")
        if item not in KNOWN_HOSTS or item in seen:
            return ValidationError("bad-value", "hosts")
        seen.add(item)
    return None


def _schema_key_error(obj: Dict[str, Any], allowed: Tuple[str, ...],
                      required: Tuple[str, ...]) -> Optional[ValidationError]:
    allowed_set = set(allowed)
    for key in obj:
        if key not in allowed_set:
            return ValidationError("unknown-field", key)
    for key in required:
        if key not in obj:
            return ValidationError("missing-field", key)
    return None


# --------------------------------------------------------------------------
# Request validation (text only; the writer adds conversion on top)
# --------------------------------------------------------------------------

def validate_request(obj: Any, now: datetime) -> Optional[ValidationError]:
    """Check a request block by its text alone. Never touches the filesystem."""
    if not isinstance(obj, dict):
        return ValidationError("not-object")
    error = _schema_key_error(obj, REQUEST_FIELDS, REQUEST_REQUIRED)
    if error:
        return error

    checks = (
        lambda: _v_error(obj["v"]),
        lambda: _name_error(obj["name"]),
        lambda: _commands_error(obj["commands"]),
        lambda: _bounded_text_error(obj["tool"], "tool", 0, MAX_TOOL_CHARS),
        lambda: _where_error(obj["where"]),
        lambda: _request_cwd_error(obj),
        lambda: _hosts_error(obj["hosts"]),
        lambda: _request_expires_error(obj["expires"], now),
        lambda: _bounded_text_error(obj["why"], "why", 0, MAX_WHY_CHARS),
    )
    for check in checks:
        error = check()
        if error:
            return error
    return None


def _request_cwd_error(obj: Dict[str, Any]) -> Optional[ValidationError]:
    cwd = obj.get("cwd")
    if obj["where"] == "any":
        return None if cwd is None else ValidationError("bad-value", "cwd")
    if "cwd" not in obj:
        return ValidationError("missing-field", "cwd")
    return _path_error(cwd, "cwd")


def _request_expires_error(value: Any, now: datetime) -> Optional[ValidationError]:
    if not isinstance(value, str):
        return ValidationError("bad-type", "expires")
    if value == "never" or DURATION_RE.match(value):
        return None
    moment = parse_request_timestamp(value)
    if moment is None:
        return ValidationError("bad-value", "expires")
    if moment <= now:
        return ValidationError("expired", "expires")
    return None


# --------------------------------------------------------------------------
# Stored record validation
# --------------------------------------------------------------------------

def validate_record(obj: Any) -> Optional[ValidationError]:
    if not isinstance(obj, dict):
        return ValidationError("not-object")
    if "type" not in obj:
        return ValidationError("missing-field", "type")
    record_type = obj["type"]
    if record_type == "grant" and isinstance(record_type, str):
        return _grant_record_error(obj)
    if record_type == "revoke" and isinstance(record_type, str):
        return _revoke_record_error(obj)
    return ValidationError("bad-value", "type")


def _id_error(value: Any, pattern: "re.Pattern[str]") -> Optional[ValidationError]:
    if not isinstance(value, str):
        return ValidationError("bad-type", "id")
    if not pattern.match(value):
        return ValidationError("bad-value", "id")
    return None


def _stored_ts_error(value: Any, field: str, nullable: bool) -> Optional[ValidationError]:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        return ValidationError("bad-type", field)
    if parse_stored_timestamp(value) is None:
        return ValidationError("bad-value", field)
    return None


def _user_error(value: Any) -> Optional[ValidationError]:
    if not isinstance(value, str):
        return ValidationError("bad-type", "user")
    if not is_valid_sid(value):
        return ValidationError("bad-value", "user")
    return None


def _stored_path_error(obj: Dict[str, Any]) -> Optional[ValidationError]:
    path = obj["path"]
    if obj["where"] == "any":
        return None if path is None else ValidationError("bad-value", "path")
    if path is None:
        return ValidationError("bad-value", "path")
    return _path_error(path, "path")


def _grant_record_error(obj: Dict[str, Any]) -> Optional[ValidationError]:
    error = _schema_key_error(obj, GRANT_FIELDS, GRANT_FIELDS)
    if error:
        return error
    checks = (
        lambda: _v_error(obj["v"]),
        lambda: _id_error(obj["id"], GRANT_ID_RE),
        lambda: _name_error(obj["name"]),
        lambda: _stored_ts_error(obj["ts"], "ts", nullable=False),
        lambda: _user_error(obj["user"]),
        lambda: _bounded_text_error(obj["user_display"], "user_display", 1,
                                    MAX_USER_DISPLAY_CHARS),
        lambda: _commands_error(obj["commands"]),
        lambda: _bounded_text_error(obj["tool"], "tool", 0, MAX_TOOL_CHARS),
        lambda: _where_error(obj["where"]),
        lambda: _stored_path_error(obj),
        lambda: _hosts_error(obj["hosts"]),
        lambda: _stored_ts_error(obj["expires"], "expires", nullable=True),
        lambda: _bounded_text_error(obj["why"], "why", 0, MAX_WHY_CHARS),
    )
    for check in checks:
        error = check()
        if error:
            return error
    return None


def _revoke_record_error(obj: Dict[str, Any]) -> Optional[ValidationError]:
    error = _schema_key_error(obj, REVOKE_FIELDS, REVOKE_FIELDS)
    if error:
        return error
    checks = (
        lambda: _v_error(obj["v"]),
        lambda: _id_error(obj["id"], REVOKE_ID_RE),
        lambda: _stored_ts_error(obj["ts"], "ts", nullable=False),
        lambda: _user_error(obj["user"]),
        lambda: _name_error(obj["name"], allow_star=True),
    )
    for check in checks:
        error = check()
        if error:
            return error
    return None


# --------------------------------------------------------------------------
# Strict JSON
# --------------------------------------------------------------------------

def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    # Called by json for every object as it closes, with keys already unescaped.
    # So "na\u006de" and "name" compare as the same key, which is what we want.
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _JsonError("duplicate-key", key)
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    # json calls this for NaN, Infinity and -Infinity, which strict JSON forbids.
    raise _JsonError("json-syntax")


#: Decision D21: deeper nesting is a json-syntax error on both sides. Python's
#: own limit depends on the interpreter's recursion limit, so it can't be shared.
MAX_JSON_DEPTH = 64

#: Decision D22: integer literals longer than this are kept as an out-of-range
#: placeholder. Python 3.11+ refuses to convert very long digit strings, and
#: 3.9 doesn't, so without this the verdict would depend on the interpreter.
#: Such a literal can never equal 1, which is the only number the schema uses.
MAX_INT_LITERAL_CHARS = 100
_OVERSIZED_INT = 10 ** MAX_INT_LITERAL_CHARS


def _parse_int(literal: str) -> int:
    if len(literal) > MAX_INT_LITERAL_CHARS:
        return _OVERSIZED_INT
    return int(literal)


def json_depth_exceeds(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when brackets outside strings nest deeper than `limit`.

    Only a pre-check: malformed input is left for the real parser to reject.
    """
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def parse_json_line(text: str) -> Any:
    """Parse one JSON value strictly. Raises _JsonError(code, field)."""
    if json_depth_exceeds(text):
        raise _JsonError("json-syntax")
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates,
                          parse_constant=_reject_constant, parse_int=_parse_int)
    except json.JSONDecodeError as exc:
        raise _JsonError("json-syntax") from exc


def parse_request_bytes(data: bytes, now: datetime) -> Tuple[Any, Optional[ValidationError]]:
    """Decode and validate a request block given as raw bytes (fixtures, CLI).

    The same steps as the writer's clipboard path: strict UTF-8, no BOM, then
    strict JSON, then text validation.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        return None, ValidationError("bom")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, ValidationError("encoding")
    try:
        obj = parse_json_line(text)
    except _JsonError as exc:
        return None, ValidationError(exc.code, exc.field)
    return obj, validate_request(obj, now)


# --------------------------------------------------------------------------
# Whole-file validation
# --------------------------------------------------------------------------

def validate_file_bytes(data: bytes) -> Tuple[List[Grant], List[Revoke]]:
    """Validate a whole grants file. Raises GrantFileInvalid on the first error."""
    def fail(code: str, field: Optional[str] = None, line: Optional[int] = None) -> None:
        raise GrantFileInvalid(ValidationError(code, field, line))

    if len(data) > MAX_FILE_BYTES:
        fail("too-large")
    if data.startswith(b"\xef\xbb\xbf"):
        fail("bom")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("encoding")
    if "\r" in text:
        fail("cr")
    if text == "":
        return [], []
    if not text.endswith("\n"):
        fail("no-final-newline")

    grants: List[Grant] = []
    revokes: List[Revoke] = []
    seen_ids = set()
    for number, line in enumerate(text[:-1].split("\n"), start=1):
        if line == "":
            fail("blank-line", line=number)
        try:
            obj = parse_json_line(line)
        except _JsonError as exc:
            fail(exc.code, exc.field, number)
        error = validate_record(obj)
        if error:
            raise GrantFileInvalid(error.with_line(number))
        if obj["id"] in seen_ids:
            fail("duplicate-id", "id", number)
        seen_ids.add(obj["id"])
        if obj["type"] == "grant":
            grants.append(_grant_from_record(obj, number))
        else:
            revokes.append(_revoke_from_record(obj, number))
    return grants, revokes


def _grant_from_record(obj: Dict[str, Any], line: int) -> Grant:
    expires = obj["expires"]
    hosts = obj["hosts"]
    return Grant(
        id=obj["id"], name=obj["name"], ts=_must_parse(obj["ts"]), user=obj["user"],
        user_display=obj["user_display"], commands=tuple(obj["commands"]),
        tool=obj["tool"], where=obj["where"], path=obj["path"],
        hosts=tuple(hosts) if hosts is not None else None,
        expires=_must_parse(expires) if expires is not None else None,
        why=obj["why"], line=line,
    )


def _revoke_from_record(obj: Dict[str, Any], line: int) -> Revoke:
    return Revoke(id=obj["id"], ts=_must_parse(obj["ts"]), user=obj["user"],
                  name=obj["name"], line=line)


def _must_parse(text: str) -> datetime:
    moment = parse_stored_timestamp(text)
    assert moment is not None  # validate_record already checked it
    return moment


# --------------------------------------------------------------------------
# Active grants and matching
# --------------------------------------------------------------------------

def active_grants(grants: List[Grant], revokes: List[Revoke], now: datetime) -> List[Grant]:
    """Grants not revoked by a later line and not expired, in file order.

    Walking in file order is enough: a revoke only affects grants *earlier* in
    the file, and grants added later are appended after it.
    """
    records: List[Any] = sorted([*grants, *revokes], key=lambda record: record.line)
    active: List[Grant] = []
    for record in records:
        if isinstance(record, Grant):
            active.append(record)
            continue
        active = [
            grant for grant in active
            if not (grant.user == record.user
                    and (record.name == "*" or grant.name == record.name))
        ]
    return [grant for grant in active if grant.expires is None or now < grant.expires]


def canonical_path(path: Any) -> Optional[Tuple[str, ...]]:
    """Lowercase path components, e.g. ("c:", "src", "repo").

    None for anything that is not a drive-letter absolute path. Uses ntpath, so
    Windows rules apply on every OS (and in Ubuntu CI).
    """
    if not isinstance(path, str) or not DRIVE_PATH_RE.match(path):
        return None
    normalized = ntpath.normpath(path)          # "C:/a/./b/../c" -> "C:\a\c"
    parts = [part for part in normalized.split("\\") if part]
    return tuple(part.lower() for part in parts)


def location_matches(grant: Grant, cwd: Any) -> bool:
    if grant.where == "any":
        return True
    current = canonical_path(cwd)
    granted = canonical_path(grant.path)
    if current is None or granted is None:
        return False
    if grant.where == "dir":
        return current == granted
    # "repo": the folder or anything inside it, compared component by component,
    # so C:\repo never matches C:\repo-other.
    return current[:len(granted)] == granted


def first_match(active: List[Grant], command: str, cwd: Any, host: str, tool: str,
                user: str) -> Optional[Grant]:
    for grant in active:
        if grant.user != user:
            continue
        if grant.hosts is not None and host not in grant.hosts:
            continue
        if grant.tool != tool:
            continue
        # `in` on a tuple of str uses ==, which is ordinal and case-sensitive.
        if command not in grant.commands:
            continue
        if not location_matches(grant, cwd):
            continue
        return grant
    return None


def scope_summary(grant: Grant) -> str:
    count = len(grant.commands)
    what = "exact command" if count == 1 else f"{count} exact commands"
    if grant.where == "any":
        place = "any folder"
    elif grant.where == "dir":
        place = f"folder {grant.path}"
    else:
        place = f"any folder of repo {grant.path}"
    if grant.expires is None:
        until = "until revoked"
    else:
        until = "until " + grant.expires.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"Grant {grant.id}: {what}, {place}, {until}"


# --------------------------------------------------------------------------
# Hook text: the help block and the store-mention check
# --------------------------------------------------------------------------

def help_lines(command: str, cwd: Any, host: str, tool: str) -> List[str]:
    lines = ["If this command is needed, ask the user for an exception grant. "
             "Fill in name and why, then give the user this block:"]
    # A Windows cwd is cleaned ("C:/a/./b" -> "C:\a\b"). Anything else becomes ""
    # for the user to fill in (decision D4: never widen the scope to "any").
    clean_cwd = ntpath.normpath(cwd) if canonical_path(cwd) is not None else ""
    request = {"v": 1, "name": "", "commands": [command], "tool": tool,
               "where": "dir", "cwd": clean_cwd,
               "hosts": [host], "expires": "30m", "why": ""}
    # ensure_ascii keeps every invisible or unusual character visible as an
    # escape, and the block still decodes back to the exact command.
    lines.append(json.dumps(request, ensure_ascii=True, separators=(",", ":")))
    if clean_cwd == "":
        lines.append(f"This host reported the folder as {cwd!r}, which is not a Windows "
                     "path. Fill in the Windows folder in cwd.")
    return lines


def mentions_protected_store(command: str, grants_path: str) -> bool:
    """A simple substring test, enough under the guardrail threat model."""
    folder = ntpath.dirname(grants_path).lower()
    needles = {
        folder,
        folder.replace("\\", "/"),
        "aiallow",
        "grant-writer",
        "setup-grants",
        ntpath.basename(grants_path).lower(),
    }
    lower = command.lower()
    return any(needle and needle in lower for needle in needles)


# --------------------------------------------------------------------------
# Security descriptors (pure; testable on any OS)
# --------------------------------------------------------------------------

TRUSTED_SIDS = frozenset({
    "S-1-5-32-544",   # Administrators
    "S-1-5-18",       # SYSTEM
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
})

WRITE_MASK = (0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000
              | 0x10000000 | 0x40000000)
ANCESTOR_MASK = 0x10000 | 0x40 | 0x40000 | 0x80000 | 0x10000000

INHERIT_ONLY_ACE = 0x08
SE_DACL_PRESENT = 0x0004
SE_DACL_PROTECTED = 0x1000
SE_SELF_RELATIVE = 0x8000

_SID_NAMES = {
    "S-1-5-32-545": "Users",
    "S-1-5-11": "Authenticated Users",
    "S-1-1-0": "Everyone",
}


@dataclass(frozen=True)
class Ace:
    type: int     # 0 allow, 1 deny, anything else = unusual
    flags: int    # 0x08 = INHERIT_ONLY
    mask: int
    sid: str


@dataclass(frozen=True)
class ObjectSecurity:
    owner_sid: Optional[str]
    dacl_present: bool        # False means a NULL DACL
    dacl_protected: bool
    aces: Tuple[Ace, ...]
    is_reparse: bool
    malformed: Optional[str] = None   # why the bytes could not be parsed


class _Malformed(Exception):
    pass


def _read_sid(data: bytes, offset: int, limit: int) -> str:
    """Read a SID at `offset`, which must end at or before `limit`."""
    if offset + 8 > limit:
        raise _Malformed("SID header out of range")
    revision, count = data[offset], data[offset + 1]
    if revision != 1 or not 1 <= count <= 15:
        raise _Malformed("bad SID revision or sub-authority count")
    end = offset + 8 + 4 * count
    if end > limit:
        raise _Malformed("SID runs past its container")
    authority = int.from_bytes(data[offset + 2:offset + 8], "big")
    subs = struct.unpack_from(f"<{count}I", data, offset + 8)
    return "S-1-" + str(authority) + "".join(f"-{sub}" for sub in subs)


def parse_security_descriptor(data: bytes, is_reparse: bool) -> ObjectSecurity:
    """Parse a self-relative security descriptor. Never raises.

    A descriptor that can't be parsed comes back with `malformed` set, and the
    rule checks report it as a problem.
    """
    try:
        return _parse_security_descriptor(data, is_reparse)
    except (_Malformed, struct.error) as exc:
        return ObjectSecurity(None, False, False, (), is_reparse, malformed=str(exc) or "bad")


def _parse_security_descriptor(data: bytes, is_reparse: bool) -> ObjectSecurity:
    size = len(data)
    if size < 20:
        raise _Malformed("descriptor shorter than its header")
    revision, _sbz1, control, owner_off, _group_off, _sacl_off, dacl_off = struct.unpack_from(
        "<BBHIIII", data, 0)
    if revision != 1:
        raise _Malformed("descriptor revision is not 1")
    if not control & SE_SELF_RELATIVE:
        raise _Malformed("descriptor is not self-relative")

    owner = _read_sid(data, owner_off, size) if owner_off else None

    dacl_present = bool(control & SE_DACL_PRESENT) and dacl_off != 0
    aces: List[Ace] = []
    if dacl_present:
        if dacl_off + 8 > size:
            raise _Malformed("ACL header out of range")
        acl_revision, _s1, acl_size, ace_count, _s2 = struct.unpack_from("<BBHHH", data, dacl_off)
        if acl_revision not in (2, 4):
            raise _Malformed("unknown ACL revision")
        acl_end = dacl_off + acl_size
        if acl_size < 8 or acl_end > size:
            raise _Malformed("ACL runs past the descriptor")
        cursor = dacl_off + 8
        for _ in range(ace_count):
            if cursor + 4 > acl_end:
                raise _Malformed("ACE header runs past the ACL")
            ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, cursor)
            if ace_size < 4 or cursor + ace_size > acl_end:
                raise _Malformed("ACE runs past the ACL")
            ace_end = cursor + ace_size
            if ace_type in (0, 1):
                if cursor + 8 > ace_end:
                    raise _Malformed("ACE too small for its mask")
                (mask,) = struct.unpack_from("<I", data, cursor + 4)
                sid = _read_sid(data, cursor + 8, ace_end)
                aces.append(Ace(ace_type, ace_flags, mask, sid))
            else:
                aces.append(Ace(ace_type, ace_flags, 0, ""))
            cursor = ace_end

    return ObjectSecurity(
        owner_sid=owner,
        dacl_present=dacl_present,
        dacl_protected=bool(control & SE_DACL_PROTECTED),
        aces=tuple(aces),
        is_reparse=is_reparse,
    )


def _sid_label(sid: str) -> str:
    name = _SID_NAMES.get(sid)
    return f"{name} ({sid})" if name else sid


def _common_problems(sec: ObjectSecurity, label: str) -> List[Tuple[str, str]]:
    """Checks shared by protected objects and ancestors, in the shared order:
    malformed, owner, reparse, null-dacl, ace-type."""
    if sec.malformed is not None:
        return [("malformed", f"could not parse the security of {label}: {sec.malformed}")]
    problems: List[Tuple[str, str]] = []
    if sec.owner_sid not in TRUSTED_SIDS:
        problems.append(("owner", f"{label} is owned by {sec.owner_sid}, not an administrator"))
    if sec.is_reparse:
        problems.append(("reparse", f"{label} is a symlink or junction"))
    if not sec.dacl_present:
        problems.append(("null-dacl", f"{label} has no permission list (everyone may write)"))
        return problems
    for ace in sec.aces:
        if ace.type not in (0, 1):
            problems.append(("ace-type", f"{label} has an unusual permission entry "
                                         f"(type {ace.type})"))
            break
    return problems


def _rights_problems(sec: ObjectSecurity, label: str, mask: int) -> List[Tuple[str, str]]:
    for ace in sec.aces:
        if ace.type != 0 or ace.flags & INHERIT_ONLY_ACE:
            continue  # deny entries only remove rights; inherit-only don't apply here
        if ace.sid in TRUSTED_SIDS:
            continue
        if ace.mask & mask:
            return [("write-right", f"{_sid_label(ace.sid)} can change {label} "
                                    f"(rights {ace.mask & mask:#x})")]
    return []


def protected_object_problems(sec: ObjectSecurity, require_protected_dacl: bool,
                              label: str = "the object") -> List[Tuple[str, str]]:
    """Rule I4, for the grants folder, the grants file and the writer script."""
    problems = _common_problems(sec, label)
    if problems and problems[0][0] == "malformed":
        return problems
    if sec.dacl_present:
        problems.extend(_rights_problems(sec, label, WRITE_MASK))
        if require_protected_dacl and not sec.dacl_protected:
            problems.append(("not-protected", f"{label} inherits permissions from its parent"))
    return problems


def ancestor_problems(sec: ObjectSecurity, label: str = "a parent folder") -> List[Tuple[str, str]]:
    """Rule I5, for every parent folder up to the drive root."""
    problems = _common_problems(sec, label)
    if problems and problems[0][0] == "malformed":
        return problems
    if sec.dacl_present:
        problems.extend(_rights_problems(sec, label, ANCESTOR_MASK))
    return problems


# --------------------------------------------------------------------------
# Windows: security reads, identity, and the store check
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Lookup:
    grant: Optional[Grant]
    note: Optional[str]      # shown to the user when grants were skipped


def read_object_security(path: str) -> ObjectSecurity:
    """Fetch the raw self-relative descriptor of a file or folder. Windows only.

    Interpretation happens entirely in parse_security_descriptor.
    """
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    get_info = advapi32.GetNamedSecurityInfoW
    get_info.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    get_length = advapi32.GetSecurityDescriptorLength
    get_length.argtypes = [ctypes.c_void_p]
    get_length.restype = wintypes.DWORD
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    se_file_object = 1
    owner_and_dacl = 0x1 | 0x4
    descriptor = ctypes.c_void_p()
    result = get_info(path, se_file_object, owner_and_dacl,
                      None, None, None, None, ctypes.byref(descriptor))
    if result != 0:
        raise OSError(result, ctypes.FormatError(result), path)
    try:
        length = get_length(descriptor)
        data = ctypes.string_at(descriptor, length)
    finally:
        local_free(descriptor)

    attributes = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
    is_reparse = bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)  # type: ignore[attr-defined]
    return parse_security_descriptor(data, is_reparse)


def _open_process_token() -> Any:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    token_query = 0x8
    if not open_token(kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    return token


def system_directory() -> str:
    """System32, from GetSystemDirectoryW rather than %SystemRoot% (decision A15)."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_dir = kernel32.GetSystemDirectoryW
    get_dir.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_dir.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_dir(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def _token_information(token: Any, info_class: int) -> Any:
    """Return the filled ctypes buffer. Callers keep it alive while they use
    pointers into it (TOKEN_USER holds a pointer to its own SID)."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_info = advapi32.GetTokenInformation
    get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD)]
    get_info.restype = wintypes.BOOL
    needed = wintypes.DWORD(0)
    get_info(token, info_class, None, 0, ctypes.byref(needed))  # first call: size only
    if needed.value == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not get_info(token, info_class, buffer, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer


def _close_handle(handle: Any) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(handle)


def current_user_sid() -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    to_string = advapi32.ConvertSidToStringSidW
    to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    to_string.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    token = _open_process_token()
    try:
        buffer = _token_information(token, 1)  # TokenUser
    finally:
        _close_handle(token)
    # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is a PSID
    # pointing into this same buffer, so `buffer` must stay alive until done.
    sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
    text = wintypes.LPWSTR()
    if not to_string(sid_pointer, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return str(text.value)
    finally:
        local_free(ctypes.cast(text, ctypes.c_void_p))


def is_elevated() -> bool:
    token = _open_process_token()
    try:
        buffer = _token_information(token, 20)  # TokenElevation
    finally:
        _close_handle(token)
    (elevated,) = struct.unpack_from("<I", buffer.raw, 0)
    return elevated != 0


def _ancestors(folder: str) -> List[str]:
    """Every parent folder of `folder`, nearest first, up to the drive root."""
    result: List[str] = []
    current = ntpath.normpath(folder)
    while True:
        parent = ntpath.dirname(current)
        if parent == current or not parent:
            return result
        result.append(parent)
        current = parent


def check_store(grants_path: str, writer_path: Optional[str] = None,
                elevated_ok: bool = False) -> List[str]:
    """Rule I4/I5 on the store. Returns readable problems; empty means protected."""
    if sys.platform != "win32":
        return ["Exception grants are not supported on this platform."]
    try:
        if not elevated_ok and is_elevated():
            return ["this process is running elevated (as administrator), so grants are "
                    "not trusted"]
    except OSError as exc:
        return [f"could not read this process's elevation: {exc}"]

    folder = ntpath.dirname(grants_path)
    if not os.path.isdir(folder) or not os.path.isfile(grants_path):
        return ["Exception grants are not set up. Run: aiallow setup"]

    problems: List[str] = []
    targets: List[Tuple[str, str]] = [(folder, "folder"), (grants_path, "file")]
    if writer_path is not None:
        targets.append((writer_path, "file"))
    for path, role in targets:
        try:
            sec = read_object_security(path)
        except OSError as exc:
            problems.append(f"could not read security of {path}: {exc}")
            continue
        found = protected_object_problems(sec, require_protected_dacl=(role == "folder"),
                                          label=path)
        problems.extend(message for _code, message in found)
    for ancestor in _ancestors(folder):
        try:
            sec = read_object_security(ancestor)
        except OSError as exc:
            problems.append(f"could not read security of {ancestor}: {exc}")
            continue
        problems.extend(message for _code, message in ancestor_problems(sec, label=ancestor))
    return problems


def find_grant(settings: Any, command: str, cwd: Any, host: str, tool: str,
               now: Optional[datetime] = None) -> Lookup:
    """The hook's grant lookup. Any problem means "no grant" plus a note."""
    try:
        problems = check_store(settings.grants_path)
        if problems:
            return Lookup(None, "Exception grants ignored: " + problems[0]
                          + ". Run: aiallow check")
        with open(settings.grants_path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)   # bounded read
        grants, revokes = validate_file_bytes(data)
        moment = now or datetime.now(timezone.utc)
        active = active_grants(grants, revokes, moment)
        return Lookup(first_match(active, command, cwd, host, tool, current_user_sid()), None)
    except GrantFileInvalid as exc:
        return Lookup(None, "Exception grants ignored: grants file invalid "
                            f"({exc.error.describe()}). Fix with: aiallow edit")
    except Exception as exc:  # noqa: BLE001 -- isolates grant code; can only mean "no grant"
        return Lookup(None, f"Exception grants ignored: {type(exc).__name__}: {exc}")
