"""Helpers shared by the exception-grant tests: fixture loading and record building."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parent.parent
GRANT_FIXTURES = REPO / "tests" / "fixtures" / "grants"
ACL_FIXTURES = REPO / "tests" / "fixtures" / "acl"


def load_cases(kind: str) -> List[Dict[str, Any]]:
    cases = json.loads((GRANT_FIXTURES / "cases.json").read_text(encoding="utf-8"))
    return [case for case in cases if case["kind"] == kind]


def parse_now(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def canonical_line(record: Dict[str, Any]) -> str:
    """Decision D13's canonical form, as the writer produces it.

    json.dumps with ensure_ascii=False already escapes quotes, backslashes and
    U+0000..U+001F the way D13 asks; D13 additionally escapes U+2028/U+2029.
    """
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    return text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def grant_record(*, id: str = "g-20261119T170000Z-0000abcd", name: str = "push-x",
                 user: str = "S-1-5-21-1-2-3-1001", commands: List[str],
                 tool: str = "Bash", where: str = "any", path: Any = None,
                 hosts: Any = None, expires: Any = "2099-01-01T00:00:00Z",
                 ts: str = "2026-11-19T17:00:00Z") -> Dict[str, Any]:
    return {"v": 1, "type": "grant", "id": id, "name": name, "ts": ts, "user": user,
            "user_display": "PC\\user", "commands": commands, "tool": tool,
            "where": where, "path": path, "hosts": hosts, "expires": expires, "why": ""}
