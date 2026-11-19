"""Exception grants: pure validation, active-grant logic, matching and help text.

Everything here runs on every OS. The shared fixtures in tests/fixtures/grants
are also run through the PowerShell writer (tests/test_grant_writer.py), so the
two implementations must reach the same first error for every case.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import exception_grants as eg
import pytest
from grant_fixtures import GRANT_FIXTURES, load_cases, parse_now

NOW = datetime(2026, 11, 19, 18, 0, 0, tzinfo=timezone.utc)
USER = "S-1-5-21-1-2-3-1001"


# ------------------------------------------------------------- shared fixtures

@pytest.mark.parametrize("case", load_cases("request"), ids=lambda c: c["id"])
def test_request_fixture(case: Dict[str, Any]) -> None:
    data = (GRANT_FIXTURES / case["path"]).read_bytes()
    _obj, error = eg.parse_request_bytes(data, parse_now(case["now"]))
    if case["valid"]:
        assert error is None
    else:
        assert error is not None
        assert (error.code, error.field) == (case["code"], case["field"])


@pytest.mark.parametrize("case", load_cases("file"), ids=lambda c: c["id"])
def test_file_fixture(case: Dict[str, Any]) -> None:
    data = (GRANT_FIXTURES / case["path"]).read_bytes()
    if not case["valid"]:
        with pytest.raises(eg.GrantFileInvalid) as info:
            eg.validate_file_bytes(data)
        error = info.value.error
        assert (error.code, error.field, error.line) == (case["code"], case["field"],
                                                          case["line"])
        return
    grants, revokes = eg.validate_file_bytes(data)
    active = eg.active_grants(grants, revokes, parse_now(case["now"]))
    by_user: Dict[str, List[str]] = {}
    for grant in active:
        by_user.setdefault(grant.user, []).append(grant.id)
    assert by_user == case["active"]


def test_file_over_one_megabyte_is_rejected_before_anything_else() -> None:
    data = b"x" * (eg.MAX_FILE_BYTES + 1)
    with pytest.raises(eg.GrantFileInvalid) as info:
        eg.validate_file_bytes(data)
    assert info.value.error.code == "too-large"


def test_file_of_exactly_one_megabyte_is_checked_normally() -> None:
    data = b"x" * eg.MAX_FILE_BYTES
    with pytest.raises(eg.GrantFileInvalid) as info:
        eg.validate_file_bytes(data)
    assert info.value.error.code == "no-final-newline"


def test_fixture_ids_are_unique() -> None:
    cases = json.loads((GRANT_FIXTURES / "cases.json").read_text(encoding="utf-8"))
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids))
    # Windows file names ignore case, so two paths differing only in case would
    # silently overwrite each other when the fixtures are generated there.
    paths = [case["path"].lower() for case in cases]
    assert len(paths) == len(set(paths))


# ------------------------------------------------------------- active grants

def make_grant(line: int, name: str = "a", user: str = USER, expires: Any = None,
               **overrides: Any) -> eg.Grant:
    fields: Dict[str, Any] = dict(
        id=f"g-20261119T170000Z-{line:08x}", name=name, ts=NOW, user=user,
        user_display="PC\\user", commands=("git push",), tool="Bash", where="any",
        path=None, hosts=None, expires=expires, why="", line=line,
    )
    fields.update(overrides)
    return eg.Grant(**fields)


def make_revoke(line: int, name: str = "a", user: str = USER) -> eg.Revoke:
    return eg.Revoke(id=f"r-20261119T171000Z-{line:08x}", ts=NOW, user=user, name=name,
                     line=line)


def test_revoke_only_affects_earlier_grants() -> None:
    early, late = make_grant(1), make_grant(3)
    active = eg.active_grants([early, late], [make_revoke(2)], NOW)
    assert active == [late]


def test_star_revoke_removes_all_of_one_users_earlier_grants() -> None:
    mine_a, mine_b = make_grant(1, "a"), make_grant(2, "b")
    theirs = make_grant(3, "a", user="S-1-5-21-9")
    active = eg.active_grants([mine_a, mine_b, theirs], [make_revoke(4, "*")], NOW)
    assert active == [theirs]


def test_expiry_is_exclusive() -> None:
    at_now = make_grant(1, expires=NOW)
    later = make_grant(2, expires=NOW + timedelta(seconds=1))
    assert eg.active_grants([at_now, later], [], NOW) == [later]


# ------------------------------------------------------------- matching

def test_first_match_requires_every_condition() -> None:
    grant = make_grant(1, hosts=("claude",), tool="Bash", commands=("git push", "ls"))
    active = [grant]
    assert eg.first_match(active, "ls", "C:\\x", "claude", "Bash", USER) is grant
    assert eg.first_match(active, "ls", "C:\\x", "codex", "Bash", USER) is None
    assert eg.first_match(active, "ls", "C:\\x", "claude", "PowerShell", USER) is None
    assert eg.first_match(active, "ls", "C:\\x", "claude", "Bash", "S-1-5-21-9") is None
    assert eg.first_match(active, "LS", "C:\\x", "claude", "Bash", USER) is None
    assert eg.first_match(active, "ls ", "C:\\x", "claude", "Bash", USER) is None


def test_first_match_reports_the_first_in_file_order() -> None:
    first, second = make_grant(1, "a"), make_grant(2, "b")
    assert eg.first_match([first, second], "git push", None, "claude", "Bash", USER) is first


def test_dir_grant_matches_only_its_folder_case_insensitively() -> None:
    grant = make_grant(1, where="dir", path="C:\\Src\\Repo")
    assert eg.location_matches(grant, "c:/src/repo")
    assert eg.location_matches(grant, "C:\\src\\repo\\")
    assert not eg.location_matches(grant, "C:\\src\\repo\\sub")
    assert not eg.location_matches(grant, "/c/src/repo")
    assert not eg.location_matches(grant, None)


def test_repo_grant_compares_folder_by_folder() -> None:
    grant = make_grant(1, where="repo", path="C:\\src\\repo")
    assert eg.location_matches(grant, "C:\\src\\repo")
    assert eg.location_matches(grant, "C:\\SRC\\repo\\a\\b")
    assert not eg.location_matches(grant, "C:\\src\\repo-other")
    assert not eg.location_matches(grant, "C:\\src")
    assert not eg.location_matches(grant, "D:\\src\\repo")


def test_any_grant_matches_any_folder_even_a_posix_one() -> None:
    assert eg.location_matches(make_grant(1), "/e/Source")


# ------------------------------------------------------------- paths

@pytest.mark.parametrize("path, expected", [
    ("C:\\Src\\Repo", ("c:", "src", "repo")),
    ("c:/src/repo/", ("c:", "src", "repo")),
    ("C:\\a\\.\\b\\..\\c", ("c:", "a", "c")),
    ("C:\\", ("c:",)),
    ("\\\\server\\share\\x", None),
    ("/e/Source", None),
    ("\\x", None),
    ("relative", None),
    ("", None),
    (None, None),
])
def test_canonical_path(path: Any, expected: Any) -> None:
    assert eg.canonical_path(path) == expected


# ------------------------------------------------------------- help lines

def fill(block_line: str, **changes: Any) -> Dict[str, Any]:
    request = json.loads(block_line)
    request.update(changes)
    return request


def test_help_block_becomes_valid_once_name_is_filled() -> None:
    lines = eg.help_lines("git push --force", "C:\\src\\proj", "claude", "Bash")
    assert len(lines) == 2
    request = fill(lines[1], name="push")
    assert eg.validate_request(request, NOW) is None
    assert request["hosts"] == ["claude"]
    assert request["where"] == "dir"


def test_help_block_for_a_posix_cwd_needs_the_folder_filled_in() -> None:
    lines = eg.help_lines("ls", "/e/Source", "codex", "shell")
    assert len(lines) == 3
    assert "'/e/Source'" in lines[2]
    request = fill(lines[1], name="ls")
    assert request["cwd"] == ""
    assert request["where"] == "dir"     # never widened to "any" (D4)
    error = eg.validate_request(request, NOW)
    assert error is not None and error.field == "cwd"
    assert eg.validate_request(fill(lines[1], name="ls", cwd="E:\\Source"), NOW) is None


def test_help_block_for_an_over_long_command_stays_invalid() -> None:
    lines = eg.help_lines("x" * 8001, "C:\\src", "claude", "Bash")
    error = eg.validate_request(fill(lines[1], name="long"), NOW)
    assert error is not None and error.field == "commands"


@pytest.mark.parametrize("command", ["echo \U0001F600", "a\tb", "a\r\nb", "x\u200by", "\"q\\"])
def test_help_block_decodes_to_the_exact_command_and_is_ascii(command: str) -> None:
    line = eg.help_lines(command, "C:\\src", "claude", "Bash")[1]
    assert line.isascii()
    assert json.loads(line)["commands"] == [command]


def test_help_block_cleans_the_cwd() -> None:
    line = eg.help_lines("ls", "C:/a/./b", "claude", "Bash")[1]
    assert json.loads(line)["cwd"] == "C:\\a\\b"


# ------------------------------------------------------------- store mention check

@pytest.mark.parametrize("command", [
    "type C:\\ProgramData\\cc-ai-review\\grants.jsonl",
    "cat c:/programdata/CC-AI-REVIEW/x",
    "AIALLOW add",
    "powershell -File grant-writer.ps1",
    "setup-grants.ps1 -Reset",
    "copy x grants.jsonl",
])
def test_store_mentions_are_detected(command: str) -> None:
    assert eg.mentions_protected_store(command, "C:\\ProgramData\\cc-ai-review\\grants.jsonl")


def test_unrelated_commands_are_not_store_mentions() -> None:
    assert not eg.mentions_protected_store(
        "git status", "C:\\ProgramData\\cc-ai-review\\grants.jsonl")


# ------------------------------------------------------------- misc

def test_scope_summary() -> None:
    grant = make_grant(1, where="repo", path="C:\\x",
                       expires=datetime(2026, 11, 19, 18, 32, tzinfo=timezone.utc))
    assert eg.scope_summary(grant) == (
        f"Grant {grant.id}: exact command, any folder of repo C:\\x, "
        "until 2026-11-19 18:32 UTC")
    assert eg.scope_summary(make_grant(2)).endswith("any folder, until revoked")


def test_validation_error_description() -> None:
    assert eg.ValidationError("bad-value", "commands", 3).describe() == \
        "line 3: bad-value in 'commands'"
    assert eg.ValidationError("too-large").describe() == "too-large"


@pytest.mark.parametrize("sid, valid", [
    ("S-1-5-18", True),
    ("S-1-5-21-1-2-3-1001", True),
    ("S-1-0-0", True),
    ("S-1-5", False),
    ("S-1-05-18", False),
    ("S-1-5-18\n", False),
    ("S-1-5-\u0661", False),
    ("s-1-5-18", False),
])
def test_sid_rule(sid: str, valid: bool) -> None:
    assert eg.is_valid_sid(sid) is valid
