"""Exception grants: the integrity rule (I4/I5) and Windows identity helpers.

The descriptor parser and the rule checks are pure, so the shared ACL fixtures
run on every OS. The tests that read real files are Windows-only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import exception_grants as eg
import pytest
from grant_fixtures import ACL_FIXTURES

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows API")


def acl_cases() -> List[Dict[str, Any]]:
    return json.loads((ACL_FIXTURES / "cases.json").read_text(encoding="utf-8"))


def evaluate(case: Dict[str, Any]) -> List[Any]:
    sec = eg.parse_security_descriptor(bytes.fromhex(case["hex"]), case["reparse"])
    if case["role"] == "ancestor":
        return eg.ancestor_problems(sec)
    return eg.protected_object_problems(sec, require_protected_dacl=case["role"] == "folder")


@pytest.mark.parametrize("case", acl_cases(), ids=lambda c: c["id"])
def test_acl_fixture(case: Dict[str, Any]) -> None:
    problems = evaluate(case)
    assert (not problems) is case["ok"]
    first = problems[0][0] if problems else None
    assert first == case["problem"]


def test_fixtures_cover_every_problem_code() -> None:
    codes = {case["problem"] for case in acl_cases()}
    assert codes >= {"owner", "reparse", "null-dacl", "ace-type", "write-right",
                     "not-protected", "malformed"}


@pytest.mark.parametrize("length", range(0, 64, 3))
def test_any_truncation_is_malformed_and_never_raises(length: int) -> None:
    good = bytes.fromhex(next(c for c in acl_cases() if c["id"] == "file-sddl")["hex"])
    sec = eg.parse_security_descriptor(good[:length], False)
    assert sec.malformed is not None
    assert eg.protected_object_problems(sec, False)[0][0] == "malformed"


def test_garbage_bytes_never_raise() -> None:
    import random

    rng = random.Random(1234)
    for _ in range(500):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        sec = eg.parse_security_descriptor(data, False)
        problems = eg.protected_object_problems(sec, True)
        assert isinstance(problems, list)


def test_parsed_fields_of_the_setup_descriptor() -> None:
    case = next(c for c in acl_cases() if c["id"] == "setup-folder")
    sec = eg.parse_security_descriptor(bytes.fromhex(case["hex"]), False)
    assert sec.owner_sid == "S-1-5-32-544"
    assert sec.dacl_present and sec.dacl_protected
    assert [(ace.type, ace.mask, ace.sid) for ace in sec.aces] == [
        (0, 0x1F01FF, "S-1-5-32-544"),
        (0, 0x1F01FF, "S-1-5-18"),
        (0, 0x1200A9, "S-1-5-32-545"),
    ]


# ------------------------------------------------------------- Windows only

@windows_only
def test_hosts_file_is_admin_owned_and_not_writable_by_users() -> None:
    system32 = Path(eg.system_directory())
    sec = eg.read_object_security(str(system32 / "drivers" / "etc" / "hosts"))
    assert sec.owner_sid in eg.TRUSTED_SIDS
    assert eg.protected_object_problems(sec, require_protected_dacl=False) == []


@windows_only
def test_a_user_owned_temp_file_is_rejected(tmp_path: Path) -> None:
    if eg.is_elevated():
        pytest.skip("an elevated test runner may create admin-owned files")
    target = tmp_path / "grants.jsonl"
    target.write_bytes(b"")
    problems = eg.protected_object_problems(eg.read_object_security(str(target)), False)
    assert problems and problems[0][0] == "owner"


@windows_only
def test_a_junction_is_reported_as_a_reparse_point(tmp_path: Path) -> None:
    import _winapi

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    _winapi.CreateJunction(str(real), str(link))
    sec = eg.read_object_security(str(link))
    assert sec.is_reparse
    codes = [code for code, _message in eg.protected_object_problems(sec, False)]
    assert "reparse" in codes


@windows_only
def test_check_store_reports_a_missing_store(tmp_path: Path) -> None:
    if eg.is_elevated():
        pytest.skip("check_store refuses to trust an elevated process first")
    problems = eg.check_store(str(tmp_path / "missing" / "grants.jsonl"))
    assert problems == ["Exception grants are not set up. Run: aiallow setup"]


@windows_only
def test_check_store_rejects_a_user_owned_store(tmp_path: Path) -> None:
    if eg.is_elevated():
        pytest.skip("check_store refuses to trust an elevated process first")
    folder = tmp_path / "store"
    folder.mkdir()
    (folder / "grants.jsonl").write_bytes(b"")
    problems = eg.check_store(str(folder / "grants.jsonl"))
    assert problems
    assert any("owned by" in problem for problem in problems)


@windows_only
def test_current_user_sid_matches_whoami() -> None:
    sid = eg.current_user_sid()
    assert eg.is_valid_sid(sid)
    whoami = Path(eg.system_directory()) / "whoami.exe"
    output = subprocess.run([str(whoami), "/user", "/fo", "csv", "/nh"], capture_output=True,
                            text=True, check=True).stdout
    assert sid in output


@windows_only
def test_is_elevated_returns_a_bool() -> None:
    assert isinstance(eg.is_elevated(), bool)


def test_check_store_is_unsupported_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eg.sys, "platform", "linux")
    assert eg.check_store("C:\\x\\grants.jsonl") == [
        "Exception grants are not supported on this platform."]


def test_ancestors_walk_up_to_the_drive_root() -> None:
    assert eg._ancestors("C:\\ProgramData\\cc-ai-review") == ["C:\\ProgramData", "C:\\"]
    assert eg._ancestors("C:\\") == []


class _Settings:
    def __init__(self, path: str) -> None:
        self.grants_path = path


def test_find_grant_turns_store_problems_into_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eg, "check_store", lambda *a, **k: ["the folder is owned by X"])
    lookup = eg.find_grant(_Settings("C:\\x\\grants.jsonl"), "ls", "C:\\", "claude", "Bash")
    assert lookup.grant is None
    assert lookup.note == ("Exception grants ignored: the folder is owned by X. "
                           "Run: aiallow check")


def test_find_grant_reports_an_invalid_file(tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "grants.jsonl"
    path.write_bytes(b"{}\n")
    monkeypatch.setattr(eg, "check_store", lambda *a, **k: [])
    lookup = eg.find_grant(_Settings(str(path)), "ls", "C:\\", "claude", "Bash")
    assert lookup.grant is None
    assert lookup.note is not None
    assert "line 1: missing-field in 'type'" in lookup.note
    assert "aiallow edit" in lookup.note


def test_find_grant_isolates_unexpected_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> List[str]:
        raise RuntimeError("kaput")

    monkeypatch.setattr(eg, "check_store", boom)
    lookup = eg.find_grant(_Settings("C:\\x\\grants.jsonl"), "ls", "C:\\", "claude", "Bash")
    assert lookup.grant is None
    assert lookup.note == "Exception grants ignored: RuntimeError: kaput"
