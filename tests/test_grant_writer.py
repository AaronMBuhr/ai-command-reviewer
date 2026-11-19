"""The PowerShell grant writer (plan Phase 5). Windows only.

The writer must reach the same verdict and first error as the Python hook on
every shared fixture. Bulk fixtures run through tests/ps/writer-harness.ps1,
which loads the writer as a library so PowerShell starts once; the real entry
points are exercised separately. Nothing here runs elevated or writes to the
real ProgramData store: write actions are only run against temp folders, where
they must refuse (plan A19).
"""
from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import exception_grants as eg
import pytest
from grant_fixtures import ACL_FIXTURES, GRANT_FIXTURES, REPO, load_cases, parse_now

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the writer is Windows-only")

WRITER = REPO / "grant-writer" / "grant-writer.ps1"
HARNESS = REPO / "tests" / "ps" / "writer-harness.ps1"
CHECKER = REPO / "tests" / "ps" / "check-no-cmdlets.ps1"
DEFAULT_USER = "S-1-5-21-0-0-0-1000"


def powershell() -> str:
    return str(Path(eg.system_directory()) / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def run_ps(script: Path, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    command = [powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(script), *args]
    return subprocess.run(command, capture_output=True, timeout=timeout)


def json_lines(proc: subprocess.CompletedProcess) -> List[Any]:
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    text = proc.stdout.decode("ascii")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def run_harness(tmp_path: Path, entries: List[str]) -> List[Any]:
    listing = tmp_path / "harness-list.txt"
    listing.write_text("\n".join(entries) + "\n", encoding="utf-8")
    results = json_lines(run_ps(HARNESS, "-Writer", str(WRITER), "-ListFile", str(listing)))
    assert len(results) == len(entries)
    return results


# ------------------------------------------------------------- shared fixtures

def test_request_and_file_fixtures_match_python(tmp_path: Path) -> None:
    requests = load_cases("request")
    files = load_cases("file")
    entries = [f"validate-request|{GRANT_FIXTURES / c['path']}|{c['now']}|{c['for_user']}"
               for c in requests]
    entries += [f"validate-file|{GRANT_FIXTURES / c['path']}|{c['now']}|" for c in files]
    results = run_harness(tmp_path, entries)

    mismatches = []
    for case, result in zip(requests, results[:len(requests)]):
        _obj, py_error = eg.parse_request_bytes((GRANT_FIXTURES / case["path"]).read_bytes(),
                                                parse_now(case["now"]))
        expected = None if py_error is None else {"code": py_error.code,
                                                  "field": py_error.field, "line": None}
        if result["valid"] != (py_error is None) or result["error"] != expected:
            mismatches.append((case["id"], expected, result["error"]))
    for case, result in zip(files, results[len(requests):]):
        if case["valid"]:
            expected_error = None
        else:
            expected_error = {"code": case["code"], "field": case["field"], "line": case["line"]}
        if result["error"] != expected_error:
            mismatches.append((case["id"], expected_error, result["error"]))
        elif case["valid"] and result["active"] != case["active"]:
            mismatches.append((case["id"], case["active"], result["active"]))
    assert mismatches == []


def test_oversized_file_is_rejected_by_the_writer(tmp_path: Path) -> None:
    big = tmp_path / "big.jsonl"
    big.write_bytes(b"x" * (eg.MAX_FILE_BYTES + 1))
    [result] = run_harness(tmp_path, [f"validate-file|{big}|2026-11-19T18:00:00Z|"])
    assert result["error"] == {"code": "too-large", "field": None, "line": None}


def test_acl_fixtures_match_python() -> None:
    [results] = json_lines(run_ps(WRITER, "-Action", "validate-acl",
                                  "-AclFile", str(ACL_FIXTURES / "cases.json")))
    cases = json.loads((ACL_FIXTURES / "cases.json").read_text(encoding="utf-8"))
    got = {r["id"]: (r["ok"], r["problem"]) for r in results}
    expected = {c["id"]: (c["ok"], c["problem"]) for c in cases}
    assert got == expected


# ------------------------------------------------------------- conversion

def make_folders(tmp_path: Path) -> Dict[str, str]:
    plain = tmp_path / "plain"
    plain.mkdir()
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "sub").mkdir()
    return {"{TMP_REPO}": str(repo), "{TMP}": str(plain)}


def expand(text: str, folders: Dict[str, str], json_escape: bool) -> str:
    for marker, path in folders.items():
        text = text.replace(marker, path.replace("\\", "\\\\") if json_escape else path)
    return text


def normalize_description(text: str, record: Dict[str, Any],
                          folders: Dict[str, str]) -> str:
    """Replace the machine-dependent parts with markers (plan section 14)."""
    for marker, path in folders.items():
        text = text.replace(path, marker)
    text = text.replace("For user: " + record["user_display"] + " (", "For user: {USER} (")
    return re.sub(r"Until: \d{4}-\d{2}-\d{2} \d{2}:\d{2} local time",
                  "Until: {LOCAL} local time", text)


def test_conversion_cases(tmp_path: Path) -> None:
    folders = make_folders(tmp_path)
    cases = load_cases("conversion")
    entries = []
    for case in cases:
        raw = (GRANT_FIXTURES / case["path"]).read_text(encoding="utf-8")
        target = tmp_path / f"{case['id']}.json"
        target.write_text(expand(raw, folders, json_escape=True), encoding="utf-8")
        entries.append(f"validate-request|{target}|{case['now']}|{case['for_user']}")
    results = run_harness(tmp_path, entries)

    for case, result in zip(cases, results):
        assert result["valid"] is True, (case["id"], result)
        if "record" not in case:
            assert result["conversion_error"] == {"code": case["code"],
                                                  "field": case["field"]}, case["id"]
            continue
        assert result["conversion_error"] is None, (case["id"], result)
        record = result["record"]
        expected = json.loads(expand(json.dumps(case["record"]), folders, json_escape=True))
        compared = {k: v for k, v in record.items() if k not in ("id", "ts", "user_display")}
        assert compared == expected, case["id"]
        assert list(record) == list(eg.GRANT_FIELDS)
        assert eg.GRANT_ID_RE.match(record["id"])
        assert record["ts"] == case["now"]
        assert isinstance(record["user_display"], str) and record["user_display"]
        assert eg.validate_record(record) is None

        if "description" in case:
            golden = (GRANT_FIXTURES / case["description"]).read_text(encoding="utf-8")
            got = normalize_description(result["description"], record, folders)
            assert got == golden, case["id"]
            check_local_time(result["description"], record)


def check_local_time(description: str, record: Dict[str, Any]) -> None:
    from datetime import datetime

    match = re.search(r"Until: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}) local time", description)
    if record["expires"] is None:
        assert match is None
        assert "Until revoked (no expiry)" in description
        return
    assert match is not None
    expires = eg.parse_stored_timestamp(record["expires"])
    assert expires is not None
    assert match.group(1) == expires.astimezone().strftime("%Y-%m-%d %H:%M")
    assert isinstance(datetime.now(), datetime)


# ------------------------------------------------------------- JSON shapes

@pytest.mark.parametrize("text", ['{"a":[]}', '{"a":["x"]}', '{"a":["x","y"]}',
                                  '{"a":[[]],"b":{"c":null,"d":true}}', '[]', '["x"]'])
def test_arrays_survive_a_round_trip(text: str, tmp_path: Path) -> None:
    source = tmp_path / "doc.json"
    source.write_text(text, encoding="utf-8")
    [result] = run_harness(tmp_path, [f"validate-roundtrip|{source}||"])
    assert result["canonical"] == text
    assert result["value"] == json.loads(text)


def test_canonical_escapes(tmp_path: Path) -> None:
    value = {"s": "q\"b\\n\nr\rt\tb\bf\f\x01  \x7fé\U0001F600"}
    source = tmp_path / "doc.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    [result] = run_harness(tmp_path, [f"validate-roundtrip|{source}||"])
    assert result["canonical"] == (
        '{"s":"q\\"b\\\\n\\nr\\rt\\tb\\bf\\f\\u0001\\u2028\\u2029\x7fé\U0001F600"}')


# ------------------------------------------------------------- diff

def diff(tmp_path: Path, old: List[str], new: List[str]) -> Dict[str, Any]:
    old_file = tmp_path / "old.txt"
    new_file = tmp_path / "new.txt"
    old_file.write_text("".join(line + "\n" for line in old), encoding="utf-8")
    new_file.write_text("".join(line + "\n" for line in new), encoding="utf-8")
    [result] = json_lines(run_ps(WRITER, "-Action", "validate-diff", "-OldFile", str(old_file),
                                 "-NewFile", str(new_file), timeout=600))
    return result


@pytest.mark.parametrize("old_count, new_count, path", [
    (5000, 10, "lcs"),
    (1000, 1000, "lcs"),       # exactly 1,000,000: still the full diff
    (1000, 1001, "fallback"),  # just over the limit
    (200000, 10, "fallback"),
])
def test_diff_branch_choice(old_count: int, new_count: int, path: str, tmp_path: Path) -> None:
    old = [f"old {i}" for i in range(old_count)]
    new = [f"new {i}" for i in range(new_count)]
    result = diff(tmp_path, old, new)
    assert result["path"] == path
    removed = [line[2:] for line in result["lines"] if line.startswith("- ")]
    added = [line[2:] for line in result["lines"] if line.startswith("+ ")]
    assert removed == old
    assert added == new


def test_diff_keeps_common_lines(tmp_path: Path) -> None:
    result = diff(tmp_path, ["a", "b", "c"], ["a", "x", "c", "d"])
    assert result == {"path": "lcs", "lines": ["  a", "- b", "+ x", "  c", "+ d"]}


# ------------------------------------------------------------- write actions refuse

def test_add_refuses_a_user_owned_store_and_changes_nothing(tmp_path: Path) -> None:
    if eg.is_elevated():
        pytest.skip("an elevated runner can create admin-owned temp files")
    store = tmp_path / "store"
    store.mkdir()
    grants = store / "grants.jsonl"
    grants.write_bytes(b"")
    proc = run_ps(WRITER, "-Action", "add", "-ForUser", eg.current_user_sid(),
                  "-GrantsPath", str(grants))
    assert proc.returncode == 30, proc.stdout
    assert grants.read_bytes() == b""
    assert sorted(p.name for p in store.iterdir()) == ["grants.jsonl"]


def test_add_waits_for_nobody_when_the_lock_is_held(tmp_path: Path) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateMutexW(None, 1, "Global\\cc-ai-review-grants")
    assert handle, ctypes.get_last_error()
    try:
        grants = tmp_path / "grants.jsonl"
        grants.write_bytes(b"")
        proc = run_ps(WRITER, "-Action", "add", "-ForUser", eg.current_user_sid(),
                      "-GrantsPath", str(grants))
        assert proc.returncode == 40, proc.stdout
        assert b"Another grant window is open" in proc.stdout
    finally:
        kernel32.CloseHandle(handle)


def test_write_actions_reject_a_bad_user_or_path(tmp_path: Path) -> None:
    proc = run_ps(WRITER, "-Action", "add", "-ForUser", "S-1-5-bad",
                  "-GrantsPath", str(tmp_path / "grants.jsonl"))
    assert proc.returncode == 20
    proc = run_ps(WRITER, "-Action", "add", "-ForUser", DEFAULT_USER,
                  "-GrantsPath", "relative.jsonl")
    assert proc.returncode == 30


def test_validate_request_entry_point() -> None:
    [result] = json_lines(run_ps(WRITER, "-Action", "validate-request", "-RequestFile",
                                 str(GRANT_FIXTURES / "requests" / "empty-command.json"),
                                 "-Now", "2026-11-19T18:00:00Z"))
    assert result["error"] == {"code": "bad-value", "field": "commands", "line": None}


# ------------------------------------------------------------- no cmdlets (A18)

def check(path: Path, library: Optional[Path] = None) -> Dict[str, Any]:
    args = ["-Path", str(path)] + (["-LibraryPath", str(library)] if library else [])
    proc = run_ps(CHECKER, *args)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    result = json.loads(proc.stdout.decode("utf-8"))
    # ConvertTo-Json writes a one-element array as a bare string; normalize.
    for key in ("parse_errors", "bad"):
        if isinstance(result[key], str):
            result[key] = [result[key]]
        result[key] = result[key] or []
    return result


def test_writer_calls_no_cmdlets() -> None:
    assert check(WRITER) == {"parse_errors": [], "bad": []}


def sample(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_checker_reports_a_real_cmdlet_call(tmp_path: Path) -> None:
    result = check(sample(tmp_path, "a.ps1", "function F { 1 }\nF\nGet-Date\n"))
    assert result["bad"] == ["Get-Date"]


def test_checker_ignores_comments_and_strings(tmp_path: Path) -> None:
    text = "# Get-Date\n$x = 'Get-Date'\n$y = \"Get-Date\"\n"
    assert check(sample(tmp_path, "b.ps1", text))["bad"] == []


def test_checker_reports_dynamic_invocation_and_imports(tmp_path: Path) -> None:
    text = "$x = { 1 }\n& $x\n. $Other -LibraryOnly\n. $SourceWriter -LibraryOnly\n"
    assert check(sample(tmp_path, "c.ps1", text))["bad"] == [
        "& $x", ". $Other -LibraryOnly", ". $SourceWriter -LibraryOnly"]


def test_checker_allows_one_library_import_for_setup(tmp_path: Path) -> None:
    library = sample(tmp_path, "lib.ps1", "function Invoke-Helper { 1 }\n")
    setup = sample(tmp_path, "setup.ps1",
                   ". $SourceWriter -LibraryOnly\nInvoke-Helper\n")
    assert check(setup, library)["bad"] == []
    twice = sample(tmp_path, "twice.ps1",
                   ". $SourceWriter -LibraryOnly\n. $SourceWriter -LibraryOnly\n")
    assert check(twice, library)["bad"] == [". $SourceWriter -LibraryOnly"]


# ------------------------------------------------------------- setup (Phase 6)

SETUP = REPO / ".claude" / "hooks" / "setup-grants.ps1"


def test_setup_calls_no_cmdlets_beyond_the_one_library_import() -> None:
    assert check(SETUP, WRITER) == {"parse_errors": [], "bad": []}


def names(script: Path) -> Dict[str, List[str]]:
    proc = run_ps(REPO / "tests" / "ps" / "list-names.ps1", "-Path", str(script))
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.decode("utf-8"))


def test_setup_and_writer_share_no_parameter_or_function_names() -> None:
    setup, writer = names(SETUP), names(WRITER)
    lower = str.lower  # PowerShell names are case-insensitive
    assert not {lower(n) for n in setup["params"]} & {lower(n) for n in writer["params"]}
    assert not {lower(n) for n in setup["functions"]} & {lower(n) for n in writer["functions"]}
    assert "Invoke-Setup" in setup["functions"]


def test_loading_the_writer_as_a_library_runs_no_action() -> None:
    proc = run_ps(REPO / "tests" / "ps" / "load-writer-library.ps1", "-SourceWriter", str(WRITER))
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.decode("utf-8"))
    assert result == {"functions": ["Invoke-Main", "Test-StoreIntegrity", "Show-Result",
                                    "Show-Confirm"], "security_class": True}


def plan(*flags: str, existing: str = "", source: str = "", program_data: str = "") -> Any:
    args = ["-PlanOnly", "-PlanNow", "2026-11-19T18:00:00Z", *flags]
    if existing:
        args += ["-PlanExisting", existing]
    if source:
        args += ["-SourceWriter", source]
    if program_data:
        args += ["-ProgramData", program_data]
    proc = run_ps(SETUP, *args)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    return json.loads(proc.stdout.decode("utf-8"))


BACKUP = "cc-ai-review.old-20261119T180000Z"


@pytest.mark.parametrize("flags, expected", [
    (["-Reset", "-PlanFolderExists", "-PlanIntegrityOk"],
     {"action": "reset", "backup_name": BACKUP}),
    (["-Reset", "-PlanFolderExists"], {"action": "reset", "backup_name": BACKUP}),
    (["-Reset"], {"action": "fresh", "backup_name": None}),
    (["-PlanFolderExists", "-PlanIntegrityOk"], {"action": "update", "backup_name": None}),
    (["-PlanFolderExists"], {"action": "refuse", "backup_name": None}),
    ([], {"action": "fresh", "backup_name": None}),
])
def test_setup_decision_table(flags: List[str], expected: Dict[str, Any]) -> None:
    assert plan(*flags) == expected


def test_setup_backup_names_avoid_existing_ones() -> None:
    existing = f"cc-ai-review|{BACKUP}|{BACKUP.upper()}-2|Microsoft"
    assert plan("-Reset", "-PlanFolderExists", existing=existing) == {
        "action": "reset", "backup_name": BACKUP + "-3"}


def test_plan_only_touches_no_lock_library_or_folder(tmp_path: Path) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateMutexW(None, 1, r"Global\cc-ai-review-grants")
    assert handle
    try:
        result = plan("-PlanFolderExists", "-PlanIntegrityOk",
                      source=str(tmp_path / "missing-writer.ps1"),
                      program_data=str(tmp_path / "missing-programdata"))
    finally:
        kernel32.CloseHandle(handle)
    assert result == {"action": "update", "backup_name": None}


# ------------------------------------------------------------- approved scope (CODE-003)

@pytest.mark.parametrize("choice", ["30m", "2h", "never"])
def test_add_writes_exactly_the_scope_the_dialog_showed(choice: str, tmp_path: Path) -> None:
    proc = run_ps(REPO / "tests" / "ps" / "add-scope-probe.ps1", "-Writer", str(WRITER),
                  "-Cwd", str(tmp_path), "-Choice", choice)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.decode("utf-8"))
    assert result["code"] == 0
    # The root is resolved once, however the expiry changes.
    assert result["root_calls"] == 1
    record = json.loads(result["written"].splitlines()[-1])
    assert eg.validate_record(record) is None
    assert record["path"] == r"C:\root-1"
    assert r"any folder of the git repo at C:\root-1" in result["shown"]
    if choice == "never":
        assert record["expires"] is None
        assert "Until revoked" in result["shown"]
    else:
        minutes = {"30m": 30, "2h": 120}[choice]
        ts = eg.parse_stored_timestamp(record["ts"])
        expires = eg.parse_stored_timestamp(record["expires"])
        assert ts is not None and expires is not None
        assert (expires - ts).total_seconds() == minutes * 60
