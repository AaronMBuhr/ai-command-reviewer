"""The aiallow CLI (plan Phase 7). Process launching, the store check and the
user SID are replaced, so nothing here elevates or touches the real store."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import aiallow
import config as config_module
import exception_grants as eg
import pytest
from grant_fixtures import canonical_line, grant_record

USER = "S-1-5-21-1-2-3-1001"


class Recorder:
    def __init__(self, code: int = 0) -> None:
        self.calls: List[Tuple[str, List[str]]] = []
        self.code = code

    def __call__(self, script: str, args: List[str]) -> int:
        self.calls.append((script, list(args)))
        return self.code


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    grants = tmp_path / "store" / "grants.jsonl"
    grants.parent.mkdir()
    grants.write_bytes(b"")
    log = tmp_path / "decisions.jsonl"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"exceptions:\n  enabled: true\n  grants_path: '{grants}'\n"
                   f"policy:\n  log_path: '{log}'\n", encoding="utf-8")
    monkeypatch.setenv(config_module.CONFIG_PATH_ENV, str(cfg))
    monkeypatch.setattr(sys, "platform", "win32")
    recorder = Recorder()
    monkeypatch.setattr(aiallow, "run_elevated", recorder)
    checks: List[Tuple[str, Any]] = []

    def fake_check(path: str, writer_path: Any = None, elevated_ok: bool = False) -> List[str]:
        checks.append((path, writer_path))
        return list(state["problems"])

    state: Dict[str, Any] = {"problems": [], "grants": grants, "log": log,
                             "recorder": recorder, "checks": checks, "cfg": cfg}
    monkeypatch.setattr(eg, "check_store", fake_check)
    monkeypatch.setattr(eg, "current_user_sid", lambda: USER)
    return state


@pytest.fixture(autouse=True)
def windows_paths_only() -> None:
    if sys.platform != "win32":
        pytest.skip("the grants path must be a drive-letter path")


def write(path: Path, records: List[Dict[str, Any]]) -> None:
    path.write_bytes("".join(canonical_line(r) + "\n" for r in records).encode("utf-8"))


def test_add_launches_the_store_writer_with_the_right_arguments(env: Dict[str, Any]) -> None:
    assert aiallow.main(["add"]) == 0
    [(script, args)] = env["recorder"].calls
    grants = str(env["grants"])
    assert script == str(env["grants"].parent / "grant-writer.ps1")
    assert args == ["-Action", "add", "-ForUser", USER, "-GrantsPath", grants]
    assert env["checks"] == [(grants, str(env["grants"].parent / "grant-writer.ps1"))]


def test_revoke_and_edit_arguments(env: Dict[str, Any]) -> None:
    assert aiallow.main(["revoke", "push-x"]) == 0
    assert aiallow.main(["revoke", "--all"]) == 0
    assert aiallow.main(["edit"]) == 0
    calls = [args for _script, args in env["recorder"].calls]
    assert calls[0][-2:] == ["-Name", "push-x"]
    assert calls[1][-2:] == ["-Name", "*"]
    assert calls[2][:2] == ["-Action", "edit"] and "-Name" not in calls[2]


def test_revoke_rejects_a_bad_name(env: Dict[str, Any]) -> None:
    assert aiallow.main(["revoke", "Bad Name"]) == 20
    assert env["recorder"].calls == []


@pytest.mark.parametrize("command", [["add"], ["edit"], ["revoke", "x"]])
def test_failed_pre_uac_check_stops_without_falling_back(
    command: List[str], env: Dict[str, Any], capsys: pytest.CaptureFixture
) -> None:
    env["problems"] = ["the writer is owned by S-1-5-21-9"]
    assert aiallow.main(command) == 30
    assert env["recorder"].calls == []        # neither the writer nor setup
    out = capsys.readouterr().out
    assert "owned by S-1-5-21-9" in out


def test_setup_refuses_a_custom_store(env: Dict[str, Any]) -> None:
    assert aiallow.main(["setup"]) == 30
    assert env["recorder"].calls == []


def test_setup_skips_the_pre_uac_check_and_launches_setup(
    env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    env["cfg"].write_text("exceptions:\n  enabled: true\n", encoding="utf-8")
    env["problems"] = ["Exception grants are not set up. Run: aiallow setup"]
    # The stubbed check keeps reporting "not set up", so the final check fails
    # (CODE-004). What matters here is that setup still launched.
    assert aiallow.main(["setup", "--reset"]) == 30
    [(script, args)] = env["recorder"].calls
    assert script.endswith("setup-grants.ps1")
    assert args[0] == "-SourceWriter" and args[1].endswith("grant-writer.ps1")
    default = config_module._default_grants_path()
    assert args[2:] == ["-ProgramData", str(Path(default).parent.parent), "-Reset"]
    # The only check is the unelevated one afterwards.
    assert len(env["checks"]) == 1


@pytest.mark.parametrize("code", sorted(aiallow.EXIT_MESSAGES))
def test_exit_codes_map_to_messages(code: int, env: Dict[str, Any],
                                    capsys: pytest.CaptureFixture) -> None:
    env["recorder"].code = code
    assert aiallow.main(["edit"]) == code
    assert aiallow.EXIT_MESSAGES[code] in capsys.readouterr().out


def test_add_prints_the_new_grant(env: Dict[str, Any], capsys: pytest.CaptureFixture) -> None:
    write(env["grants"], [grant_record(commands=["ls"])])
    assert aiallow.main(["add"]) == 0
    assert "Grant g-20261119T170000Z-0000abcd: exact command, any folder" in \
        capsys.readouterr().out


def test_check_output(env: Dict[str, Any], capsys: pytest.CaptureFixture) -> None:
    assert aiallow.main(["check"]) == 0
    assert "Protected:" in capsys.readouterr().out
    env["problems"] = ["bad owner"]
    assert aiallow.main(["check"]) == 30
    assert "  - bad owner" in capsys.readouterr().out


def test_list_shows_only_my_active_grants(env: Dict[str, Any],
                                         capsys: pytest.CaptureFixture) -> None:
    write(env["grants"], [
        grant_record(id="g-20261119T170000Z-00000001", name="mine", commands=["a\tb"]),
        grant_record(id="g-20261119T170000Z-00000002", name="theirs", commands=["x"],
                     user="S-1-5-21-9"),
        grant_record(id="g-20261119T170000Z-00000003", name="expired-one", commands=["y"],
                     expires="2020-01-01T00:00:00Z"),
    ])
    assert aiallow.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "mine" in out and "'a\\tb'" in out
    assert "theirs" not in out and "expired-one" not in out


def test_list_reports_an_invalid_file(env: Dict[str, Any], capsys: pytest.CaptureFixture) -> None:
    env["grants"].write_bytes(b"{}\n")
    assert aiallow.main(["list"]) == 21
    assert "aiallow edit" in capsys.readouterr().out


def test_history_with_use_counts(env: Dict[str, Any], capsys: pytest.CaptureFixture) -> None:
    write(env["grants"], [grant_record(commands=["ls"], ts="2020-01-01T00:00:00Z"),
                          {"v": 1, "type": "revoke", "id": "r-20261119T171000Z-0000abcd",
                           "ts": "2020-01-01T00:10:00Z", "user": USER, "name": "push-x"}])
    entry = {"source": "grant", "flags": ["exception-grant",
                                          "exception-grant-id:g-20261119T170000Z-0000abcd"]}
    env["log"].write_text(json.dumps(entry) + "\n" + json.dumps(entry) + "\nnot json\n",
                          encoding="utf-8")
    assert aiallow.main(["history"]) == 0
    out = capsys.readouterr().out
    assert "grant   push-x" in out and "used 2x" in out
    assert "revoke  push-x" in out
    assert aiallow.main(["history", "--since", "1m"]) == 0
    assert "push-x" not in capsys.readouterr().out


def test_disabled_exceptions_warn_but_continue(env: Dict[str, Any],
                                               capsys: pytest.CaptureFixture) -> None:
    env["cfg"].write_text(f"exceptions:\n  grants_path: '{env['grants']}'\n", encoding="utf-8")
    assert aiallow.main(["add"]) == 0
    assert "exceptions.enabled is false" in capsys.readouterr().out
    assert len(env["recorder"].calls) == 1


def test_parameters_quote_values_and_refuse_dangerous_ones() -> None:
    line = aiallow.build_parameters(r"C:\p\w.ps1", ["-Action", "add", "-GrantsPath", r"C:\a b\g"])
    assert line == ('-NoProfile -ExecutionPolicy Bypass -Sta -WindowStyle Hidden '
                    '-File "C:\\p\\w.ps1" -Action "add" -GrantsPath "C:\\a b\\g"')
    with pytest.raises(ValueError, match="double quote"):
        aiallow.build_parameters("s.ps1", ["-Name", 'a"b'])
    with pytest.raises(ValueError, match="backslash"):
        aiallow.build_parameters("s.ps1", ["-GrantsPath", "C:\\x\\"])


def test_unsupported_platform(monkeypatch: pytest.MonkeyPatch,
                              capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert aiallow.main(["list"]) == 30
    assert "Windows-only" in capsys.readouterr().out


@pytest.mark.parametrize("child, problems, expected, message", [
    (0, [], 0, "Setup complete."),
    (0, ["post-setup integrity failure"], 30, "failed the check above"),
    (40, [], 40, aiallow.EXIT_MESSAGES[40]),
    (11, ["not set up"], 11, aiallow.EXIT_MESSAGES[11]),
])
def test_setup_result_includes_the_final_check(
    child: int, problems: List[str], expected: int, message: str,
    env: Dict[str, Any], capsys: pytest.CaptureFixture
) -> None:
    env["cfg"].write_text("exceptions:\n  enabled: true\n", encoding="utf-8")
    env["recorder"].code = child
    env["problems"] = problems
    assert aiallow.main(["setup"]) == expected
    out = capsys.readouterr().out
    assert message in out
    if expected != 0:
        assert "Setup complete." not in out
