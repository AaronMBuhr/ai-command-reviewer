"""Exception grants inside `review_payload` (plan Phase 4, section 6).

The store integrity check and the user SID are patched, so these run in-process.
Grant matching itself is Windows-only, so those tests pretend to be on Windows
by patching sys.platform for the duration of the test.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import config as config_module
import exception_grants
import providers
import pytest
import review_core
from grant_fixtures import canonical_line, grant_record

USER = "S-1-5-21-1-2-3-1001"


def payload(command: str, cwd: str = "C:\\work\\proj", tool: str = "Bash") -> Dict[str, Any]:
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd,
            "tool_input": {"command": command}}


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> str:
        raise AssertionError("unexpected outbound HTTP request")
    monkeypatch.setattr(providers, "post_json", explode)


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Enable grants against a temp store that the integrity check accepts."""
    if sys.platform != "win32":
        # The grants path must be a drive-letter path, which a POSIX temp
        # folder can't provide. Non-Windows behavior has its own test below.
        pytest.skip("exception grants are Windows-only")
    grants = tmp_path / "store" / "grants.jsonl"
    grants.parent.mkdir()
    grants.write_bytes(b"")
    log = tmp_path / "decisions.jsonl"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "exceptions:\n  enabled: true\n"
        f"  grants_path: '{grants}'\n"
        f"policy:\n  log_path: '{log}'\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(config_module.CONFIG_PATH_ENV, str(config_path))
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(exception_grants, "check_store", lambda *a, **k: [])
    monkeypatch.setattr(exception_grants, "current_user_sid", lambda: USER)
    return grants


def write_grants(path: Path, records: List[Dict[str, Any]]) -> None:
    path.write_bytes("".join(canonical_line(r) + "\n" for r in records).encode("utf-8"))


def last_log_entry(store: Path) -> Dict[str, Any]:
    lines = (store.parent.parent / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
    return json.loads(lines[-1])


def test_matching_grant_allows_and_skips_the_external_reviewer(
    store: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    # A configured provider would normally be called for a local "ask".
    monkeypatch.setenv("CC_AI_REVIEW__REVIEWER__PROVIDER", "claude")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    write_grants(store, [grant_record(commands=["pip install requests"])])
    # The network guard alone isn't enough: the reviewer path catches its
    # exception. A call counter is checked after review_payload returns, where
    # no production handler can swallow it (review finding CODE-001).
    calls: List[Any] = []
    monkeypatch.setattr(review_core, "_external_review_with_deadline",
                        lambda *args, **kwargs: calls.append(args))

    result = review_core.review_payload(payload("pip install requests"))
    assert calls == []
    review = result.review
    assert review.decision == "allow"
    assert review.source == "grant"
    assert "exception-grant-id:g-20261119T170000Z-0000abcd" in review.flags
    assert review.headline == "Allowed by your exception grant 'push-x'."
    entry = last_log_entry(store)
    assert entry["source"] == "grant"
    assert entry["decision"] == "allow"


def test_grant_lifts_a_local_deny(store: Path, no_network: None) -> None:
    write_grants(store, [grant_record(commands=["git reset --hard"])])
    assert review_core.review_payload(payload("git reset --hard")).review.decision == "allow"


def test_non_matching_command_gets_normal_review_plus_help(store: Path,
                                                           no_network: None) -> None:
    write_grants(store, [grant_record(commands=["git reset --hard"])])
    review = review_core.review_payload(payload("git reset --hard HEAD~1")).review
    assert review.decision == "deny"
    assert review.source != "grant"
    rendered = review_core.render_reason(review)
    block = json.loads(rendered.splitlines()[-1])
    assert block["commands"] == ["git reset --hard HEAD~1"]
    assert block["cwd"] == "C:\\work\\proj"
    assert block["tool"] == "Bash"
    assert block["hosts"] == ["claude"]


def test_tool_and_host_must_match(store: Path, no_network: None) -> None:
    write_grants(store, [grant_record(commands=["git reset --hard"], tool="Bash",
                                      hosts=["codex"])])
    review = review_core.review_payload(payload("git reset --hard")).review
    assert review.decision == "deny"
    review = review_core.review_payload(payload("git reset --hard"), host="codex").review
    assert review.decision == "allow"
    review = review_core.review_payload(payload("git reset --hard", tool="PowerShell"),
                                        host="codex").review
    assert review.decision == "deny"


def test_help_lines_survive_more_than_ten_particulars() -> None:
    review = review_core.Review(decision="deny", headline="h",
                                particulars=[f"p{i}" for i in range(15)],
                                extra_lines=["HELP-1", "HELP-2"])
    lines = review_core.render_reason(review).splitlines()
    assert lines[-2:] == ["HELP-1", "HELP-2"]
    assert sum(line.startswith(" - p") for line in lines) == 10


def test_store_access_is_denied_without_help(store: Path, no_network: None) -> None:
    review = review_core.review_payload(payload("aiallow add")).review
    assert review.decision == "deny"
    assert review.flags == ["exception-store-access"]
    assert review.extra_lines == []


def test_store_access_cannot_be_granted(store: Path, no_network: None) -> None:
    write_grants(store, [grant_record(commands=[f"type {store}"])])
    review = review_core.review_payload(payload(f"type {store}")).review
    assert review.decision == "deny"
    assert "exception-store-access" in review.flags


def test_invalid_grants_file_adds_a_note_and_grants_nothing(store: Path,
                                                            no_network: None) -> None:
    store.write_bytes(b"not json\n")
    review = review_core.review_payload(payload("git reset --hard")).review
    assert review.decision == "deny"
    assert review.extra_lines[0].startswith("Exception grants ignored: grants file invalid")
    assert review.extra_lines[1].startswith("If this command is needed")


def test_allowed_commands_get_no_help(store: Path, no_network: None) -> None:
    review = review_core.review_payload(payload("git status")).review
    assert review.decision == "allow"
    assert review.extra_lines == []


def test_missing_command_gets_no_help(store: Path, no_network: None) -> None:
    review = review_core.review_payload(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}).review
    assert review.decision == "deny"
    assert review.extra_lines == []


def test_disabled_exceptions_change_nothing(no_network: None,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("grants must not be read while disabled")

    monkeypatch.setattr(exception_grants, "find_grant", explode)
    review = review_core.review_payload(payload("git reset --hard")).review
    assert review.extra_lines == []
    review = review_core.review_payload(payload("aiallow add")).review
    assert "exception-store-access" not in review.flags


def test_enabled_off_windows_only_adds_a_note(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                              no_network: None) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("exceptions:\n  enabled: true\n", encoding="utf-8")
    monkeypatch.setenv(config_module.CONFIG_PATH_ENV, str(config_path))
    monkeypatch.setattr(sys, "platform", "linux")
    review = review_core.review_payload(payload("git reset --hard")).review
    assert review.decision == "deny"
    assert review.extra_lines == ["Exception grants are not supported on this platform."]
    assert review_core.review_payload(payload("git status")).review.extra_lines == []


def test_invalid_exceptions_config_fails_closed(tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("exceptions: false\n", encoding="utf-8")
    monkeypatch.setenv(config_module.CONFIG_PATH_ENV, str(config_path))
    with pytest.raises(review_core.ConfigError):
        review_core.review_payload(payload("git status"))
