"""Feedback is visible without participating in Devin's approval gate."""
from __future__ import annotations

import io
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import devin_feedback as feedback
import pytest


def test_feedback_records_concurrent_reviews_without_waiting(monkeypatch: pytest.MonkeyPatch,
                                                            tmp_path: Path) -> None:
    path = tmp_path / "reviews.jsonl"
    monkeypatch.setattr(feedback, "feedback_path", lambda: path)
    launches = []

    def launch(*args: Any, **kwargs: Any) -> None:
        launches.append((args, kwargs))

    monkeypatch.setattr(subprocess, "Popen", launch)
    commands = [f"git status #{i} café 日本語" for i in range(16)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda command: feedback.publish_feedback(
            command, "C:/project space", "allow", "Read-only operation"), commands))
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert sorted(record["command"] for record in records) == sorted(commands)
    assert all(record["reason"] == "Read-only operation" for record in records)
    assert len(launches) == len(commands)
    for args, kwargs in launches:
        assert args[0][-2:] == ["--show", str(path)]
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["close_fds"]


def test_partial_record_is_retried_without_losing_unicode() -> None:
    record = {"decision": "ask", "reason": "日本語"}
    raw = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    stream = io.BytesIO(raw[:raw.index("日".encode()) + 1])
    assert feedback.read_updates(stream) == []
    assert stream.tell() == 0
    stream.seek(0, 2)
    stream.write(raw[stream.tell():])
    stream.seek(0)
    assert feedback.read_updates(stream) == [record]
    assert feedback.read_updates(stream) == []


@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
def test_full_review_is_formatted(decision: str) -> None:
    entry = {"time": "12:00", "command": "echo café\n" + "x" * 20000,
             "cwd": "C:/project", "decision": decision, "reason": "A full explanation"}
    rendered = feedback.format_entry(entry)
    assert feedback.STATUS[decision] in rendered
    assert entry["command"] in rendered
    assert entry["cwd"] in rendered
    assert entry["reason"] in rendered


def test_existing_viewer_prevents_another_window(tmp_path: Path) -> None:
    path = tmp_path / "reviews.jsonl"
    with feedback.viewer_lock(path) as acquired:
        assert acquired
        # A second viewer must exit before importing Tk or reading the log.
        proc = subprocess.run([sys.executable, str(Path(feedback.__file__)), "--show", str(path)],
                              capture_output=True, timeout=5)
        assert proc.returncode == 0, proc.stderr
    with feedback.viewer_lock(path) as acquired:
        assert acquired


def test_unknown_decision_cannot_be_displayed(monkeypatch: pytest.MonkeyPatch,
                                             tmp_path: Path) -> None:
    path = tmp_path / "reviews.jsonl"
    monkeypatch.setattr(feedback, "feedback_path", lambda: path)
    with pytest.raises(ValueError, match="Unknown review decision"):
        feedback.publish_feedback("command", "cwd", "approved-ish", "reason")
    assert not path.exists()
