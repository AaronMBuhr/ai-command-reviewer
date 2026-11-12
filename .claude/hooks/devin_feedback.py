"""Optional, nonblocking desktop history for Devin command-review decisions."""
from __future__ import annotations

import argparse
import contextlib
import datetime
import errno
import json
import os
import subprocess
import sys
import traceback
from collections import deque
from pathlib import Path
from typing import Any, BinaryIO, Deque, Dict, Iterator, List

from review_core import append_log_line

STATUS = {
    "allow": "APPROVED by reviewer",
    "ask": "APPROVAL NEEDED",
    "deny": "BLOCKED by reviewer",
}


def feedback_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_STATE_HOME")
    directory = Path(base) if base else Path.home() / ".local" / "state"
    return directory / "cc-ai-review" / "devin-feedback.jsonl"


def publish_feedback(command: str, cwd: str, decision: str, reason: str) -> None:
    """Record the review and ensure a viewer exists, without waiting for a click."""
    if decision not in STATUS:
        raise ValueError(f"Unknown review decision: {decision}")
    path = feedback_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
             "command": command, "cwd": cwd, "decision": decision, "reason": reason}
    append_log_line(str(path), (json.dumps(entry, ensure_ascii=True) + "\n").encode("utf-8"))
    options: Dict[str, Any] = (
        {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt"
        else {"start_new_session": True}
    )
    # Detached stdio is essential: an open hook pipe would make Devin wait for
    # the viewer to close. The child uses a file lock to keep one window open.
    with path.with_suffix(".errors.log").open("ab") as errors:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--show", str(path)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors,
                         close_fds=True, **options)


@contextlib.contextmanager
def viewer_lock(path: Path) -> Iterator[bool]:
    """A process-owned lock releases automatically if the viewer crashes."""
    with path.with_suffix(".viewer.lock").open("a+b") as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            def lock() -> None:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

            def unlock() -> None:
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            def lock() -> None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            def unlock() -> None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        try:
            lock()
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            yield False
            return
        try:
            yield True
        finally:
            unlock()


def read_updates(stream: BinaryIO) -> List[Dict[str, str]]:
    """Read complete records only; retry a concurrent partial append next time."""
    entries = []
    while True:
        position = stream.tell()
        line = stream.readline()
        if not line.endswith(b"\n"):
            stream.seek(position)
            return entries
        entry = json.loads(line.decode("utf-8"))
        if not isinstance(entry, dict) or entry.get("decision") not in STATUS:
            raise ValueError("Invalid desktop feedback record")
        entries.append(entry)


def format_entry(entry: Dict[str, str]) -> str:
    return (f"{entry['time']}   {STATUS[entry['decision']]}\n"
            f"Command: {entry['command']}\nWorking directory: {entry['cwd']}\n\n"
            f"{entry['reason']}\n\n{'-' * 72}\n\n")


def show_reviews(path: Path) -> None:
    with viewer_lock(path) as acquired:
        if not acquired:
            return
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        root = tk.Tk()
        try:
            root.title("AI Command Review - Devin")
            root.geometry("860x600")
            root.minsize(600, 360)
            frame = ttk.Frame(root, padding=14)
            frame.pack(fill="both", expand=True)
            ttk.Label(frame, text="Devin command reviews", font=("TkDefaultFont", 14, "bold")).pack(
                anchor="w")
            ttk.Label(frame, text="Approved and blocked reviews, newest first. Approval requests "
                      "have their own Allow once / Cancel dialog.", wraplength=800).pack(
                          anchor="w", pady=(6, 10))
            details = ScrolledText(frame, wrap="word", font=("Consolas", 10), state="disabled")
            details.pack(fill="both", expand=True)
            colors = {"allow": "#166534", "ask": "#92400e", "deny": "#b91c1c"}
            for decision, color in colors.items():
                details.tag_configure(decision, foreground=color)
            ttk.Button(frame, text="Close", command=root.destroy).pack(anchor="e", pady=(10, 0))
            entries: Deque[Dict[str, str]] = deque(maxlen=50)
            with path.open("rb") as stream:
                def refresh() -> None:
                    try:
                        updates = read_updates(stream)
                        if updates:
                            entries.extend(updates)
                            details.configure(state="normal")
                            details.delete("1.0", "end")
                            for entry in reversed(entries):
                                details.insert("end", format_entry(entry), entry["decision"])
                            details.configure(state="disabled")
                            details.yview_moveto(0)
                            if updates[-1]["decision"] in {"ask", "deny"}:
                                root.lift()
                    except (OSError, ValueError, KeyError) as exc:
                        details.configure(state="normal")
                        details.insert("1.0", f"Feedback could not refresh: {exc}\n", "deny")
                        details.configure(state="disabled")
                        traceback.print_exc()
                        return
                    root.after(500, refresh)

                refresh()
                root.mainloop()
        finally:
            with contextlib.suppress(tk.TclError):
                root.destroy()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show", required=True, type=Path)
    show_reviews(parser.parse_args().show)
