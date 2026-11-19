#!/usr/bin/env python3
"""aiallow: manage exception grants (design section 9, plan section 9).

Runs unelevated and holds no authority. It lists grants, runs the integrity
check, and launches the protected writer or the setup script through UAC. It
never passes a request's contents: the writer reads the clipboard itself.

Run it from your own terminal, not through the AI. While exceptions are
enabled, the hook denies any AI command that mentions aiallow.
"""
from __future__ import annotations

import argparse
import json
import ntpath
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import config  # noqa: E402
import exception_grants as eg  # noqa: E402

PARAMETER_NAME_RE = re.compile(r"\A-[A-Za-z]+\Z")

EXIT_MESSAGES: Dict[int, str] = {
    0: "Done.",
    10: "Cancelled in the grant window. Nothing was changed.",
    11: "The UAC prompt was declined. Nothing was changed.",
    20: "The request was invalid. Nothing was changed.",
    21: "The grants file is invalid. Fix it with: aiallow edit",
    30: "The integrity check failed. Run: aiallow check",
    40: "Another grant window is open. Nothing was changed.",
    41: "The grant lock could not be used. Nothing was changed.",
    50: "The write failed; the grants file is unchanged.",
    51: "The write reported an error, but the new content is in the grants file.",
    52: "The write failed and the outcome is unknown. Run: aiallow check, then aiallow list",
    60: "Unexpected error in the grant window.",
}


# --------------------------------------------------------------------------
# Launching elevated (the only place a process is started; tests replace it)
# --------------------------------------------------------------------------

def powershell_path() -> str:
    """System32 PowerShell 5.1, located with the API, not %SystemRoot% (A15)."""
    return ntpath.join(eg.system_directory(), "WindowsPowerShell", "v1.0", "powershell.exe")


def build_parameters(script: str, args: Sequence[str]) -> str:
    """The command line handed to powershell.exe.

    Arguments containing a double quote are refused. Parameter names such as
    -Action stay bare so PowerShell binds them; every value is quoted.
    """
    for value in [script, *args]:
        if '"' in value:
            raise ValueError(f"refusing an argument containing a double quote: {value!r}")
        # On a Windows command line, a backslash before the closing quote
        # escapes it, which would merge this value with the next argument.
        if value.endswith("\\"):
            raise ValueError(f"refusing an argument ending in a backslash: {value!r}")
    quoted = " ".join(value if PARAMETER_NAME_RE.match(value) else f'"{value}"'
                      for value in args)
    return (f'-NoProfile -ExecutionPolicy Bypass -Sta -WindowStyle Hidden '
            f'-File "{script}" {quoted}').rstrip()


def run_elevated(script: str, args: List[str]) -> int:
    """Launch System32 PowerShell elevated via ShellExecuteExW and wait for it.

    Returns the child's exit code, or 11 if the user declined the UAC prompt
    (ERROR_CANCELLED = 1223).
    """
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
        ]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    execute = shell32.ShellExecuteExW
    execute.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    execute.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS: give us the process handle
    info.lpVerb = "runas"
    info.lpFile = powershell_path()
    info.lpParameters = build_parameters(script, args)
    info.nShow = 1
    if not execute(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:  # ERROR_CANCELLED: the user said No at the UAC prompt
            return 11
        raise ctypes.WinError(error)
    try:
        kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)  # INFINITE
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(code.value)
    finally:
        kernel32.CloseHandle(info.hProcess)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def say(text: str = "") -> None:
    print(text)


def source_writer_path() -> Path:
    """The writer copy setup installs: next to this file once installed, or
    grant-writer/grant-writer.ps1 when run from a checkout."""
    installed = HERE / "grant-writer.ps1"
    if installed.is_file():
        return installed
    return HERE.parent.parent / "grant-writer" / "grant-writer.ps1"


def store_writer_path(grants_path: str) -> str:
    return ntpath.join(ntpath.dirname(grants_path), "grant-writer.ps1")


def load_settings() -> config.ExceptionSettings:
    return config.load_config().exceptions


def read_store(grants_path: str) -> Optional[tuple]:
    """Validated (grants, revokes), or None after printing why not."""
    try:
        with open(grants_path, "rb") as handle:
            data = handle.read(eg.MAX_FILE_BYTES + 1)
    except OSError as exc:
        say(f"Could not read {grants_path}: {exc}")
        return None
    try:
        return eg.validate_file_bytes(data)
    except eg.GrantFileInvalid as exc:
        say(f"The grants file is invalid ({exc.error.describe()}). Fix it with: aiallow edit")
        return None


def time_left(grant: eg.Grant, now: datetime) -> str:
    if grant.expires is None:
        return "until revoked"
    minutes = int((grant.expires - now).total_seconds() // 60)
    if minutes >= 1440:
        return f"{minutes // 1440}d {minutes % 1440 // 60}h left"
    if minutes >= 60:
        return f"{minutes // 60}h {minutes % 60}m left"
    return f"{max(minutes, 0)}m left"


def report(code: int) -> int:
    say(EXIT_MESSAGES.get(code, f"The grant window exited with code {code}."))
    return code


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_writer(action: str, settings: config.ExceptionSettings, name: Optional[str]) -> int:
    if not settings.enabled:
        say("Note: exceptions.enabled is false, so the hook ignores grants until you set it "
            "to true.")
    writer = store_writer_path(settings.grants_path)
    problems = eg.check_store(settings.grants_path, writer_path=writer)
    if problems:
        # Never fall back to setup or reset here (design 4.1): only say what to run.
        say("The grants store isn't protected, so the grant window won't open:")
        for problem in problems:
            say(f"  - {problem}")
        say("Run: aiallow check   (or aiallow setup / aiallow setup --reset)")
        return 30
    args = ["-Action", action, "-ForUser", eg.current_user_sid(),
            "-GrantsPath", settings.grants_path]
    if name is not None:
        args += ["-Name", name]
    code = report(run_elevated(writer, args))
    if action == "add" and code == 0:
        print_newest_grant(settings.grants_path)
    return code


def print_newest_grant(grants_path: str) -> None:
    store = read_store(grants_path)
    if store is None:
        return
    grants, _revokes = store
    user = eg.current_user_sid()
    mine = [grant for grant in grants if grant.user == user]
    if mine:
        say(eg.scope_summary(mine[-1]))


def cmd_setup(settings: config.ExceptionSettings, reset: bool) -> int:
    default = config._default_grants_path()
    if ntpath.normcase(settings.grants_path) != ntpath.normcase(default):
        say(f"exceptions.grants_path is set to {settings.grants_path}, not the default "
            f"{default}.")
        say("aiallow setup only provisions the default store. Set up a custom store by hand "
            "(see the README's advanced section), then verify it with: aiallow check")
        return 30
    program_data = ntpath.dirname(ntpath.dirname(default))
    args = ["-SourceWriter", str(source_writer_path()), "-ProgramData", program_data]
    if reset:
        args.append("-Reset")
    code = run_elevated(str(HERE / "setup-grants.ps1"), args)
    if code != 0:
        # The elevated step failed: its code wins. The check still runs, so the
        # user sees the store's current state.
        report(code)
        say()
        cmd_check(settings)
        return code
    # Setup only counts as done when the unelevated check also passes
    # (review CODE-004).
    check_code = cmd_check(settings)
    if check_code == 0:
        say("Setup complete.")
    else:
        say("Setup ran, but the store failed the check above.")
    return check_code


def cmd_check(settings: config.ExceptionSettings) -> int:
    problems = eg.check_store(settings.grants_path,
                              writer_path=store_writer_path(settings.grants_path))
    if problems:
        say(f"Not protected: {settings.grants_path}")
        for problem in problems:
            say(f"  - {problem}")
        return 30
    say(f"Protected: {settings.grants_path}")
    if not settings.enabled:
        say("Note: exceptions.enabled is false, so the hook ignores grants.")
    return 0


def cmd_list(settings: config.ExceptionSettings) -> int:
    store = read_store(settings.grants_path)
    if store is None:
        return 21
    grants, revokes = store
    now = datetime.now(timezone.utc)
    user = eg.current_user_sid()
    active = [g for g in eg.active_grants(grants, revokes, now) if g.user == user]
    if not active:
        say("No active grants.")
        return 0
    for grant in active:
        hosts = "all hosts" if grant.hosts is None else ", ".join(grant.hosts)
        say(f"{grant.name}  ({time_left(grant, now)}; tool {grant.tool!r}; {hosts})")
        for command in grant.commands:
            say(f"    {command!r}")   # repr() shows invisible characters
        say(f"    {eg.scope_summary(grant)}")
    return 0


def parse_since(text: str) -> timedelta:
    match = eg.DURATION_RE.match(text)
    if not match:
        raise argparse.ArgumentTypeError("use a number and m, h or d, e.g. 7d")
    count, unit = int(match.group(1)), match.group(2)
    return {"m": timedelta(minutes=count), "h": timedelta(hours=count),
            "d": timedelta(days=count)}[unit]


def grant_use_counts(log_path: Optional[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    if not log_path:
        return counts
    path = os.path.expanduser(os.path.expandvars(log_path))
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, dict) or entry.get("source") != "grant":
                    continue
                for flag in entry.get("flags") or []:
                    if isinstance(flag, str) and flag.startswith("exception-grant-id:"):
                        grant_id = flag[len("exception-grant-id:"):]
                        counts[grant_id] = counts.get(grant_id, 0) + 1
    except OSError:
        pass
    return counts


def cmd_history(settings: config.ExceptionSettings, since: Optional[timedelta]) -> int:
    store = read_store(settings.grants_path)
    if store is None:
        return 21
    grants, revokes = store
    cutoff = datetime.now(timezone.utc) - since if since else None
    counts = grant_use_counts(config.load_config().policy.log_path)
    records = sorted([*grants, *revokes], key=lambda record: record.line)
    for record in records:
        if cutoff and record.ts < cutoff:
            continue
        stamp = eg.format_stored_timestamp(record.ts)
        if isinstance(record, eg.Grant):
            used = f", used {counts.get(record.id, 0)}x" if counts else ""
            say(f"{stamp}  grant   {record.name}  ({record.user_display}{used})")
            say(f"    {eg.scope_summary(record)}")
        else:
            say(f"{stamp}  revoke  {record.name}  ({record.user})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aiallow", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("add", help="approve the request block on the clipboard (UAC prompt)")
    sub.add_parser("list", help="your active grants")
    history = sub.add_parser("history", help="grants and revokes, with use counts")
    history.add_argument("--since", type=parse_since, help="e.g. 7d, 12h, 30m")
    revoke = sub.add_parser("revoke", help="revoke a grant by name (UAC prompt)")
    target = revoke.add_mutually_exclusive_group(required=True)
    target.add_argument("name", nargs="?")
    target.add_argument("--all", action="store_true", help="revoke all of your grants")
    sub.add_parser("edit", help="repair the grants file (UAC prompt)")
    setup = sub.add_parser("setup", help="create or update the protected store (UAC prompt)")
    setup.add_argument("--reset", action="store_true",
                       help="rename the existing store as a backup and start fresh")
    sub.add_parser("check", help="check that the store is protected")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if sys.platform != "win32":
        say("Exception grants are Windows-only in this version.")
        return 30
    try:
        settings = load_settings()
    except config.ConfigError as exc:
        say(f"Config error: {exc}")
        return 30

    if args.command in ("add", "edit"):
        return cmd_writer(args.command, settings, None)
    if args.command == "revoke":
        name = "*" if args.all else args.name
        if name != "*" and not eg.NAME_RE.match(name or ""):
            say("A grant name is lowercase letters, digits and dashes.")
            return 20
        return cmd_writer("revoke", settings, name)
    if args.command == "setup":
        return cmd_setup(settings, args.reset)
    if args.command == "check":
        return cmd_check(settings)
    if args.command == "list":
        return cmd_list(settings)
    return cmd_history(settings, args.since)


if __name__ == "__main__":
    raise SystemExit(main())
