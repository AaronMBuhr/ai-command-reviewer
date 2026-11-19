#!/usr/bin/env python3
"""Configuration loading for the command safety reviewer.

Settings come from three layers. Later layers win:

1. Built-in defaults (:data:`DEFAULTS`)
2. A YAML config file (see :func:`find_config_path`)
3. Environment variables

The YAML file is optional. If none is found the reviewer runs on defaults plus
environment variables, which keeps the zero-install path working.

Security note -- config discovery deliberately excludes the current working
directory and ``CLAUDE_PROJECT_DIR``. Those are attacker-controlled when an agent
is pointed at a cloned repository, and this file can select the reviewer endpoint
and the reviewer subprocess. Config is read only from locations the *user* owns:
an explicit path, the user config directory, or the hook's own install directory.
The same reasoning restricts ``.env`` loading to API keys (see
:func:`load_dotenv_files`).
"""
from __future__ import annotations

import copy
import ntpath
import os
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

APP_DIR_NAME = "cc-ai-review"
CONFIG_BASENAMES = ("config.yaml", "config.yml")

#: Environment variable holding an explicit config file path.
CONFIG_PATH_ENV = "CC_AI_REVIEW_CONFIG"

#: Prefix for structured overrides: ``CC_AI_REVIEW__PROVIDERS__GEMINI__MODEL``.
#: A doubled underscore separates path segments so that key names containing a
#: single underscore (``max_tokens``) stay unambiguous.
ENV_PREFIX = "CC_AI_REVIEW__"
ENV_PATH_SEPARATOR = "__"

DEFAULTS: Dict[str, Any] = {
    "reviewer": {
        # Explicit provider choice, or "auto" to pick the first provider in
        # PROVIDER_AUTO_ORDER that has a usable API key.
        "provider": "auto",
        # Both take precedence over `provider` when set. See README.
        "url": None,
        "command": None,
    },
    "providers": {
        # Per-provider settings are intentionally free-form: each provider
        # accepts the keys its own API understands. Only `api_key_env` and
        # `base_url` are interpreted here; the rest is passed to the provider
        # adapter in providers.py.
        "claude": {"api_key_env": "ANTHROPIC_API_KEY"},
        "chatgpt": {"api_key_env": "OPENAI_API_KEY"},
        "gemini": {"api_key_env": "GEMINI_API_KEY"},
    },
    "policy": {
        "fail_mode": "ask",
        "timeout_seconds": 20,
        "allow_readonly": True,
        "allow_external_override": False,
        "skip_external_when_local_allows": False,
        # "auto" resolves per host: deny on Codex, where an `ask` on a
        # PermissionRequest is advisory and would not actually gate the delete;
        # ask on Claude Code, which enforces `ask` with a real prompt.
        "delete_decision": "auto",
        "log_path": None,
    },
    # Exception grants (see exception-grants-design.md). Off by default; while
    # off, the hook never reads grants and adds nothing to reasons.
    "exceptions": {
        "enabled": False,
        # None means the default protected store under ProgramData.
        "grants_path": None,
    },
}

#: Fallback grants location, used when the ProgramData known folder can't be
#: looked up (and on non-Windows platforms, where grants are unsupported).
DEFAULT_GRANTS_PATH = r"C:\ProgramData\cc-ai-review\grants.jsonl"

#: A drive-letter absolute Windows path, e.g. ``C:\...`` or ``C:/...``. The
#: same rule as in exception_grants (decision D3): no UNC, no rooted-without-drive.
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")

#: Order used when `reviewer.provider` is "auto".
PROVIDER_AUTO_ORDER: Tuple[str, ...] = ("claude", "chatgpt", "gemini")

#: Friendly aliases so users can write either the product name or the vendor.
PROVIDER_ALIASES: Dict[str, str] = {
    "anthropic": "claude",
    "openai": "chatgpt",
    "gpt": "chatgpt",
    "google": "gemini",
}

#: Legacy flat environment variables, mapped onto config paths. These predate the
#: config file and stay supported so existing installs keep working.
LEGACY_ENV_MAP: Dict[str, Tuple[str, ...]] = {
    "ANTHROPIC_API_KEY": ("providers", "claude", "api_key"),
    "OPENAI_API_KEY": ("providers", "chatgpt", "api_key"),
    "GEMINI_API_KEY": ("providers", "gemini", "api_key"),
    "GOOGLE_API_KEY": ("providers", "gemini", "api_key"),
    "CC_AI_REVIEW_ANTHROPIC_MODEL": ("providers", "claude", "model"),
    "CC_AI_REVIEW_OPENAI_MODEL": ("providers", "chatgpt", "model"),
    "CC_AI_REVIEW_GEMINI_MODEL": ("providers", "gemini", "model"),
    "CC_AI_REVIEW_PROVIDER": ("reviewer", "provider"),
    "CC_AI_REVIEW_URL": ("reviewer", "url"),
    "CC_AI_REVIEW_COMMAND": ("reviewer", "command"),
    "CC_AI_REVIEW_TIMEOUT_SECONDS": ("policy", "timeout_seconds"),
    "CC_AI_REVIEW_FAIL_MODE": ("policy", "fail_mode"),
    "CC_AI_REVIEW_ALLOW_EXTERNAL_OVERRIDE": ("policy", "allow_external_override"),
    "CC_AI_REVIEW_ALLOW_READONLY": ("policy", "allow_readonly"),
    "CC_AI_REVIEW_LOG": ("policy", "log_path"),
}


class ConfigError(Exception):
    """Raised when configuration is present but unusable.

    The caller must fail closed on this: a config file the user wrote but that
    cannot be honoured must never silently degrade to permissive defaults.
    """


# --------------------------------------------------------------------------
# .env loading
# --------------------------------------------------------------------------

#: `.env` files are searched in the working directory, which an agent may have
#: pointed at an untrusted repository. A hostile `.env` that could set
#: `reviewer.command` would be arbitrary code execution inside the very hook
#: meant to prevent it, and one that could set a `base_url` would hand the
#: attacker every reviewed command plus control of the verdict.
#:
#: So `.env` is restricted to API keys by allowlist. Everything else must come
#: from the real environment or the config file. Allowlist rather than denylist:
#: a new setting is refused by default instead of being silently trusted.
def _is_dotenv_allowed_key(name: str) -> bool:
    upper = name.upper()
    if upper.endswith("_API_KEY"):
        return True
    # Structured form: CC_AI_REVIEW__PROVIDERS__<NAME>__API_KEY
    return upper.startswith(ENV_PREFIX) and upper.endswith("__API_KEY")


def _parse_dotenv_line(raw_line: str) -> Optional[Tuple[str, str]]:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export "):].strip()
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return (key, value) if key else None


def dotenv_candidates() -> List[Path]:
    here = Path(__file__).resolve().parent
    project_root = here.parent.parent  # .claude/hooks -> repo root
    raw = [
        os.environ.get("CLAUDE_PROJECT_DIR", ""),
        os.environ.get("CODEX_PROJECT_DIR", ""),
        str(project_root),
        os.getcwd(),
    ]
    return [Path(d) / ".env" for d in raw if d]


def load_dotenv_files() -> List[str]:
    """Load API keys from `.env` into ``os.environ`` without overriding it.

    Returns the names of variables that were refused because they fall outside
    the API-key allowlist, so the caller can surface them. A silent refusal
    would look like a broken config; a visible one is also how a user notices
    that a repository shipped a hostile `.env`.

    Best-effort and never raises: a malformed `.env` must not break the hook.
    """
    refused: List[str] = []
    seen: set = set()
    for path in dotenv_candidates():
        try:
            if not path.is_file():
                continue
            resolved = os.path.normcase(str(path.resolve()))
            if resolved in seen:
                continue
            seen.add(resolved)
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                parsed = _parse_dotenv_line(raw_line)
                if parsed is None:
                    continue
                key, value = parsed
                if not _is_dotenv_allowed_key(key):
                    if key not in refused:
                        refused.append(key)
                    continue
                os.environ.setdefault(key, value)
        except OSError:
            continue
        except Exception:  # pragma: no cover - defensive; .env must never break the hook
            continue
    return refused


# --------------------------------------------------------------------------
# YAML loading
# --------------------------------------------------------------------------

def user_config_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_DIR_NAME
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / APP_DIR_NAME


def config_search_paths() -> List[Path]:
    """Locations searched for a config file, highest priority first.

    Deliberately excludes the working directory and ``CLAUDE_PROJECT_DIR``; see
    the module docstring.
    """
    paths: List[Path] = []
    explicit = os.environ.get(CONFIG_PATH_ENV, "").strip()
    if explicit:
        paths.append(Path(os.path.expanduser(os.path.expandvars(explicit))))
    for directory in (user_config_dir(), Path(__file__).resolve().parent):
        paths.extend(directory / name for name in CONFIG_BASENAMES)
    return paths


def find_config_path() -> Optional[Path]:
    for path in config_search_paths():
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Parse a YAML config file, failing closed on any problem.

    PyYAML is an optional dependency. If the user wrote a config file we must not
    proceed as though it did not exist -- that would silently discard a stricter
    policy than the defaults. So a missing parser is an error, not a fallback.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ConfigError(
            f"Config file {path} exists but PyYAML is not installed for "
            f"{sys.executable}. Install it with 'pip install pyyaml', or remove "
            f"the config file to run on environment variables alone."
        ) from exc

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Config file {path} is not valid YAML: {exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(
            f"Config file {path} must contain a mapping at the top level, "
            f"got {type(data).__name__}."
        )
    return data


# --------------------------------------------------------------------------
# Merging and environment overrides
# --------------------------------------------------------------------------

def deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``overlay`` onto ``base``, returning a new dict."""
    merged: Dict[str, Any] = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, Mapping):
            merged[key] = deep_merge(existing, value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


_TRUE_WORDS = {"true", "yes", "on", "1"}
_FALSE_WORDS = {"false", "no", "off", "0"}


def coerce_bool(value: Any, field: str, section: str = "policy") -> bool:
    """Interpret a config value as a boolean, strictly.

    Plain ``bool(value)`` is wrong here: YAML quotes are easy to add by accident,
    and ``bool("false")`` is True. In a policy file that silently inverts the
    setting -- ``allow_readonly: "false"`` would turn the allow-list back ON.
    So strings are matched against explicit word lists and anything unrecognised
    is an error rather than a guess.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE_WORDS:
            return True
        if text in _FALSE_WORDS:
            return False
    raise ConfigError(
        f"{section}.{field} must be a boolean (true/false), got {value!r}. "
        f"If you quoted it in YAML, remove the quotes."
    )


def coerce_scalar(text: str) -> Any:
    """Interpret an environment string as bool, int, float, None, or str.

    Environment variables are always strings, but config values are typed. This
    keeps `CC_AI_REVIEW__POLICY__TIMEOUT_SECONDS=30` an int without requiring
    PyYAML, which may legitimately be absent.
    """
    stripped = text.strip()
    lowered = stripped.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "none", ""}:
        return None
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    return stripped


def _set_path(data: Dict[str, Any], path: Tuple[str, ...], value: Any) -> None:
    cursor = data
    for segment in path[:-1]:
        nxt = cursor.get(segment)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[segment] = nxt
        cursor = nxt
    cursor[path[-1]] = value


def env_overrides(environ: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Build the override layer from environment variables.

    Structured overrides (``CC_AI_REVIEW__SECTION__KEY``) are applied after the
    legacy flat names, so the structured form wins if both are set.
    """
    env = os.environ if environ is None else environ
    overrides: Dict[str, Any] = {}

    for name, path in LEGACY_ENV_MAP.items():
        raw = env.get(name)
        if raw is not None and raw.strip() != "":
            _set_path(overrides, path, coerce_scalar(raw))

    for name, raw in env.items():
        if not name.startswith(ENV_PREFIX) or name == CONFIG_PATH_ENV:
            continue
        suffix = name[len(ENV_PREFIX):]
        segments = [s.lower() for s in suffix.split(ENV_PATH_SEPARATOR) if s]
        if not segments:
            continue
        _set_path(overrides, tuple(segments), coerce_scalar(raw))

    return overrides


# --------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------

#: Hosts whose "ask" is advisory rather than an enforced prompt.
ADVISORY_ASK_HOSTS = frozenset({"codex"})

#: Ceiling on `policy.timeout_seconds`.
#:
#: Host agents impose their own hook timeout (60s by default in both Claude Code
#: and the shipped Codex examples) and treat an overrunning hook as *skipped* --
#: the command then runs with no review and nothing says so. A reviewer allowed
#: to outlast that window would convert a slow provider into a silent pass, so
#: the value is clamped here and the ceiling is documented in the README.
MAX_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class Policy:
    fail_mode: str = "ask"
    timeout_seconds: int = 20
    allow_readonly: bool = True
    allow_external_override: bool = False
    skip_external_when_local_allows: bool = False
    delete_decision: str = "ask"
    log_path: Optional[str] = None


@dataclass(frozen=True)
class ExceptionSettings:
    enabled: bool
    #: Always a normalized, drive-letter absolute Windows path.
    grants_path: str


def _default_grants_path() -> str:
    """The grants file under the ProgramData known folder.

    Uses ``SHGetKnownFolderPath`` rather than ``%ProgramData%``: environment
    variables are user-controlled, the known-folder API is not. Any failure, and
    every non-Windows platform, falls back to :data:`DEFAULT_GRANTS_PATH`.
    """
    if sys.platform != "win32":
        return DEFAULT_GRANTS_PATH
    try:
        program_data = _known_folder_program_data()
    except (OSError, AttributeError, ValueError):
        return DEFAULT_GRANTS_PATH
    if not program_data or not _DRIVE_PATH_RE.match(program_data):
        return DEFAULT_GRANTS_PATH
    return ntpath.join(program_data, APP_DIR_NAME, "grants.jsonl")


def _known_folder_program_data() -> str:
    """Look up FOLDERID_ProgramData through shell32. Windows only."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    # FOLDERID_ProgramData = {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
    folder_id = GUID(
        0x62AB5D82, 0xFDC1, 0x4DC3,
        (ctypes.c_ubyte * 8)(0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97),
    )
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    get_path = shell32.SHGetKnownFolderPath
    get_path.argtypes = [
        ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    get_path.restype = ctypes.c_long  # HRESULT
    free = ole32.CoTaskMemFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = None

    buffer = ctypes.c_wchar_p()
    result = get_path(ctypes.byref(folder_id), 0, None, ctypes.byref(buffer))
    try:
        if result != 0:
            raise OSError(f"SHGetKnownFolderPath failed with HRESULT {result:#x}")
        return buffer.value or ""
    finally:
        # The shell allocates the string even on some failures; always free it.
        free(buffer)


@dataclass(frozen=True)
class Config:
    data: Dict[str, Any] = field(default_factory=dict)
    source_path: Optional[Path] = None
    refused_dotenv_keys: List[str] = field(default_factory=list)

    def policy_for_host(self, host: str) -> Policy:
        """Resolve policy for a specific host agent.

        Only `delete_decision: auto` is host-dependent; an explicit `ask` or
        `deny` in the config is honoured on every host.
        """
        base = self.policy
        raw = str((self.data.get("policy") or {}).get("delete_decision", "auto"))
        choice = raw.strip().lower()
        if choice not in {"auto", "ask", "deny"}:
            choice = "auto"
        if choice == "auto":
            choice = "deny" if host.strip().lower() in ADVISORY_ASK_HOSTS else "ask"
        return replace(base, delete_decision=choice)

    @property
    def policy(self) -> Policy:
        raw = self.data.get("policy") or {}
        fail_mode = str(raw.get("fail_mode", "ask")).strip().lower()
        if fail_mode not in {"ask", "deny"}:
            fail_mode = "ask"
        timeout = raw.get("timeout_seconds", 20)
        try:
            timeout = max(1, min(int(timeout), MAX_TIMEOUT_SECONDS))
        except (TypeError, ValueError):
            timeout = 20
        log_path = raw.get("log_path")
        return Policy(
            fail_mode=fail_mode,
            timeout_seconds=timeout,
            allow_readonly=coerce_bool(raw.get("allow_readonly", True), "allow_readonly"),
            allow_external_override=coerce_bool(
                raw.get("allow_external_override", False), "allow_external_override"),
            skip_external_when_local_allows=coerce_bool(
                raw.get("skip_external_when_local_allows", False),
                "skip_external_when_local_allows"),
            # Host-independent default; policy_for_host() resolves "auto".
            delete_decision="ask",
            log_path=str(log_path) if log_path else None,
        )

    @property
    def exceptions(self) -> ExceptionSettings:
        raw = self.data.get("exceptions")
        # Only "absent" and null mean defaults. `false`, 0, "", [] and other
        # scalars are mistakes and must fail closed. Don't write `... or {}`
        # here: that would quietly turn `exceptions: false` into the defaults.
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ConfigError(f"exceptions must be a mapping, got {raw!r}.")

        enabled = coerce_bool(raw.get("enabled", False), "enabled", section="exceptions")

        path_value = raw.get("grants_path")
        if path_value is None:
            path = _default_grants_path()
        elif isinstance(path_value, str) and path_value.strip():
            path = os.path.expandvars(os.path.expanduser(path_value.strip()))
        else:
            raise ConfigError(
                f"exceptions.grants_path must be a path or null, got {path_value!r}. "
                "If you set it via an environment variable, 'off'/'false' are read "
                "as booleans."
            )
        # A drive letter is required, not just "absolute": a rooted path without
        # a drive, a UNC path, or an unexpanded %VARIABLE% is not allowed.
        if not _DRIVE_PATH_RE.match(path):
            raise ConfigError(
                "exceptions.grants_path must start with a drive letter, "
                f"e.g. C:\\..., got {path!r}."
            )
        return ExceptionSettings(enabled=enabled, grants_path=ntpath.normpath(path))

    def _reviewer_setting(self, key: str) -> Optional[str]:
        value = (self.data.get("reviewer") or {}).get(key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @property
    def reviewer_url(self) -> Optional[str]:
        return self._reviewer_setting("url")

    @property
    def reviewer_command(self) -> Optional[str]:
        return self._reviewer_setting("command")

    def provider_settings(self, name: str) -> Dict[str, Any]:
        providers = self.data.get("providers") or {}
        raw = providers.get(name) or {}
        return dict(raw) if isinstance(raw, dict) else {}

    def resolve_api_key(self, name: str) -> Optional[str]:
        """Return the API key for a provider.

        A literal ``api_key`` in the config wins; otherwise the environment
        variable named by ``api_key_env`` is read. Naming the variable is the
        documented path so keys need not be written to disk.
        """
        settings = self.provider_settings(name)
        literal = settings.get("api_key")
        if literal and str(literal).strip():
            return str(literal).strip()
        default_env = (DEFAULTS["providers"].get(name) or {}).get("api_key_env")
        env_name = str(settings.get("api_key_env") or default_env or "").strip()
        if not env_name:
            return None
        value = os.environ.get(env_name, "").strip()
        return value or None

    def requested_provider(self) -> Optional[str]:
        """The provider the user asked for, before any API-key check.

        `selected_provider()` returns None both when review is deliberately off
        and when a named provider cannot run for want of a key. Those must not be
        treated alike: the first is a supported mode, the second is a
        misconfiguration that would otherwise downgrade every review to local
        heuristics with nothing anywhere saying so.

        Returns None for `none` and for an unset value; returns "auto" as-is, so
        the caller can keep treating the zero-config path as local-only.
        """
        raw = (self.data.get("reviewer") or {}).get("provider")
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None
        requested = str(raw).strip().lower()
        requested = PROVIDER_ALIASES.get(requested, requested)
        return None if requested == "none" else requested

    def selected_provider(self) -> Optional[str]:
        """Resolve which provider to use, or None when no LLM should be called.

        A null/empty value means "no provider", not "fall back to auto".
        `provider: null` in YAML and `CC_AI_REVIEW__REVIEWER__PROVIDER=none` in
        the environment both arrive here as None (env values are coerced, and
        "none" coerces to null), and both plainly mean disabled. Treating that
        as "auto" would silently call a provider the user asked to turn off.
        """
        raw = (self.data.get("reviewer") or {}).get("provider")
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None

        requested = str(raw).strip().lower()
        requested = PROVIDER_ALIASES.get(requested, requested)

        if requested != "auto":
            if requested == "none":
                return None
            return requested if self.resolve_api_key(requested) else None

        for candidate in PROVIDER_AUTO_ORDER:
            if self.resolve_api_key(candidate):
                return candidate
        return None


def load_config(environ: Optional[Mapping[str, str]] = None) -> Config:
    """Load defaults, then the YAML file, then environment overrides.

    Raises :class:`ConfigError` if a config file exists but cannot be honoured.
    """
    refused = load_dotenv_files()

    path = find_config_path()
    file_data = _load_yaml(path) if path is not None else {}

    merged = deep_merge(DEFAULTS, file_data)
    merged = deep_merge(merged, env_overrides(environ))

    # Normalise provider aliases so `providers.anthropic` and `providers.claude`
    # address the same settings block.
    providers = merged.get("providers")
    if isinstance(providers, dict):
        for alias, canonical in PROVIDER_ALIASES.items():
            if alias in providers:
                merged["providers"][canonical] = deep_merge(
                    providers.get(canonical) or {}, providers.pop(alias) or {}
                )

    return Config(data=merged, source_path=path, refused_dotenv_keys=refused)
