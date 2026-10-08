"""Config layering, provider selection, and the `.env` trust boundary."""
from __future__ import annotations

from pathlib import Path

import config
import pytest


def write_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv(config.CONFIG_PATH_ENV, str(path))
    return path


# ------------------------------------------------------------- layering

def test_defaults_apply_with_no_config_file() -> None:
    cfg = config.load_config()
    assert cfg.source_path is None
    assert cfg.policy.fail_mode == "ask"
    assert cfg.policy.timeout_seconds == 20
    assert cfg.policy.allow_readonly is True


def test_config_file_overrides_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_config(tmp_path, monkeypatch, """
policy:
  fail_mode: deny
  timeout_seconds: 45
providers:
  gemini:
    model: gemini-test
""")
    cfg = config.load_config()
    assert cfg.policy.fail_mode == "deny"
    assert cfg.policy.timeout_seconds == 45
    assert cfg.provider_settings("gemini")["model"] == "gemini-test"
    # Unspecified keys still fall back to defaults rather than disappearing.
    assert cfg.policy.allow_readonly is True


def test_environment_overrides_the_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, monkeypatch, "policy:\n  fail_mode: deny\n")
    monkeypatch.setenv("CC_AI_REVIEW__POLICY__FAIL_MODE", "ask")
    assert config.load_config().policy.fail_mode == "ask"


def test_doubled_underscore_separates_path_segments(monkeypatch: pytest.MonkeyPatch) -> None:
    """`max_tokens` contains an underscore, so segments need an unambiguous split."""
    monkeypatch.setenv("CC_AI_REVIEW__PROVIDERS__CHATGPT__MAX_TOKENS", "1234")
    settings = config.load_config().provider_settings("chatgpt")
    assert settings["max_tokens"] == 1234  # coerced to int, not left as "1234"


def test_legacy_flat_env_vars_still_work(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CC_AI_REVIEW_ANTHROPIC_MODEL", "claude-legacy")
    monkeypatch.setenv("CC_AI_REVIEW_FAIL_MODE", "deny")
    cfg = config.load_config()
    assert cfg.provider_settings("claude")["model"] == "claude-legacy"
    assert cfg.policy.fail_mode == "deny"


def test_provider_aliases_merge_onto_canonical_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, monkeypatch, """
providers:
  anthropic:
    model: via-alias
""")
    assert config.load_config().provider_settings("claude")["model"] == "via-alias"


@pytest.mark.parametrize("raw,expected", [
    (True, True), (False, False),
    ("true", True), ("True", True), ("YES", True), ("on", True), ("1", True),
    ("false", False), ("False", False), ("no", False), ("off", False), ("0", False),
    (1, True), (0, False),
])
def test_boolean_coercion_accepts_the_obvious_spellings(raw: object, expected: bool) -> None:
    assert config.coerce_bool(raw, "allow_readonly") is expected


@pytest.mark.parametrize("raw", ["maybe", "", "  ", "sure", [], {}, None, 1.5])
def test_boolean_coercion_rejects_anything_ambiguous(raw: object) -> None:
    """Guessing is worse than failing here: bool("false") is True, so a quoted
    YAML value would silently invert a security policy."""
    with pytest.raises(config.ConfigError, match="must be a boolean"):
        config.coerce_bool(raw, "allow_readonly")


def test_quoted_false_does_not_re_enable_the_readonly_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, monkeypatch, 'policy:\n  allow_readonly: "false"\n')
    assert config.load_config().policy.allow_readonly is False


def test_unparsable_boolean_in_a_config_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, monkeypatch, "policy:\n  allow_readonly: maybe\n")
    with pytest.raises(config.ConfigError, match="allow_readonly"):
        _ = config.load_config().policy


def test_unquoted_false_still_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_config(tmp_path, monkeypatch, "policy:\n  allow_readonly: false\n")
    assert config.load_config().policy.allow_readonly is False


def test_scalar_coercion() -> None:
    assert config.coerce_scalar("true") is True
    assert config.coerce_scalar("off") is False
    assert config.coerce_scalar("null") is None
    assert config.coerce_scalar("30") == 30
    assert config.coerce_scalar("0.5") == 0.5
    assert config.coerce_scalar("claude-haiku-4-5") == "claude-haiku-4-5"


# --------------------------------------------------- fail-closed on config

def test_malformed_yaml_raises_rather_than_reverting_to_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, monkeypatch, "policy:\n  fail_mode: [unclosed\n")
    with pytest.raises(config.ConfigError, match="not valid YAML"):
        config.load_config()


def test_non_mapping_config_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, monkeypatch, "- just\n- a list\n")
    with pytest.raises(config.ConfigError, match="mapping at the top level"):
        config.load_config()


def test_missing_pyyaml_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A config file the user wrote must never be silently ignored."""
    path = write_config(tmp_path, monkeypatch, "policy:\n  fail_mode: deny\n")
    import builtins
    real_import = builtins.__import__

    def no_yaml(name: str, *args: object, **kwargs: object) -> object:
        if name == "yaml":
            raise ImportError("No module named 'yaml'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_yaml)
    with pytest.raises(config.ConfigError, match="PyYAML is not installed"):
        config._load_yaml(path)


# --------------------------------------------------- provider selection

def test_auto_selection_prefers_claude_then_chatgpt_then_gemini(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    assert config.load_config().selected_provider() == "gemini"

    monkeypatch.setenv("OPENAI_API_KEY", "o")
    assert config.load_config().selected_provider() == "chatgpt"

    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    assert config.load_config().selected_provider() == "claude"


def test_no_key_means_no_provider() -> None:
    assert config.load_config().selected_provider() is None


def test_explicit_provider_without_a_key_selects_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Falling back to a different provider than the one asked for would be
    surprising, and could send commands to an unintended vendor."""
    write_config(tmp_path, monkeypatch, "reviewer:\n  provider: gemini\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    assert config.load_config().selected_provider() is None


def test_api_key_env_indirection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_config(tmp_path, monkeypatch, """
providers:
  chatgpt:
    api_key_env: MY_CUSTOM_KEY_VAR
""")
    monkeypatch.setenv("MY_CUSTOM_KEY_VAR", "secret")
    assert config.load_config().resolve_api_key("chatgpt") == "secret"


# ------------------------------------------------------- reviewer routing

def test_reviewer_url_and_command_are_read_from_the_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without this, a typo in the accessors would silently disable the HTTP and
    command reviewer paths while every other test still passed."""
    write_config(tmp_path, monkeypatch, """
reviewer:
  url: http://127.0.0.1:8765/review
  command: python /opt/review_cli.py
""")
    cfg = config.load_config()
    assert cfg.reviewer_url == "http://127.0.0.1:8765/review"
    assert cfg.reviewer_command == "python /opt/review_cli.py"


@pytest.mark.parametrize("value", ["null", '""', '"   "'])
def test_blank_reviewer_settings_are_treated_as_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    write_config(tmp_path, monkeypatch, f"reviewer:\n  url: {value}\n")
    assert config.load_config().reviewer_url is None


# ------------------------------------------------------ .env trust boundary

def test_dotenv_loads_api_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-from-dotenv\n", encoding="utf-8")
    cfg = config.load_config()
    assert cfg.resolve_api_key("chatgpt") == "sk-from-dotenv"
    assert cfg.refused_dotenv_keys == []


@pytest.mark.parametrize("hostile_key", [
    "CC_AI_REVIEW_COMMAND",
    "CC_AI_REVIEW_URL",
    "CC_AI_REVIEW__REVIEWER__COMMAND",
    "CC_AI_REVIEW__PROVIDERS__CLAUDE__BASE_URL",
    "CC_AI_REVIEW_CONFIG",
])
def test_dotenv_refuses_everything_except_api_keys(
    tmp_path: Path, hostile_key: str
) -> None:
    """A `.env` is read from the working directory, which an agent may have
    pointed at a cloned repository. Letting it set the reviewer command would be
    arbitrary code execution inside the hook meant to prevent exactly that."""
    (tmp_path / ".env").write_text(f"{hostile_key}=payload\n", encoding="utf-8")
    cfg = config.load_config()

    assert hostile_key in cfg.refused_dotenv_keys
    import os
    assert os.environ.get(hostile_key) is None
    assert cfg.reviewer_command is None
    assert cfg.reviewer_url is None


def test_dotenv_never_overrides_the_real_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-real-env")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=from-dotenv\n", encoding="utf-8")
    assert config.load_config().resolve_api_key("claude") == "from-real-env"


def test_config_is_not_discovered_from_the_working_directory(tmp_path: Path) -> None:
    """The strongest form of the same boundary: a cloned repo cannot ship a
    config.yaml that redirects the reviewer."""
    (tmp_path / "config.yaml").write_text(
        "reviewer:\n  command: touch /tmp/pwned\n", encoding="utf-8"
    )
    cfg = config.load_config()
    assert cfg.source_path is None
    assert cfg.reviewer_command is None


def test_claude_project_dir_is_not_a_config_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = tmp_path / "cloned-repo"
    hostile.mkdir()
    (hostile / "config.yaml").write_text(
        "reviewer:\n  url: http://attacker.test/review\n", encoding="utf-8"
    )
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(hostile))
    assert config.load_config().reviewer_url is None
