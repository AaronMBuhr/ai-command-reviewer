"""Provider request building and response extraction.

These tests never touch the network: `call_provider` is exercised with a stubbed
transport so the exact request shape each provider receives is asserted
directly. That shape is the part most likely to break silently when a provider
changes, and the part hardest to notice from a passing end-to-end run.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

import providers
import pytest

SYSTEM = "system prompt"
USER = "user content"


class Transport:
    """Stand-in for the HTTP layer: records requests, replays queued responses."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.queue: List[str] = []

    def post_json(self, url: str, body: bytes, headers: Any, timeout: int) -> str:
        self.requests.append({
            "url": url,
            "body": json.loads(body.decode("utf-8")),
            "headers": {k.lower(): v for k, v in dict(headers).items()},
            "timeout": timeout,
        })
        if not self.queue:
            raise AssertionError(f"unexpected request to {url}")
        return self.queue.pop(0)

    def __getitem__(self, index: int) -> Dict[str, Any]:
        return self.requests[index]

    def __len__(self) -> int:
        return len(self.requests)


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Transport:
    transport = Transport()
    monkeypatch.setattr(providers, "post_json", transport.post_json)
    return transport


def _review_json() -> str:
    return json.dumps({"decision": "allow", "headline": "fine"})


def call(name: str, settings: Dict[str, Any], captured: Transport,
         raw_response: str) -> Dict[str, Any]:
    captured.queue.append(raw_response)
    return providers.call_provider(
        provider_name=name, settings=settings, api_key="test-key",
        system_prompt=SYSTEM, user_content=USER, timeout=7,
    )


# ---------------------------------------------------------------- claude

def test_claude_request_shape(captured: Transport) -> None:
    response = json.dumps({"content": [{"type": "text", "text": _review_json()}]})
    result = call("claude", {"model": "claude-haiku-4-5"}, captured, response)

    request = captured[0]
    assert request["url"] == "https://api.anthropic.com/v1/messages"
    assert request["headers"]["x-api-key"] == "test-key"
    assert request["headers"]["anthropic-version"] == "2023-06-01"
    assert request["timeout"] == 7

    body = request["body"]
    assert body["model"] == "claude-haiku-4-5"
    assert body["system"] == SYSTEM
    assert body["messages"] == [{"role": "user", "content": USER}]
    # The Messages API requires max_tokens, so it must always be present.
    assert body["max_tokens"] == providers.DEFAULT_MAX_TOKENS
    assert body["temperature"] == 0
    assert result == {"decision": "allow", "headline": "fine"}


def test_claude_uses_default_model_when_unset(captured: Transport) -> None:
    response = json.dumps({"content": [{"type": "text", "text": _review_json()}]})
    call("claude", {}, captured, response)
    assert captured[0]["body"]["model"] == providers.CLAUDE_DEFAULT_MODEL


def test_claude_joins_multiple_text_blocks() -> None:
    data = {"content": [
        {"type": "text", "text": '{"decision":'},
        {"type": "thinking", "text": "ignored"},
        {"type": "text", "text": '"deny"}'},
    ]}
    assert providers._extract_claude_text(data) == '{"decision":"deny"}'


# --------------------------------------------------------------- chatgpt

def test_chatgpt_request_shape(captured: Transport) -> None:
    response = json.dumps({"choices": [{"message": {"content": _review_json()}}]})
    call("chatgpt", {"model": "gpt-4.1-mini"}, captured, response)

    request = captured[0]
    assert request["url"] == "https://api.openai.com/v1/chat/completions"
    assert request["headers"]["authorization"] == "Bearer test-key"

    body = request["body"]
    assert body["messages"] == [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": USER},
    ]
    # Reasoning models reject `max_tokens`; the modern field name is the default.
    assert body["max_completion_tokens"] == providers.DEFAULT_MAX_TOKENS
    assert "max_tokens" not in body
    assert body["response_format"] == {"type": "json_object"}


def test_chatgpt_token_field_and_response_format_are_configurable(captured: Transport) -> None:
    """Older models and third-party gateways need the legacy spellings."""
    response = json.dumps({"choices": [{"message": {"content": _review_json()}}]})
    call("chatgpt", {
        "model": "local-model",
        "max_tokens_field": "max_tokens",
        "response_format": None,
        "base_url": "http://localhost:1234/v1",
    }, captured, response)

    request = captured[0]
    assert request["url"] == "http://localhost:1234/v1/chat/completions"
    assert request["body"]["max_tokens"] == providers.DEFAULT_MAX_TOKENS
    assert "response_format" not in request["body"]


@pytest.mark.parametrize("content", ["", '{"decision": "as'])
def test_chatgpt_reports_truncation_clearly(content: str) -> None:
    """Truncation must be reported even when partial text came back -- a cut-off
    reply is invalid JSON, and "raise your token limit" is the useful message."""
    data = {"choices": [{"message": {"content": content}, "finish_reason": "length"}]}
    with pytest.raises(providers.ProviderError, match="token limit"):
        providers._extract_chatgpt_text(data)


# ---------------------------------------------------------------- gemini

def test_gemini_request_shape(captured: Transport) -> None:
    response = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": _review_json()}]}}]}
    )
    call("gemini", {"model": "gemini-2.5-flash", "max_output_tokens": 2048,
                    "thinking_budget": 0}, captured, response)

    request = captured[0]
    assert request["url"] == (
        "https://generativelanguage.googleapis.com/v1beta"
        "/models/gemini-2.5-flash:generateContent"
    )
    # The key must travel in a header, never the query string.
    assert request["headers"]["x-goog-api-key"] == "test-key"
    assert "test-key" not in request["url"]

    body = request["body"]
    assert body["systemInstruction"] == {"parts": [{"text": SYSTEM}]}
    assert body["contents"] == [{"role": "user", "parts": [{"text": USER}]}]
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["maxOutputTokens"] == 2048
    assert config["thinkingConfig"] == {"thinkingBudget": 0}


def test_gemini_thinking_level_replaces_the_deprecated_budget(captured: Transport) -> None:
    """Gemini 3.x deprecated the numeric thinkingBudget in favour of a
    thinkingLevel enum. Sending the old field there is silently ignored, so a
    config that sets it is doing nothing."""
    response = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": _review_json()}]}}]}
    )
    call("gemini", {"model": "gemini-3.6-flash", "thinking_level": "medium"},
         captured, response)
    config = captured[0]["body"]["generationConfig"]
    assert config["thinkingConfig"] == {"thinkingLevel": "medium"}
    assert "thinkingBudget" not in config["thinkingConfig"]


def test_gemini_thinking_level_wins_over_thinking_budget(captured: Transport) -> None:
    """Both set is a config in mid-migration; the current field should win."""
    response = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": _review_json()}]}}]}
    )
    call("gemini", {"model": "m", "thinking_level": "low", "thinking_budget": 128},
         captured, response)
    assert captured[0]["body"]["generationConfig"]["thinkingConfig"] == {
        "thinkingLevel": "low"}


def test_gemini_still_supports_thinking_budget_for_older_models(
    captured: Transport
) -> None:
    response = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": _review_json()}]}}]}
    )
    call("gemini", {"model": "gemini-2.5-flash", "thinking_budget": 0},
         captured, response)
    assert captured[0]["body"]["generationConfig"]["thinkingConfig"] == {
        "thinkingBudget": 0}


@pytest.mark.parametrize("parts", [[], [{"text": '{"decision": "as'}]])
def test_gemini_reports_thinking_budget_exhaustion(parts: list) -> None:
    """Observed live: a thinking model with too small a budget returns truncated
    JSON, which previously surfaced as an unhelpful "no JSON object" error."""
    data = {"candidates": [{"content": {"parts": parts}, "finishReason": "MAX_TOKENS"}]}
    with pytest.raises(providers.ProviderError, match="thinking_budget"):
        providers._extract_gemini_text(data)


def test_gemini_surfaces_prompt_block() -> None:
    with pytest.raises(providers.ProviderError, match="SAFETY"):
        providers._extract_gemini_text({"promptFeedback": {"blockReason": "SAFETY"}})


# ------------------------------------------------------- shared behaviour

@pytest.mark.parametrize("name", ["chatgpt", "gemini"])
def test_providers_without_a_verified_default_require_an_explicit_model(name: str) -> None:
    """Guessing a model id would fail on first run for every user."""
    with pytest.raises(providers.ProviderError, match="No model configured"):
        providers.call_provider(
            provider_name=name, settings={}, api_key="k",
            system_prompt=SYSTEM, user_content=USER, timeout=5,
        )


@pytest.mark.parametrize("name,settings,response", [
    ("claude", {"model": "m"}, {"content": [{"type": "text", "text": '{"decision":"allow"}'}]}),
    ("chatgpt", {"model": "m"}, {"choices": [{"message": {"content": '{"decision":"allow"}'}}]}),
    ("gemini", {"model": "m"},
     {"candidates": [{"content": {"parts": [{"text": '{"decision":"allow"}'}]}}]}),
])
def test_temperature_null_omits_the_field(
    name: str, settings: Dict[str, Any], response: Dict[str, Any], captured: Transport
) -> None:
    """Some models reject `temperature` outright; null must omit, not send 0."""
    call(name, {**settings, "temperature": None}, captured, json.dumps(response))
    body = captured[0]["body"]
    assert "temperature" not in json.dumps(body)


def test_extra_body_passes_unknown_parameters_through(captured: Transport) -> None:
    response = json.dumps({"choices": [{"message": {"content": _review_json()}}]})
    call("chatgpt", {"model": "m", "extra_body": {"seed": 42, "top_p": 0.1}},
         captured, response)
    assert captured[0]["body"]["seed"] == 42
    assert captured[0]["body"]["top_p"] == 0.1


def test_missing_api_key_is_reported_before_any_request(captured: Transport) -> None:
    with pytest.raises(providers.ProviderError, match="No API key"):
        providers.call_provider(
            provider_name="claude", settings={"model": "m"}, api_key="",
            system_prompt=SYSTEM, user_content=USER, timeout=5,
        )
    assert len(captured) == 0


def test_unknown_provider_lists_the_supported_ones() -> None:
    with pytest.raises(providers.ProviderError, match="claude, chatgpt, gemini"):
        providers.call_provider(
            provider_name="llama", settings={}, api_key="k",
            system_prompt=SYSTEM, user_content=USER, timeout=5,
        )


def test_json_wrapped_in_prose_is_still_parsed() -> None:
    text = 'Here is my review:\n```json\n{"decision": "ask"}\n```\nHope that helps.'
    assert providers.parse_json_object(text, "test") == {"decision": "ask"}


def test_non_object_json_is_rejected() -> None:
    with pytest.raises(providers.ProviderError, match="expected an object"):
        providers.parse_json_object("[1, 2, 3]", "test")
