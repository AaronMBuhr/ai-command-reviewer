#!/usr/bin/env python3
"""LLM provider adapters for the command safety reviewer.

Three providers are supported out of the box -- ``claude`` (Anthropic),
``chatgpt`` (OpenAI), and ``gemini`` (Google). Each is described by a
:class:`ProviderSpec` holding the two things that actually differ between them:
how to build the HTTP request, and how to pull the model's text back out.

Every provider accepts the settings its own API understands. Shared keys
(``model``, ``temperature``, ``max_tokens``) are normalised here; anything else
can be passed verbatim through ``extra_body``, so a provider gaining a new
parameter does not require a change to this file.

Dependency-free by design: ``urllib`` only, no vendor SDKs.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

DEFAULT_MAX_TOKENS = 512
DEFAULT_TEMPERATURE = 0

#: Only Claude carries a built-in model default: it is the one this project
#: exercises in its own tests. Baking in an unverified default for the other
#: providers would fail on first run for every user, so those must be set
#: explicitly -- config.example.yaml carries suggested values to start from.
#:
#: This is an alias, not a dated snapshot. `GET /v1/models` lists only concrete
#: snapshots (claude-haiku-4-5-20251001), so the alias looks "missing" there
#: while working fine in `POST /v1/messages`, where it resolves to the current
#: snapshot. The alias is deliberate: pinning a snapshot buys reproducibility
#: and then silently rots when it is retired -- exactly what happened to
#: gemini-2.0-flash and gemini-2.5-flash-lite during this project's testing.
CLAUDE_DEFAULT_MODEL = "claude-haiku-4-5"


class ProviderError(RuntimeError):
    """A provider could not be called, or returned something unusable."""


@dataclass(frozen=True)
class HttpRequest:
    url: str
    body: bytes
    headers: Dict[str, str]


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    default_base_url: str
    build_request: Callable[["ProviderContext"], HttpRequest]
    extract_text: Callable[[Dict[str, Any]], str]
    default_model: Optional[str] = None


@dataclass(frozen=True)
class ProviderContext:
    """Everything a provider needs to build one review request."""

    settings: Mapping[str, Any]
    api_key: str
    system_prompt: str
    user_content: str
    spec: "ProviderSpec"

    def base_url(self) -> str:
        raw = self.settings.get("base_url")
        base = str(raw).strip() if raw else self.spec.default_base_url
        return base.rstrip("/")

    def model(self) -> str:
        raw = self.settings.get("model")
        model = str(raw).strip() if raw else (self.spec.default_model or "")
        if not model:
            raise ProviderError(
                f"No model configured for provider '{self.spec.name}'. Set "
                f"providers.{self.spec.name}.model in your config file (or "
                f"CC_AI_REVIEW__PROVIDERS__{self.spec.name.upper()}__MODEL) to a "
                f"model your account can access."
            )
        return model

    def max_tokens(self) -> Optional[int]:
        if "max_tokens" not in self.settings:
            return DEFAULT_MAX_TOKENS
        raw = self.settings.get("max_tokens")
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError) as exc:
            raise ProviderError(
                f"providers.{self.spec.name}.max_tokens must be an integer, got {raw!r}."
            ) from exc

    def temperature(self) -> Optional[float]:
        """Return the sampling temperature, or None to omit it entirely.

        Some models reject ``temperature`` outright. Setting it to null in the
        config omits the field rather than guessing on the user's behalf.
        """
        if "temperature" not in self.settings:
            return DEFAULT_TEMPERATURE
        raw = self.settings.get("temperature")
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError) as exc:
            raise ProviderError(
                f"providers.{self.spec.name}.temperature must be a number or null, "
                f"got {raw!r}."
            ) from exc

    def extra_body(self) -> Dict[str, Any]:
        raw = self.settings.get("extra_body")
        return dict(raw) if isinstance(raw, Mapping) else {}


def _json_headers(extra: Mapping[str, str]) -> Dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    headers.update(extra)
    return headers


# --------------------------------------------------------------------------
# Claude (Anthropic Messages API)
# --------------------------------------------------------------------------

def _build_claude_request(ctx: ProviderContext) -> HttpRequest:
    body: Dict[str, Any] = {
        "model": ctx.model(),
        "system": ctx.system_prompt,
        "messages": [{"role": "user", "content": ctx.user_content}],
    }
    max_tokens = ctx.max_tokens()
    # The Messages API requires max_tokens, so fall back rather than omit.
    body["max_tokens"] = DEFAULT_MAX_TOKENS if max_tokens is None else max_tokens
    temperature = ctx.temperature()
    if temperature is not None:
        body["temperature"] = temperature
    body.update(ctx.extra_body())

    version = str(ctx.settings.get("anthropic_version") or "2023-06-01")
    return HttpRequest(
        url=f"{ctx.base_url()}/v1/messages",
        body=json.dumps(body).encode("utf-8"),
        headers=_json_headers({"x-api-key": ctx.api_key, "anthropic-version": version}),
    )


def _extract_claude_text(data: Dict[str, Any]) -> str:
    parts: List[str] = []
    for block in data.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "".join(parts).strip()


# --------------------------------------------------------------------------
# ChatGPT (OpenAI Chat Completions)
# --------------------------------------------------------------------------

def _build_chatgpt_request(ctx: ProviderContext) -> HttpRequest:
    body: Dict[str, Any] = {
        "model": ctx.model(),
        "messages": [
            {"role": "system", "content": ctx.system_prompt},
            {"role": "user", "content": ctx.user_content},
        ],
    }

    max_tokens = ctx.max_tokens()
    if max_tokens is not None:
        # Reasoning models require max_completion_tokens; older models and
        # OpenAI-compatible gateways may only accept max_tokens. Which name to
        # send is configuration, not a guess made at runtime.
        field = str(ctx.settings.get("max_tokens_field") or "max_completion_tokens")
        body[field] = max_tokens

    temperature = ctx.temperature()
    if temperature is not None:
        body["temperature"] = temperature

    # "json_object" holds the model to a JSON reply. Set to null for gateways
    # or models that do not implement response_format.
    response_format = (
        ctx.settings.get("response_format")
        if "response_format" in ctx.settings
        else "json_object"
    )
    if response_format:
        body["response_format"] = {"type": str(response_format)}

    body.update(ctx.extra_body())
    return HttpRequest(
        url=f"{ctx.base_url()}/chat/completions",
        body=json.dumps(body).encode("utf-8"),
        headers=_json_headers({"authorization": f"Bearer {ctx.api_key}"}),
    )


def _extract_chatgpt_text(data: Dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        raise ProviderError("OpenAI response contained no choices.")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("OpenAI response choice was not an object.")
    # Checked before the text is examined: a reply cut off at the token limit is
    # truncated JSON, which would otherwise surface as a confusing parse error
    # rather than the actionable "raise your token limit".
    if first.get("finish_reason") == "length":
        raise ProviderError(
            "OpenAI stopped at the token limit before completing its reply. "
            "Raise providers.chatgpt.max_tokens."
        )

    message = first.get("message") or {}
    content = message.get("content")

    if isinstance(content, list):  # some gateways return content parts
        content = "".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict)
        )
    return str(content or "").strip()


# --------------------------------------------------------------------------
# Gemini (Google Generative Language API)
# --------------------------------------------------------------------------

def _build_gemini_request(ctx: ProviderContext) -> HttpRequest:
    generation_config: Dict[str, Any] = {"responseMimeType": "application/json"}

    temperature = ctx.temperature()
    if temperature is not None:
        generation_config["temperature"] = temperature

    # Gemini names this maxOutputTokens; accept the provider's own spelling as
    # well as the shared max_tokens key.
    max_output = ctx.settings.get("max_output_tokens")
    if max_output is None:
        max_output = ctx.max_tokens()
    if max_output is not None:
        generation_config["maxOutputTokens"] = int(max_output)

    # Thinking controls. Gemini 3.x replaced the numeric thinkingBudget with a
    # thinkingLevel enum ("minimal" | "medium" | "high"); the old field is
    # deprecated and ignored there, so setting it silently does nothing. Both are
    # supported because 2.5-era models still take the budget.
    thinking_level = ctx.settings.get("thinking_level")
    thinking_budget = ctx.settings.get("thinking_budget")
    if thinking_level:
        generation_config["thinkingConfig"] = {"thinkingLevel": str(thinking_level)}
    elif thinking_budget is not None:
        generation_config["thinkingConfig"] = {"thinkingBudget": int(thinking_budget)}

    body: Dict[str, Any] = {
        "systemInstruction": {"parts": [{"text": ctx.system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": ctx.user_content}]}],
        "generationConfig": generation_config,
    }
    body.update(ctx.extra_body())

    model = ctx.model()
    return HttpRequest(
        # The API key goes in a header, not the query string, so it cannot leak
        # into proxy logs or error messages that echo the URL.
        url=f"{ctx.base_url()}/models/{model}:generateContent",
        body=json.dumps(body).encode("utf-8"),
        headers=_json_headers({"x-goog-api-key": ctx.api_key}),
    )


def _extract_gemini_text(data: Dict[str, Any]) -> str:
    feedback = data.get("promptFeedback") or {}
    if feedback.get("blockReason"):
        raise ProviderError(
            f"Gemini blocked the review prompt: {feedback.get('blockReason')}."
        )

    candidates = data.get("candidates") or []
    if not candidates:
        raise ProviderError("Gemini response contained no candidates.")
    candidate = candidates[0]
    if not isinstance(candidate, dict):
        raise ProviderError("Gemini candidate was not an object.")

    # Checked before the text is examined. On a thinking model the budget is
    # spent before any text is emitted, so a too-small limit yields either no
    # text or truncated JSON -- both of which must report the real cause rather
    # than a parse failure.
    if candidate.get("finishReason") == "MAX_TOKENS":
        raise ProviderError(
            "Gemini hit the token limit before completing its reply. Raise "
            "providers.gemini.max_output_tokens (thinking models need noticeably "
            "more), or lower providers.gemini.thinking_budget so fewer of those "
            "tokens go to thinking."
        )

    parts = (candidate.get("content") or {}).get("parts") or []
    return "".join(
        str(part.get("text", "")) for part in parts if isinstance(part, dict)
    ).strip()


REGISTRY: Dict[str, ProviderSpec] = {
    "claude": ProviderSpec(
        name="claude",
        default_base_url="https://api.anthropic.com",
        build_request=_build_claude_request,
        extract_text=_extract_claude_text,
        default_model=CLAUDE_DEFAULT_MODEL,
    ),
    "chatgpt": ProviderSpec(
        name="chatgpt",
        default_base_url="https://api.openai.com/v1",
        build_request=_build_chatgpt_request,
        extract_text=_extract_chatgpt_text,
    ),
    "gemini": ProviderSpec(
        name="gemini",
        default_base_url="https://generativelanguage.googleapis.com/v1beta",
        build_request=_build_gemini_request,
        extract_text=_extract_gemini_text,
    ),
}


# --------------------------------------------------------------------------
# HTTP transport
# --------------------------------------------------------------------------

def describe_http_error(exc: urllib.error.HTTPError) -> str:
    """Flatten an HTTPError into a status line plus the server's explanation.

    ``str(HTTPError)`` is only "HTTP Error 400: Bad Request"; the actionable
    reason (exhausted credits, revoked key, rejected parameter) is in the body,
    which is readable exactly once and lost as soon as the exception escapes.
    Surfacing it is what lets a user fix a provider-specific parameter without
    this code having to guess which parameter was wrong.
    """
    try:
        raw = exc.read().decode("utf-8", errors="replace").strip()
    except Exception:
        raw = ""

    detail = raw
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    else:
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            detail = str(err.get("message") or "").strip() or json.dumps(err)
        elif isinstance(err, str):
            detail = err

    detail = re.sub(r"\s+", " ", detail).strip()[:400]
    status = f"HTTP {exc.code} {exc.reason}".strip()
    return f"{status}: {detail}" if detail else status


def post_json(url: str, body: bytes, headers: Mapping[str, str], timeout: int) -> str:
    """POST bytes and return the response text, preserving error bodies."""
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise ProviderError(describe_http_error(exc)) from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"Could not reach {url}: {exc.reason}") from exc


def parse_json_object(text: str, provider_name: str) -> Dict[str, Any]:
    """Parse the model's reply as a JSON object.

    Models occasionally wrap JSON in prose or a code fence even when told not
    to, so fall back to the first balanced-looking object in the text.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ProviderError(
                f"{provider_name} returned no JSON object: {text[:200]}"
            ) from None
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"{provider_name} returned malformed JSON: {text[:200]}"
            ) from exc

    if not isinstance(parsed, dict):
        raise ProviderError(
            f"{provider_name} returned {type(parsed).__name__}, expected an object."
        )
    return parsed


def call_provider(
    provider_name: str,
    settings: Mapping[str, Any],
    api_key: str,
    system_prompt: str,
    user_content: str,
    timeout: int,
) -> Dict[str, Any]:
    """Call one provider and return the parsed JSON review object."""
    spec = REGISTRY.get(provider_name)
    if spec is None:
        # Registry order, which is also the auto-selection order documented in
        # the config file -- more useful to a reader than alphabetical.
        known = ", ".join(REGISTRY)
        raise ProviderError(
            f"Unknown provider '{provider_name}'. Supported providers: {known}."
        )
    if not api_key:
        raise ProviderError(
            f"No API key for provider '{provider_name}'. Set the environment "
            f"variable named by providers.{provider_name}.api_key_env."
        )

    ctx = ProviderContext(
        settings=settings,
        api_key=api_key,
        system_prompt=system_prompt,
        user_content=user_content,
        spec=spec,
    )
    request = spec.build_request(ctx)
    raw = post_json(request.url, request.body, request.headers, timeout)

    try:
        response = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(
            f"{provider_name} returned a non-JSON HTTP body: {raw[:200]}"
        ) from exc
    if not isinstance(response, dict):
        raise ProviderError(f"{provider_name} returned an unexpected HTTP body shape.")

    return parse_json_object(spec.extract_text(response), provider_name)
