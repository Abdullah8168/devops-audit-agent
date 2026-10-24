"""Thin LLM client for any OpenAI-compatible chat-completions endpoint.

Google Gemini, OpenAI, Groq, OpenRouter and Ollama all expose this API, so the
agent is provider-agnostic: the provider is chosen with ``LLM_BASE_URL`` and
``LLM_MODEL``. Only the plain ``openai`` SDK is used; tool dispatch and control
flow live in :mod:`auditor.agent_loop`.

The client adds what a long unattended run needs: bounded retries with
exponential backoff (honouring server ``retry-after`` hints), optional request
throttling for free-tier rate limits, and clear errors for fatal conditions
(bad key, unknown model, exhausted daily quota).
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_MODEL = "gemini-2.5-flash"


class LLMError(Exception):
    """The LLM provider failed in a way the agent cannot recover from."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]
    raw_arguments: str = ""
    parse_error: str | None = None


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall]
    message: dict[str, Any]  # assistant message to append to the conversation, verbatim
    usage: dict[str, int] = field(default_factory=dict)
    finish_reason: str | None = None


class ChatModel(Protocol):
    """Interface used by the agent loop (implemented by the real client and test fakes)."""

    model: str

    def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], tool_choice: str = "auto"
    ) -> LLMResponse: ...


@dataclass
class LLMSettings:
    api_key: str
    model: str = DEFAULT_MODEL
    base_url: str = DEFAULT_BASE_URL
    timeout_s: float = 120.0
    max_retries: int = 6
    min_interval_s: float = 0.0
    temperature: float = 0.1

    @classmethod
    def from_env(cls, model: str | None = None) -> LLMSettings:
        api_key = (
            os.getenv("LLM_API_KEY") or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
            or os.getenv("OPENAI_API_KEY") or ""
        ).strip()
        if not api_key:
            raise LLMError(
                "No API key configured. Set LLM_API_KEY in your environment or .env file "
                "(see .env.example)."
            )
        try:
            min_interval = float(os.getenv("LLM_MIN_INTERVAL", "0") or 0)
        except ValueError:
            min_interval = 0.0
        return cls(
            api_key=api_key,
            model=(model or os.getenv("LLM_MODEL") or DEFAULT_MODEL).strip(),
            base_url=(os.getenv("LLM_BASE_URL") or DEFAULT_BASE_URL).strip(),
            min_interval_s=max(0.0, min_interval),
        )


def parse_arguments(raw: str | None) -> tuple[dict[str, Any], str | None]:
    """Parse a tool call's JSON arguments, tolerating empty strings and code fences."""
    if raw is None or not str(raw).strip():
        return {}, None
    text = str(raw).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        return {}, f"arguments are not valid JSON: {exc}"
    if not isinstance(value, dict):
        return {}, "arguments must be a JSON object"
    return value, None


class OpenAICompatibleClient:
    """Chat client with tool calling, retries and throttling."""

    def __init__(self, settings: LLMSettings):
        try:
            import openai
        except ImportError as exc:  # pragma: no cover
            raise LLMError("The 'openai' package is required: pip install -r requirements.txt") from exc
        self._openai = openai
        self.settings = settings
        self.model = settings.model
        self._client = openai.OpenAI(
            api_key=settings.api_key,
            base_url=settings.base_url,
            timeout=settings.timeout_s,
            max_retries=0,  # retries are handled here so they can be logged and bounded
        )
        self._last_request = 0.0
        self.total_usage: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "requests": 0}

    def _throttle(self) -> None:
        wait = self.settings.min_interval_s - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    @staticmethod
    def _retry_after(exc: Exception) -> float | None:
        response = getattr(exc, "response", None)
        if response is not None:
            header = response.headers.get("retry-after") if hasattr(response, "headers") else None
            if header:
                try:
                    return float(header)
                except ValueError:
                    pass
        match = re.search(r"retry(?:Delay| in)[\"':\s]*([\d.]+)\s*s", str(exc), re.IGNORECASE)
        return float(match.group(1)) if match else None

    def chat(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], tool_choice: str = "auto"
    ) -> LLMResponse:
        oa = self._openai
        last_error: Exception | None = None
        for attempt in range(self.settings.max_retries + 1):
            self._throttle()
            try:
                completion = self._client.chat.completions.create(
                    model=self.settings.model,
                    messages=messages,
                    tools=tools,
                    tool_choice=tool_choice,
                    temperature=self.settings.temperature,
                )
                return self._to_response(completion)
            except oa.AuthenticationError as exc:
                raise LLMError(f"LLM authentication failed (check LLM_API_KEY): {self._err(exc)}") from exc
            except oa.PermissionDeniedError as exc:
                raise LLMError(f"LLM request was denied: {self._err(exc)}") from exc
            except oa.NotFoundError as exc:
                raise LLMError(
                    f"Model {self.settings.model!r} or endpoint not found (check LLM_MODEL / LLM_BASE_URL): {self._err(exc)}"
                ) from exc
            except oa.RateLimitError as exc:
                text = str(exc)
                if re.search(r"PerDay|per day|daily", text, re.IGNORECASE):
                    raise LLMError(
                        "LLM daily quota exhausted. Try again tomorrow, use another model "
                        f"(LLM_MODEL) or another API key. Detail: {self._err(exc)}"
                    ) from exc
                last_error = exc
                delay = self._retry_after(exc) or min(60.0, 4.0 * 2**attempt)
            except oa.BadRequestError as exc:
                raise LLMError(f"LLM rejected the request: {self._err(exc)}") from exc
            except (oa.APITimeoutError, oa.APIConnectionError, oa.InternalServerError) as exc:
                last_error = exc
                delay = min(60.0, 2.0 * 2**attempt)
            except oa.APIStatusError as exc:
                if exc.status_code and exc.status_code >= 500:
                    last_error = exc
                    delay = min(60.0, 2.0 * 2**attempt)
                else:
                    raise LLMError(f"LLM API error {exc.status_code}: {self._err(exc)}") from exc
            if attempt < self.settings.max_retries:
                time.sleep(delay + random.uniform(0, 1.0))
        raise LLMError(
            f"LLM request failed after {self.settings.max_retries + 1} attempts: {self._err(last_error)}"
        )

    def _err(self, exc: Exception | None) -> str:
        """Error text safe to show: shortened, secrets masked, own API key removed."""
        text = _short(exc)
        if self.settings.api_key:
            text = text.replace(self.settings.api_key, "[REDACTED]")
        return text

    def _to_response(self, completion: Any) -> LLMResponse:
        if not getattr(completion, "choices", None):
            raise LLMError("LLM returned no choices (the response may have been blocked by a safety filter)")
        choice = completion.choices[0]
        msg = choice.message
        tool_calls: list[ToolCall] = []
        for i, tc in enumerate(msg.tool_calls or []):
            args, err = parse_arguments(tc.function.arguments)
            tool_calls.append(
                ToolCall(
                    id=tc.id or f"call_{i}",
                    name=tc.function.name,
                    arguments=args,
                    raw_arguments=tc.function.arguments or "",
                    parse_error=err,
                )
            )
        # Keep the provider's message (including extra fields such as Gemini thought
        # signatures) so it can be sent back unchanged on the next turn.
        message: dict[str, Any] = msg.model_dump(exclude_none=True)
        message["role"] = "assistant"
        message.setdefault("content", msg.content or "")
        if tool_calls:
            for tc_dump, tc in zip(message.get("tool_calls", []), tool_calls, strict=False):
                tc_dump["id"] = tc.id
        usage = {}
        if getattr(completion, "usage", None):
            usage = {
                "prompt_tokens": completion.usage.prompt_tokens or 0,
                "completion_tokens": completion.usage.completion_tokens or 0,
            }
            self.total_usage["prompt_tokens"] += usage["prompt_tokens"]
            self.total_usage["completion_tokens"] += usage["completion_tokens"]
        self.total_usage["requests"] += 1
        return LLMResponse(
            content=msg.content or "",
            tool_calls=tool_calls,
            message=message,
            usage=usage,
            finish_reason=choice.finish_reason,
        )


_KEY_IN_ERROR = re.compile(r"(api_key:|key=|Bearer\s+)[A-Za-z0-9._\-]{10,}", re.IGNORECASE)


def _short(exc: Exception | None, limit: int = 300) -> str:
    """Shorten an exception message and strip any API key the provider echoed back."""
    from auditor.redaction import redact

    text = str(exc) if exc else "unknown error"
    text = redact(_KEY_IN_ERROR.sub(lambda m: m.group(1) + "[REDACTED]", text))
    return text if len(text) <= limit else text[:limit] + "..."
