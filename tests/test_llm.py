"""LLM client behaviour without network access (the SDK call is replaced)."""

from types import SimpleNamespace

import httpx
import openai
import pytest

from auditor.llm import LLMError, LLMSettings, OpenAICompatibleClient, parse_arguments

KEY = "AQ.test-key-1234567890abcdef"


def _status_error(cls, status, message):
    request = httpx.Request("POST", "https://llm.example/v1/chat/completions")
    return cls(message, response=httpx.Response(status, request=request), body=None)


def _completion(model):
    call = SimpleNamespace(id="c1", function=SimpleNamespace(name="list_files", arguments="{}"))
    msg = SimpleNamespace(
        content=f"answered by {model}",
        tool_calls=[call],
        model_dump=lambda exclude_none=True: {
            "role": "assistant",
            "content": f"answered by {model}",
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "list_files", "arguments": "{}"}}],
        },
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="tool_calls")], usage=None)


def make_client(behaviour, fallbacks=()):
    settings = LLMSettings(api_key=KEY, model="primary", fallback_models=list(fallbacks), max_retries=1)
    client = OpenAICompatibleClient(settings)
    seen = []

    def create(model, **_):
        seen.append(model)
        result = behaviour(model)
        if isinstance(result, Exception):
            raise result
        return result

    client._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    return client, seen


def test_successful_call_parses_tool_calls():
    client, _ = make_client(_completion)
    response = client.chat([{"role": "user", "content": "hi"}], [])
    assert response.tool_calls[0].name == "list_files" and response.tool_calls[0].arguments == {}
    assert response.message["role"] == "assistant"


def test_daily_quota_switches_to_fallback_model():
    def behaviour(model):
        if model == "primary":
            return _status_error(openai.RateLimitError, 429, "Quota exceeded: GenerateRequestsPerDayPerProjectPerModel")
        return _completion(model)

    client, seen = make_client(behaviour, fallbacks=["backup"])
    response = client.chat([], [])
    assert seen == ["primary", "backup"]
    assert client.model == "backup" and "backup" in response.content
    assert client.model_switches


def test_unknown_model_without_fallback_is_fatal():
    client, _ = make_client(lambda m: _status_error(openai.NotFoundError, 404, "model not found"))
    with pytest.raises(LLMError, match="not found"):
        client.chat([], [])


def test_auth_error_is_fatal_and_never_leaks_the_key():
    client, _ = make_client(
        lambda m: _status_error(openai.AuthenticationError, 401, f"Consumer 'api_key:{KEY}' is invalid"),
        fallbacks=["backup"],
    )
    with pytest.raises(LLMError) as exc_info:
        client.chat([], [])
    assert KEY not in str(exc_info.value)
    assert "authentication failed" in str(exc_info.value)


def test_parse_arguments_tolerates_empty_and_fenced_json():
    assert parse_arguments("") == ({}, None)
    assert parse_arguments('```json\n{"path": "a.py"}\n```') == ({"path": "a.py"}, None)
    assert parse_arguments("{bad")[1].startswith("arguments are not valid JSON")
    assert parse_arguments("[1, 2]")[1] == "arguments must be a JSON object"
