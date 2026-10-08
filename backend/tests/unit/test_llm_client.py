"""Provider clients against a mocked transport: no request ever leaves the test process."""

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import LlmSettings
from app.explain.llm_client import (
    AnthropicClient,
    LlmUnavailable,
    NoneClient,
    OllamaClient,
    OpenAICompatibleClient,
    make_client,
)


def settings(**kw: Any) -> LlmSettings:
    values: dict[str, Any] = {"llm_provider": "ollama", "llm_model": "m", "llm_timeout_s": 5}
    values.update(kw)
    return LlmSettings(**values)


def transport(
    reply: dict[str, Any] | str | int, seen: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if isinstance(reply, int):
            return httpx.Response(reply, json={"error": "boom"})
        if isinstance(reply, str):
            return httpx.Response(200, content=reply.encode())
        return httpx.Response(200, json=reply)

    return httpx.MockTransport(handler)


def test_the_default_provider_is_none_and_never_makes_a_request() -> None:
    assert LlmSettings().llm_provider == "none"
    client = make_client(LlmSettings())
    assert isinstance(client, NoneClient) and client.provider == "none"
    with pytest.raises(LlmUnavailable, match="template"):
        client.generate("s", "u")


def test_ollama_request_is_local_json_mode_at_temperature_zero() -> None:
    seen: list[httpx.Request] = []
    client = make_client(
        settings(llm_base_url="http://ollama:11434/"),
        transport({"message": {"content": '{"ok": true}'}}, seen),
    )
    assert isinstance(client, OllamaClient)
    assert client.generate("sys", "usr") == '{"ok": true}'
    body = json.loads(seen[0].content)
    assert str(seen[0].url) == "http://ollama:11434/api/chat"
    assert body["options"] == {"temperature": 0} and body["format"] == "json"
    assert body["stream"] is False and body["model"] == "m"
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


def test_openai_compatible_sends_the_key_only_as_a_bearer_header() -> None:
    seen: list[httpx.Request] = []
    client = make_client(
        settings(
            llm_provider="openai_compatible",
            llm_base_url="https://llm.example/v1",
            llm_api_key=SecretStr("sk-test-key"),
        ),
        transport({"choices": [{"message": {"content": "{}"}}]}, seen),
    )
    assert isinstance(client, OpenAICompatibleClient)
    assert client.generate("sys", "usr") == "{}"
    request = seen[0]
    assert request.headers["authorization"] == "Bearer sk-test-key"
    assert "sk-test-key" not in request.content.decode()
    assert json.loads(request.content)["temperature"] == 0


def test_anthropic_joins_text_blocks_and_sends_the_key_header() -> None:
    seen: list[httpx.Request] = []
    client = make_client(
        settings(llm_provider="anthropic", llm_api_key=SecretStr("k")),
        transport(
            {"content": [{"type": "text", "text": "{"}, {"type": "text", "text": "}"}]}, seen
        ),
    )
    assert isinstance(client, AnthropicClient)
    assert client.generate("sys", "usr") == "{}"
    assert seen[0].headers["x-api-key"] == "k" and "anthropic-version" in seen[0].headers
    body = json.loads(seen[0].content)
    assert body["temperature"] == 0 and body["system"] == "sys" and body["max_tokens"] > 0


@pytest.mark.parametrize(
    ("kind", "reply"),
    [
        ("ollama", 500),
        ("ollama", "not json"),
        ("ollama", {"unexpected": 1}),
        ("ollama", {"message": {"content": "  "}}),
        ("openai_compatible", {"choices": []}),
        ("openai_compatible", {"choices": [{"message": {}}]}),
        ("anthropic", {"content": []}),
        ("anthropic", 429),
    ],
)
def test_a_bad_response_is_unavailable_never_a_crash(kind: str, reply: Any) -> None:
    client = make_client(
        settings(
            llm_provider=kind,
            llm_base_url="http://x/v1",
            llm_api_key=SecretStr("k"),
        ),
        transport(reply),
    )
    with pytest.raises(LlmUnavailable):
        client.generate("s", "u")


def test_a_network_error_is_unavailable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = make_client(settings(llm_base_url="http://x"), httpx.MockTransport(refuse))
    with pytest.raises(LlmUnavailable, match="ConnectError"):
        client.generate("s", "u")


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"llm_model": ""}, "LLM_MODEL"),
        ({"llm_provider": "openai_compatible"}, "LLM_BASE_URL"),
        ({"llm_provider": "anthropic"}, "LLM_API_KEY"),
    ],
)
def test_incomplete_provider_configuration_is_unavailable(kw: dict[str, Any], message: str) -> None:
    with pytest.raises(LlmUnavailable, match=message):
        make_client(settings(**kw))


def test_the_api_key_never_appears_in_the_settings_repr() -> None:
    assert "sk-secret" not in repr(settings(llm_api_key=SecretStr("sk-secret")))
