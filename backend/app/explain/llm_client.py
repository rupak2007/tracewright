"""Provider clients behind one tiny interface: `generate(system, user) -> str` (architecture §13).

`none` (the default) never makes a request. `ollama` is local; `openai_compatible` and `anthropic`
are external and only exist when explicitly configured with a key from the environment (SEC-05).
Temperature is 0 for every provider and the timeout is bounded. A network error, an HTTP error
status or an unreadable response raises `LlmUnavailable`; the caller then shows the template. The
client never sees the mapping from pseudonyms to real values.
"""

from typing import Any, Protocol

import httpx

from app.core.config import LlmSettings

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
MAX_TOKENS = 2048


class LlmUnavailable(RuntimeError):
    """The provider is switched off, unreachable, slow or returned something unusable."""


class LlmClient(Protocol):
    provider: str
    model: str

    def generate(self, system: str, user: str) -> str: ...


class NoneClient:
    provider = "none"
    model = ""

    def generate(self, system: str, user: str) -> str:
        raise LlmUnavailable("LLM_PROVIDER is none: only the template summary is available")


class _HttpClient:
    provider = ""

    def __init__(self, settings: LlmSettings, transport: httpx.BaseTransport | None = None) -> None:
        self.model = settings.llm_model
        self._base = settings.llm_base_url.rstrip("/")
        self._key = settings.llm_api_key.get_secret_value() if settings.llm_api_key else ""
        self._client = httpx.Client(timeout=settings.llm_timeout_s, transport=transport)

    def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> Any:
        try:
            response = self._client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LlmUnavailable(f"{self.provider}: {type(exc).__name__}") from exc


class OllamaClient(_HttpClient):
    provider = "ollama"

    def generate(self, system: str, user: str) -> str:
        data = self._post(
            f"{self._base}/api/chat",
            {
                "model": self.model,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            {},
        )
        return _text(data, ("message", "content"))


class OpenAICompatibleClient(_HttpClient):
    provider = "openai_compatible"

    def generate(self, system: str, user: str) -> str:
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        data = self._post(
            f"{self._base}/chat/completions",
            {
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            headers,
        )
        choices = data.get("choices") if isinstance(data, dict) else None
        if not choices:
            raise LlmUnavailable("openai_compatible: no choices in the response")
        return _text(choices[0], ("message", "content"))


class AnthropicClient(_HttpClient):
    provider = "anthropic"

    def generate(self, system: str, user: str) -> str:
        data = self._post(
            self._base or ANTHROPIC_URL,
            {
                "model": self.model,
                "max_tokens": MAX_TOKENS,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            {"x-api-key": self._key, "anthropic-version": ANTHROPIC_VERSION},
        )
        blocks = data.get("content") if isinstance(data, dict) else None
        if not blocks or not isinstance(blocks, list):
            raise LlmUnavailable("anthropic: no content in the response")
        return "".join(str(b.get("text", "")) for b in blocks if isinstance(b, dict))


def _text(data: Any, path: tuple[str, ...]) -> str:
    for key in path:
        if not isinstance(data, dict) or key not in data:
            raise LlmUnavailable("the provider response has an unexpected shape")
        data = data[key]
    if not isinstance(data, str) or not data.strip():
        raise LlmUnavailable("the provider returned an empty answer")
    return data


def make_client(settings: LlmSettings, transport: httpx.BaseTransport | None = None) -> LlmClient:
    if settings.llm_provider == "none":
        return NoneClient()
    if not settings.llm_model:
        raise LlmUnavailable("LLM_MODEL is not set")
    if settings.llm_provider == "ollama":
        return OllamaClient(settings, transport)
    if settings.llm_provider == "openai_compatible":
        if not settings.llm_base_url:
            raise LlmUnavailable("LLM_BASE_URL is not set")
        return OpenAICompatibleClient(settings, transport)
    if settings.llm_provider == "anthropic":
        if settings.llm_api_key is None:
            raise LlmUnavailable("LLM_API_KEY is not set")
        return AnthropicClient(settings, transport)
    raise LlmUnavailable(f"unknown provider {settings.llm_provider!r}")
