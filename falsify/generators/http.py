"""Bounded HTTP transport for chat-completions servers (including local vLLM).

Retries are opt-in per model (`max_retries`, default 0): only rate limits, transient server
errors and timeouts are retried, with exponential backoff that honors `Retry-After`.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from falsify.generators.llm import LLMGenerator
from falsify.generators.transcript import RecordingTransport, ReplayTransport, TranscriptStore


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward authorization or prompts to an unexpected endpoint.
        return None


@dataclass(frozen=True)
class ModelConfig:
    name: str
    model: str
    endpoint: str
    api_key_env: str = ""
    max_tokens: int = 2048
    temperature: float = 0.0
    timeout: int = 120
    max_retries: int = 0          # extra attempts after a retryable failure; 0 = never retry
    retry_backoff: float = 2.0    # seconds before the first retry, doubled each time

    def __post_init__(self):
        url = urlsplit(self.endpoint)
        local = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if url.scheme != "https" and not (url.scheme == "http" and local):
            raise ValueError("model endpoint must use HTTPS (HTTP allowed only on loopback)")
        if not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("endpoint must not contain credentials, query, or fragment")
        if not self.name or not self.model or self.max_tokens <= 0 or self.timeout <= 0:
            raise ValueError("model name, ID and positive token/timeout limits are required")
        if not 0 <= self.temperature <= 2:
            raise ValueError("temperature must be between 0 and 2")
        if not 0 <= self.max_retries <= 10 or self.retry_backoff <= 0:
            raise ValueError("max_retries must be 0-10 and retry_backoff positive")


#: Statuses worth retrying: rate limiting and transient server-side failures.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
MAX_RETRY_AFTER = 60.0


class HTTPTransport:
    def __init__(self, config: ModelConfig, sleep=time.sleep):
        self.config = config
        self.calls: list[dict] = []
        self._sleep = sleep
        if config.api_key_env and not os.environ.get(config.api_key_env):
            raise ValueError(f"missing API key environment variable: {config.api_key_env}")

    def __call__(self, system: str, prompt: str) -> str:
        c = self.config
        headers = {"Content-Type": "application/json"}
        if c.api_key_env:
            headers["Authorization"] = "Bearer " + os.environ[c.api_key_env]
        body = {"model": c.model, "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "max_tokens": c.max_tokens, "temperature": c.temperature}
        payload = json.dumps(body).encode()
        for attempt in range(1, c.max_retries + 2):
            request = Request(c.endpoint, payload, headers, method="POST")
            try:
                with build_opener(NoRedirect).open(request, timeout=c.timeout) as response:
                    data = json.load(response)
                break
            except HTTPError as exc:
                retryable, wait = exc.code in RETRYABLE_STATUS, _retry_after(exc)
                failure = f"model HTTP request failed: status {exc.code}"
            except (URLError, TimeoutError):
                retryable, wait = True, None
                failure = "model request failed or timed out"
            if not retryable or attempt > c.max_retries:
                raise RuntimeError(failure) from None
            self._sleep(wait if wait is not None else c.retry_backoff * 2 ** (attempt - 1))
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"]
            if not isinstance(text, str) or not text.strip():
                raise ValueError
            if choice.get("finish_reason") == "length":
                raise RuntimeError("model output truncated by token limit")
        except (KeyError, IndexError, TypeError, ValueError):
            raise RuntimeError("model returned an invalid chat-completions response") from None
        self.calls.append({"model": data.get("model", c.model), "usage": data.get("usage", {}),
                           "attempts": attempt})
        return text


def _retry_after(exc: HTTPError) -> float | None:
    """A `Retry-After` delay in seconds, capped; None when absent or not a number."""
    try:
        return min(max(float(exc.headers.get("Retry-After", "")), 0.0), MAX_RETRY_AFTER)
    except (TypeError, ValueError, AttributeError):
        return None


def load_models(path: Path, check_credentials: bool = True) -> list[ModelConfig]:
    data = json.loads(path.read_text())
    configs = [ModelConfig(**item) for item in data["models"]]
    if not configs or len({c.name for c in configs}) != len(configs):
        raise ValueError("models must have unique, nonempty names")
    # Validate every credential before starting a potentially expensive campaign.
    if check_credentials:
        for config in configs:
            HTTPTransport(config)
    return configs


def build_model(config: ModelConfig, record: Path | None = None,
                replay: TranscriptStore | None = None) -> LLMGenerator:
    """A live generator, optionally recording its exchanges or replaying a recording."""
    if record and replay:
        raise ValueError("record and replay are mutually exclusive")
    if replay is not None:
        return LLMGenerator(ReplayTransport(replay, config.name), name=f"replay:{config.name}")
    transport = HTTPTransport(config)
    if record is not None:
        transport = RecordingTransport(transport, record, config.name)
    return LLMGenerator(transport, name=f"live:{config.name}")
