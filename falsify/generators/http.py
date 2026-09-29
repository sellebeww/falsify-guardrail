"""Bounded HTTP transport for chat-completions servers (including local vLLM)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from falsify.generators.llm import LLMGenerator


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


class HTTPTransport:
    def __init__(self, config: ModelConfig):
        self.config = config
        self.calls: list[dict] = []
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
        request = Request(c.endpoint, json.dumps(body).encode(), headers, method="POST")
        try:
            with build_opener(NoRedirect).open(request, timeout=c.timeout) as response:
                data = json.load(response)
        except HTTPError as exc:
            raise RuntimeError(f"model HTTP request failed: status {exc.code}") from None
        except (URLError, TimeoutError):
            raise RuntimeError("model request failed or timed out") from None
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"]
            if not isinstance(text, str) or not text.strip():
                raise ValueError
            if choice.get("finish_reason") == "length":
                raise RuntimeError("model output truncated by token limit")
        except (KeyError, IndexError, TypeError, ValueError):
            raise RuntimeError("model returned an invalid chat-completions response") from None
        self.calls.append({"model": data.get("model", c.model), "usage": data.get("usage", {})})
        return text


def load_models(path: Path) -> list[ModelConfig]:
    data = json.loads(path.read_text())
    configs = [ModelConfig(**item) for item in data["models"]]
    if not configs or len({c.name for c in configs}) != len(configs):
        raise ValueError("models must have unique, nonempty names")
    # Validate every credential before starting a potentially expensive campaign.
    for config in configs:
        HTTPTransport(config)
    return configs


def build_model(config: ModelConfig) -> LLMGenerator:
    return LLMGenerator(HTTPTransport(config), name=f"live:{config.name}")
