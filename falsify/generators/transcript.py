"""Record live model exchanges and replay them offline.

A recorded campaign can be re-evaluated without network access, credentials or spend,
for example after a change to the oracle or the scoring. Entries are keyed by model name and
a hash of the exact system and user prompt. Repair prompts embed the previous response, so
a replay follows the recorded conversation and diverges loudly if anything changed.

Responses for an identical prompt are consumed in recording order, so repetitions replay
their own responses rather than the first one again. A prompt with no remaining recorded
response is an error, never an empty generation.

The transcript is JSON Lines. It contains prompts (task specification and contract source)
and responses, never credentials.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from pathlib import Path

from falsify.generators.llm import Transport


def prompt_key(model: str, system: str, prompt: str) -> str:
    return hashlib.sha256(json.dumps([model, system, prompt]).encode()).hexdigest()


class RecordingTransport:
    """Pass calls through to a live transport and append each exchange to `path`."""

    def __init__(self, inner: Transport, path: str | Path, model: str) -> None:
        self._inner = inner
        self._path = Path(path)
        self._model = model
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def calls(self) -> list[dict]:
        return getattr(self._inner, "calls", [])

    def __call__(self, system: str, prompt: str) -> str:
        text = self._inner(system, prompt)
        usage = self.calls[-1].get("usage", {}) if self.calls else {}
        entry = {"model": self._model, "key": prompt_key(self._model, system, prompt),
                 "response": text, "usage": usage}
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return text


class TranscriptStore:
    """Recorded responses, shared by every replay transport of one campaign."""

    def __init__(self, path: str | Path) -> None:
        self._entries: dict[tuple[str, str], deque[dict]] = defaultdict(deque)
        for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                self._entries[(entry["model"], entry["key"])].append(entry)
            except (json.JSONDecodeError, KeyError, TypeError):
                raise ValueError(f"invalid transcript entry on line {n}") from None

    def models(self) -> set[str]:
        return {model for model, _ in self._entries}

    def take(self, model: str, system: str, prompt: str) -> dict:
        queue = self._entries.get((model, prompt_key(model, system, prompt)))
        if not queue:
            raise RuntimeError(f"transcript has no remaining response for this prompt "
                               f"(model {model}); the run diverged from the recording")
        return queue.popleft()


class ReplayTransport:
    def __init__(self, store: TranscriptStore, model: str) -> None:
        self._store = store
        self._model = model
        self.calls: list[dict] = []

    def __call__(self, system: str, prompt: str) -> str:
        entry = self._store.take(self._model, system, prompt)
        self.calls.append({"model": self._model, "usage": entry.get("usage", {}),
                           "replayed": True})
        return entry["response"]
