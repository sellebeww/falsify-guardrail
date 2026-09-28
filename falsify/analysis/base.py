"""Static analysis interface.

Slither is fast and noisy: it produces *candidate* findings only. Nothing here
is ever a final security gate (plan §5) — confirmation is the oracle's job.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from falsify.types import Finding, GeneratedArtifact


@runtime_checkable
class StaticAnalyzer(Protocol):
    name: str

    def analyze(self, artifact: GeneratedArtifact) -> list[Finding]:
        """Return candidate findings (status = CANDIDATE)."""
        ...
