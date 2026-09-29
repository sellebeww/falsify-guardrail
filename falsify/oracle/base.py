"""Oracle + toolchain interfaces.

The Oracle is the falsification engine: it runs deterministic PoC exploits against
a contract and reports which succeed. "Exploit failed" means UNCONFIRMED, never
SECURE (plan §3, §10). Compiler and FunctionalTester model the Foundry side used
by the repair-acceptance predicate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from falsify.types import ExploitResult, GasProfile, GeneratedArtifact, TaskSpec, VulnClass


@dataclass
class CompileResult:
    ok: bool
    error: str = ""


@dataclass
class FunctionalResult:
    passed: bool
    failures: list[str] = field(default_factory=list)  # failing test names
    gas: GasProfile = field(default_factory=GasProfile)
    coverage: dict = field(default_factory=dict)


@runtime_checkable
class Compiler(Protocol):
    def compile(self, artifact: GeneratedArtifact, solc_pragma: str) -> CompileResult:
        ...


@runtime_checkable
class FunctionalTester(Protocol):
    """Runs the human-owned functional suite for a task against a candidate contract."""

    def run(self, artifact: GeneratedArtifact, task: TaskSpec) -> FunctionalResult:
        ...


@runtime_checkable
class Oracle(Protocol):
    """Runs the deterministic PoC battery. Independent of the model under test."""

    def covered_classes(self) -> set[VulnClass]:
        """Vuln classes this oracle has at least one PoC template for."""
        ...

    def run(self, artifact: GeneratedArtifact, task: TaskSpec) -> list[ExploitResult]:
        """Run every applicable PoC against `artifact`; one ExploitResult per PoC."""
        ...
