"""In-memory fakes for the injected tools, so the loop is testable with no
blockchain toolchain. Behaviour is driven by the contract *source string*, which
tests use as a readable tag (e.g. "VULN", "FIXED", "SILENCED").
"""

from __future__ import annotations

from falsify.generators.base import RepairContext
from falsify.oracle.base import CompileResult, FunctionalResult
from falsify.types import (
    ExploitResult,
    Finding,
    GasProfile,
    GeneratedArtifact,
    Severity,
    VulnClass,
)


class ScriptedGenerator:
    """Emits a fixed initial contract then a scripted list of repairs.

    Records every RepairContext it receives so tests can assert the anti-circularity
    boundary (no PoC/invariant source ever reaches the model).
    """

    def __init__(self, initial: str, repairs: list[str], name: str = "scripted") -> None:
        self.name = name
        self._initial = initial
        self._repairs = list(repairs) or [initial]
        self._i = 0
        self.contexts: list[RepairContext] = []

    def generate(self, nl_spec: str, contract_name: str, solc_pragma: str) -> GeneratedArtifact:
        return GeneratedArtifact(
            task_id="task", model=self.name, source=self._initial, contract_name=contract_name
        )

    def repair(self, ctx: RepairContext) -> GeneratedArtifact:
        self.contexts.append(ctx)
        src = self._repairs[min(self._i, len(self._repairs) - 1)]
        self._i += 1
        return GeneratedArtifact(
            task_id=ctx.task_id, model=self.name, source=src, contract_name=ctx.contract_name
        )


class FakeAnalyzer:
    """flagged: source -> list of vuln classes Slither would raise for that source."""

    def __init__(self, flagged: dict[str, list[VulnClass]], name: str = "fake-slither") -> None:
        self.name = name
        self.flagged = flagged

    def analyze(self, artifact: GeneratedArtifact) -> list[Finding]:
        classes = self.flagged.get(artifact.source, [])
        return [
            Finding(
                id=f"{artifact.source}:{c.value}",
                detector=f"slither:{c.value}",
                swc_class=c,
                severity=Severity.HIGH,
                location=f"{artifact.contract_name}.sol",
            )
            for c in classes
        ]


class FakeOracle:
    """registry: poc_id -> vuln class. succeeds: source -> set of poc_ids that succeed."""

    def __init__(self, registry: dict[str, VulnClass], succeeds: dict[str, set[str]]) -> None:
        self.registry = registry
        self.succeeds = succeeds

    def covered_classes(self) -> set[VulnClass]:
        return set(self.registry.values())

    def run(self, artifact: GeneratedArtifact, task) -> list[ExploitResult]:
        winners = self.succeeds.get(artifact.source, set())
        out = []
        for pid, cls in self.registry.items():
            ok = pid in winners
            out.append(
                ExploitResult(
                    poc_id=pid,
                    swc_class=cls,
                    success=ok,
                    gas_used=50_000 if ok else 0,
                )
            )
        return out


class FakeCompiler:
    def __init__(self, noncompiling: frozenset[str] = frozenset()) -> None:
        self.noncompiling = set(noncompiling)

    def compile(self, artifact: GeneratedArtifact, solc_pragma: str) -> CompileResult:
        ok = artifact.source not in self.noncompiling
        return CompileResult(ok=ok, error="" if ok else "CompilerError: expected ';'")


class FakeTester:
    """failing: sources whose functional suite fails. gas: source -> per-fn gas dict."""

    def __init__(
        self, failing: frozenset[str] = frozenset(), gas: dict[str, dict[str, int]] | None = None
    ) -> None:
        self.failing = set(failing)
        self.gas = gas or {}

    def run(self, artifact: GeneratedArtifact, task) -> FunctionalResult:
        passed = artifact.source not in self.failing
        failures = [] if passed else ["test_expected_behaviour"]
        entries = dict(self.gas.get(artifact.source, {"deposit": 21_000, "withdraw": 30_000}))
        return FunctionalResult(passed=passed, failures=failures, gas=GasProfile(entries=entries))
