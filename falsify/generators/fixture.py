"""Deterministic fixture/replay generator (plan §9).

Emits a recorded initial contract, then a scripted sequence of repair contracts.
This makes `make demo` fully offline and reproducible (no API key, no nondeterminism)
while exercising the exact same loop the live LLM adapter drives.
"""

from __future__ import annotations

from falsify.generators.base import RepairContext
from falsify.types import GeneratedArtifact


class FixtureGenerator:
    def __init__(
        self,
        initial_source: str,
        repair_sources: list[str],
        contract_name: str,
        name: str = "fixture",
    ) -> None:
        self.name = name
        self._initial = initial_source
        self._repairs = list(repair_sources)
        self._contract = contract_name
        self._i = 0

    def generate(self, nl_spec: str, contract_name: str, solc_pragma: str) -> GeneratedArtifact:
        return GeneratedArtifact(
            task_id="fixture",
            model=self.name,
            source=self._initial,
            contract_name=contract_name or self._contract,
        )

    def repair(self, ctx: RepairContext) -> GeneratedArtifact:
        # Clamp at the last scripted repair so the loop's own stopping conditions
        # (not an index error) decide termination.
        src = self._repairs[min(self._i, len(self._repairs) - 1)] if self._repairs else ctx.current_source
        self._i += 1
        return GeneratedArtifact(
            task_id=ctx.task_id,
            model=self.name,
            source=src,
            contract_name=ctx.contract_name,
        )
