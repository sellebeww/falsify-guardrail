"""Generator interface (LLM adapter boundary).

The interface is deliberately narrow. Generation sees only the natural-language
spec; repair sees only a *minimal* feedback context (RepairContext) that, by
construction, cannot contain PoC source or invariants. This enforces the
anti-circularity rule in plan §4 at the type level rather than by convention.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from falsify.types import GeneratedArtifact, VulnClass


@dataclass
class RepairContext:
    """The ONLY information a repair step receives.

    Note what is absent: no PoC source, no invariant source, no functional test
    source, no reference implementation. Only the signals a human reviewer would
    hand a developer: "this class of bug is confirmed exploitable; the detector
    said X; these functional behaviours broke."
    """

    task_id: str
    contract_name: str
    solc_pragma: str
    nl_spec: str
    current_source: str
    iteration: int
    confirmed_classes: list[VulnClass] = field(default_factory=list)
    slither_findings: list[str] = field(default_factory=list)  # human-readable text only
    exploit_confirmed: bool = False
    functional_failures: list[str] = field(default_factory=list)  # test names only
    last_reject_reason: str | None = None  # why the previous attempt was rejected


@runtime_checkable
class Generator(Protocol):
    """An LLM (or fixture/replay) source of contracts."""

    name: str

    def generate(self, nl_spec: str, contract_name: str, solc_pragma: str) -> GeneratedArtifact:
        ...

    def repair(self, ctx: RepairContext) -> GeneratedArtifact:
        ...
