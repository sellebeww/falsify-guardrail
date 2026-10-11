"""Guardrail mode: evaluate an existing source against a trusted task harness, no repair.

Before trusting a "not exploited" outcome, the exploits are run on the task's
known-exploitable controls (see `harness`). A harness whose exploits cannot fire blocks
with a tool error instead of passing every candidate.

Strict mode additionally blocks outcomes that pass only because nothing was confirmed:
detector findings no exploit confirmed (ORACLE_GAP) and harnesses without an exploitable
control, whose liveness is unverified.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from falsify import benchmark, harness
from falsify.analysis.base import StaticAnalyzer
from falsify.config import LoopConfig
from falsify.generators.fixture import FixtureGenerator
from falsify.oracle.base import Compiler, FunctionalTester, Oracle
from falsify.orchestrator import Orchestrator, tool_error_record
from falsify.types import EvalRecord, LoopVerdict, ToolVersions

CONTROLS_DOC = "docs/guardrail.md#controls-proving-the-exploit-can-fire"


@dataclass
class Tools:
    analyzer: StaticAnalyzer
    oracle: Oracle
    compiler: Compiler
    tester: FunctionalTester
    versions: ToolVersions = field(default_factory=ToolVersions)


def support_from_root(source: Path, source_root: Path) -> dict[str, str]:
    """Every other `.sol` file under `source_root`, keyed by its relative path."""
    source_root = source_root.resolve()
    if source.resolve().parent != source_root:
        raise ValueError("entry source must be directly inside --source-root")
    return {p.relative_to(source_root).as_posix(): p.read_text()
            for p in source_root.rglob("*.sol") if p.resolve() != source.resolve()}


def check(task_dir: str | Path, source: str, tools: Tools,
          support_sources: dict[str, str] | None = None, strict: bool = False) -> EvalRecord:
    task_dir = Path(task_dir)
    task = benchmark.load_task(task_dir)
    name = "existing-source"

    # Liveness runs on the task's own support files: controls belong to the task.
    declared = any(c.exploitable for c in harness.controls(task_dir))
    if declared:
        live = harness.validate(task_dir, task, tools.oracle, exploitable_only=True)
        if not live.ok:
            return tool_error_record(
                task, name, tools.versions,
                "harness is not live: " + "; ".join(live.all_problems()))

    if support_sources is not None:
        task.support_sources = support_sources
    generator = FixtureGenerator(source, [], task.contract_name, name=name)
    record = Orchestrator(
        generator, tools.analyzer, tools.oracle, tools.compiler, tools.tester,
        config=LoopConfig(max_iterations=0), versions=tools.versions,
    ).run(task)

    if not declared:
        record.notes.append(
            f"exploit liveness unverified: the task declares no exploitable control ({CONTROLS_DOC})")
    if strict and record.gate_pass:
        if record.verdict is LoopVerdict.ORACLE_GAP:
            record.gate_pass = False
            record.notes.append("strict: blocked because detector findings remain unconfirmed")
        elif not declared:
            record.gate_pass = False
            record.notes.append("strict: blocked because exploit liveness is unverified")
    return record
