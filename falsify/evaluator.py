"""Compare fixture strategies or live generators on identical task specifications.

Confusion counts describe agreement with the supplied exploit battery. A negative
oracle result is unconfirmed, not proof of safety. Invalid states are excluded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from falsify import benchmark, versions
from falsify.analysis.slither_runner import SlitherAnalyzer
from falsify.config import LoopConfig
from falsify.oracle.foundry import FoundryCompiler, FoundryFunctionalTester, FoundryOracle
from falsify.orchestrator import Orchestrator
from falsify.scoring.pareto import ParetoPoint, frontier
from falsify.types import EvalRecord, FindingStatus, LoopVerdict, VulnClass


@dataclass
class RunResult:
    strategy: str
    task_id: str
    category: VulnClass
    record: EvalRecord
    repetition: int = 1


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0


@dataclass
class BenchmarkResult:
    runs: list[RunResult] = field(default_factory=list)
    mode: str = "fixture"
    model_configs: list[dict] = field(default_factory=list)

    # -- supplied exploits vs Slither, over distinct contract states -------------- #
    def confusion(self) -> Confusion:
        seen: dict[tuple[str, str], tuple[bool, bool]] = {}
        for run in self.runs:
            for key, flags, exploitable in _states(run):
                seen.setdefault(key, (flags, exploitable))
        c = Confusion()
        for flags, exploitable in seen.values():
            if flags and exploitable:
                c.tp += 1
            elif flags and not exploitable:
                c.fp += 1
            elif not flags and exploitable:
                c.fn += 1
            else:
                c.tn += 1
        return c

    def per_strategy(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for run in self.runs:
            s = out.setdefault(
                run.strategy, {"success": 0, "blocked": 0, "false_fixes": 0, "runs": 0,
                               "initial_gate_pass": 0, "tool_errors": 0}
            )
            s["runs"] += 1
            if run.record.verdict in (LoopVerdict.CLEAN, LoopVerdict.ORACLE_GAP):
                s["initial_gate_pass"] += 1
            if run.record.verdict is LoopVerdict.TOOL_ERROR:
                s["tool_errors"] += 1
            s["false_fixes"] += run.record.false_fixes
            if run.record.verdict is LoopVerdict.SUCCESS:
                s["success"] += 1
            elif not run.record.gate_pass:
                s["blocked"] += 1
        return out

    def pareto_by_category(self) -> dict[str, list[ParetoPoint]]:
        if self.mode == "live":
            return {}  # generated baselines differ across models; see docs/benchmarking.md
        # Only tasks that actually have a confirmed exploit to fix count toward a
        # strategy's security score; RQ2 false-positive tasks (nothing to fix) are excluded.
        needs_fix: dict[VulnClass, set[str]] = {}
        for run in self.runs:
            if any(r.success for r in run.record.initial_exploits):
                needs_fix.setdefault(run.category, set()).add(run.task_id)
        out: dict[str, list[ParetoPoint]] = {}
        for cat, task_ids in needs_fix.items():
            points: list[ParetoPoint] = []
            for strat in sorted({r.strategy for r in self.runs}):
                runs = [
                    r
                    for r in self.runs
                    if r.category is cat and r.strategy == strat and r.task_id in task_ids
                ]
                succ = [r for r in runs if r.record.verdict is LoopVerdict.SUCCESS]
                security = len(succ) / len(runs) if runs else 0.0
                gas = sum(r.record.gas_tax_total() for r in succ) / len(succ) if succ else 0.0
                points.append(ParetoPoint(label=strat, security=security, gas=gas))
            out[cat.value] = frontier(points)
        return out


def _states(run: RunResult):
    """Yield ((task_id, source_hash), slither_flags_category, oracle_exploitable) per state."""
    cat, rec = run.category, run.record
    if not rec.initial_exploits or any(not r.executed for r in rec.initial_exploits):
        return
    yield (
        (rec.task_id, rec.initial_source_hash),
        # The Slither column must reflect only what SLITHER flagged — exclude
        # oracle-discovered findings (detector "oracle:*"), or they inflate the detector's
        # apparent coverage and hide its false negatives.
        any(
            f.swc_class is cat
            and f.status in (FindingStatus.CONFIRMED, FindingStatus.UNCONFIRMED)
            and f.detector.startswith("slither")
            for f in rec.findings
        ),
        any(r.success and r.swc_class is cat for r in rec.initial_exploits),
    )
    for a in rec.repairs:
        if not a.exploit_results or any(not r.executed for r in a.exploit_results):
            continue
        yield (
            (rec.task_id, a.source_hash),
            cat in a.detector_classes,
            any(r.success and r.swc_class is cat for r in a.exploit_results),
        )


def run_benchmark(
    tasks_root: str | Path,
    strategies: list[str] | None = None,
    config: LoopConfig | None = None,
    models=None,
    repetitions: int = 1,
    checkpoint: Path | None = None,
) -> BenchmarkResult:
    from dataclasses import asdict

    from falsify.artifacts import write_benchmark
    from falsify.generators.http import build_model

    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    strategies = strategies or list(benchmark.STRATEGIES)
    config = config or LoopConfig()
    vers = versions.capture()
    result = BenchmarkResult(mode="live" if models else "fixture",
                             model_configs=[asdict(m) for m in models] if models else [])
    task_dirs = benchmark.discover_tasks(tasks_root)
    if not task_dirs:
        raise ValueError("no benchmark tasks found")
    for task_dir in task_dirs:
        task = benchmark.load_task(task_dir)
        for entry in models or strategies:
            for repetition in range(1, repetitions + 1):
                generator = (build_model(entry) if models else
                             benchmark.build_generator(task_dir, entry))
                orch = Orchestrator(
                    generator=generator, analyzer=SlitherAnalyzer(), oracle=FoundryOracle(),
                    compiler=FoundryCompiler(), tester=FoundryFunctionalTester(),
                    config=config, versions=vers,
                )
                record = orch.run(task)
                result.runs.append(RunResult(entry.name if models else entry, task.id,
                                             task.category, record, repetition))
                if checkpoint:
                    write_benchmark(result, checkpoint)
    return result
