"""Falsify CLI (plan §8 MVP, §dual-mode).

  falsify demo                 run the bundled reentrancy task offline (fixture generator)
  falsify run --task DIR       run any task; --generator fixture|replay
  falsify bench                all strategies x all tasks (benchmark mode)
  falsify echidna --task DIR   run a task's Echidna invariant (independent oracle)

Exit code is the guardrail signal: 0 if the contract passes the confirmed-exploit gate,
1 if it is blocked (a confirmed exploit remains).
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from falsify import benchmark, evaluator, versions
from falsify.analysis.slither_runner import SlitherAnalyzer
from falsify.artifacts import write_benchmark, write_record
from falsify.config import LoopConfig
from falsify.oracle.foundry import FoundryCompiler, FoundryFunctionalTester, FoundryOracle
from falsify.orchestrator import Orchestrator
from falsify.scoring.report import render_benchmark, render_record

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_TASK = _REPO_ROOT / "benchmark" / "tasks" / "reentrancy" / "task_001"


def _run_task(task_dir: Path, generator_kind: str, out: Path | None,
              models_path=None, model_name=None) -> int:
    task = benchmark.load_task(task_dir)

    if generator_kind == "live":
        from falsify.generators.http import build_model, load_models

        if models_path is None:
            raise ValueError("--models is required for live generation")
        configs = load_models(models_path)
        selected = [c for c in configs if c.name == model_name] if model_name else configs
        if len(selected) != 1:
            raise ValueError("choose exactly one model using --model")
        generator = build_model(selected[0])
    elif generator_kind == "replay":
        generator = benchmark.build_replay_generator(task_dir)
    else:
        generator = benchmark.build_generator(task_dir)

    orch = Orchestrator(
        generator=generator,
        analyzer=SlitherAnalyzer(),
        oracle=FoundryOracle(),
        compiler=FoundryCompiler(),
        tester=FoundryFunctionalTester(),
        config=LoopConfig(),
        versions=versions.capture(),
    )
    print(f"Running Falsify on {task.id} with generator '{generator.name}' ...\n")
    record = orch.run(task)

    out = out or (
        _REPO_ROOT
        / "results"
        / f"{task.id}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    write_record(record, out)
    print(render_record(record))
    print(f"\nArtifact: {out}")
    return 0 if record.gate_pass else 1


def _run_bench(tasks_root: Path, out: Path | None, models_path=None,
               repetitions=1, max_iterations=5) -> int:
    print(f"Running Falsify benchmark over {tasks_root} ...\n")
    out = out or (
        _REPO_ROOT
        / "results"
        / f"benchmark-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    from falsify.generators.http import load_models

    result = evaluator.run_benchmark(
        tasks_root, models=load_models(models_path) if models_path else None,
        repetitions=repetitions, config=LoopConfig(max_iterations=max_iterations), checkpoint=out,
    )
    write_benchmark(result, out)
    print(render_benchmark(result))
    print(f"\nArtifact: {out}")
    return 2 if any(r.record.verdict.value == "tool_error" for r in result.runs) else 0


def _run_echidna(task_dir: Path) -> int:
    from falsify.analysis.echidna_runner import EchidnaChecker

    task = benchmark.load_task(task_dir)
    prop = benchmark.echidna_property(task_dir)
    if prop is None:
        print(f"Task {task.id} defines no Echidna invariant (no 'echidna' block in task.json).")
        return 2
    checker = EchidnaChecker()
    if not checker.available():
        print("Echidna is not installed. Install it with: brew install echidna")
        return 2

    prop_src, prop_contract = prop
    meta_roles = ["initial", "good_fix"]
    print(f"Echidna invariant cross-check for {task.id} ('{prop_contract}'):\n")
    failed = False
    for role in meta_roles:
        try:
            src = benchmark.role_source(task_dir, role)
        except KeyError:
            continue
        res = checker.run(src, task.contract_name, prop_src, prop_contract, task.solc_pragma,
                          support_sources=task.support_sources)
        expected = role == "good_fix" or "good_fix" not in benchmark._meta(task_dir)["roles"]
        failed |= not res.properties or res.passed != expected
        if not res.properties:
            verdict = "ERROR (no property results)"
        elif res.passed:
            verdict = "HELD (no violation found)"
        else:
            verdict = f"FALSIFIED -> {', '.join(res.failed_properties) or 'unknown'}"
        print(f"  {role:10} invariant {verdict}")
    print(
        "\nEchidna is an independent, human-authored oracle (report-only); the loop's gate "
        "remains the Foundry PoC."
    )
    return 1 if failed else 0


def _check(task_dir: Path, source: Path, source_root: Path | None, out: Path) -> int:
    from falsify.generators.fixture import FixtureGenerator

    task = benchmark.load_task(task_dir)
    if source_root:
        source_root = source_root.resolve()
        if source.resolve().parent != source_root:
            raise ValueError("entry source must be directly inside --source-root")
        task.support_sources = {
            p.relative_to(source_root).as_posix(): p.read_text()
            for p in source_root.rglob("*.sol") if p.resolve() != source.resolve()
        }
    generator = FixtureGenerator(source.read_text(), [], task.contract_name, name="existing-source")
    record = Orchestrator(
        generator, SlitherAnalyzer(), FoundryOracle(), FoundryCompiler(),
        FoundryFunctionalTester(), config=LoopConfig(max_iterations=0),
        versions=versions.capture(),
    ).run(task)
    write_record(record, out)
    print(render_record(record))
    print(f"Artifact: {out}")
    return 0 if record.gate_pass else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="falsify", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="run the bundled reentrancy task offline")

    run = sub.add_parser("run", help="run a benchmark task")
    run.add_argument("--task", type=Path, default=_DEFAULT_TASK)
    run.add_argument(
        "--generator", choices=["fixture", "replay", "live"], default="fixture"
    )
    run.add_argument("--out", type=Path, default=None)
    run.add_argument("--models", type=Path)
    run.add_argument("--model")

    bench = sub.add_parser("bench", help="run all strategies across all tasks (benchmark mode)")
    bench.add_argument("--tasks", type=Path, default=_REPO_ROOT / "benchmark" / "tasks")
    bench.add_argument("--out", type=Path, default=None)
    bench.add_argument("--models", type=Path, help="JSON live model configurations")
    bench.add_argument("--repetitions", type=int, default=1)
    bench.add_argument("--max-iterations", type=int, default=5)

    ech = sub.add_parser("echidna", help="run a task's Echidna invariant (independent oracle)")
    ech.add_argument(
        "--task",
        type=Path,
        default=_REPO_ROOT / "benchmark" / "tasks" / "access_control" / "task_002_takeover",
    )

    ech.add_argument("--all", action="store_true", help="cross-check every bundled task")

    check = sub.add_parser("check", help="vet an existing contract against a trusted task harness")
    check.add_argument("--task", type=Path, required=True)
    check.add_argument("--source", type=Path, required=True)
    check.add_argument("--source-root", type=Path)
    check.add_argument("--out", type=Path, default=Path("results/guardrail.json"))

    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return _run_task(_DEFAULT_TASK, "fixture", None)
    if args.cmd == "run":
        return _run_task(args.task, args.generator, args.out, args.models, args.model)
    if args.cmd == "bench":
        return _run_bench(args.tasks, args.out, args.models, args.repetitions, args.max_iterations)
    if args.cmd == "check":
        return _check(args.task, args.source, args.source_root, args.out)
    if args.cmd == "echidna":
        if args.all:
            codes = [_run_echidna(t) for t in benchmark.discover_tasks(_REPO_ROOT / "benchmark/tasks")]
            return max(codes, default=2)
        return _run_echidna(args.task)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
