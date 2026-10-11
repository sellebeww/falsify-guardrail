"""Falsify CLI.

  falsify demo                     run the bundled reentrancy task offline (fixture generator)
  falsify run --task DIR           run any task; --generator fixture|replay|live
  falsify bench                    all strategies x all tasks (benchmark mode)
  falsify echidna --task DIR       run a task's Echidna invariant (independent oracle)
  falsify validate-task --task DIR check exploits fire on exploitable controls only
  falsify check --task DIR --source FILE
                                   gate an existing contract; --strict, --sarif, --summary

For `check` and `run`, the exit code is the guardrail signal: 0 if the contract passes the
confirmed-exploit gate, 1 if it is blocked.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from falsify import __version__, benchmark, evaluator, versions
from falsify.analysis.slither_runner import SlitherAnalyzer
from falsify.artifacts import write_benchmark, write_record
from falsify.config import LoopConfig
from falsify.oracle.foundry import FoundryCompiler, FoundryFunctionalTester, FoundryOracle
from falsify.orchestrator import Orchestrator
from falsify.scoring.report import render_benchmark, render_record

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_TASK = _REPO_ROOT / "benchmark" / "tasks" / "reentrancy" / "task_001"


def _run_task(task_dir: Path, generator_kind: str, out: Path | None,
              models_path=None, model_name=None, record=None, replay=None) -> int:
    task = benchmark.load_task(task_dir)

    if generator_kind == "live":
        from falsify.generators.http import build_model, load_models
        from falsify.generators.transcript import TranscriptStore

        if models_path is None:
            raise ValueError("--models is required for live generation")
        configs = load_models(models_path, check_credentials=replay is None)
        selected = [c for c in configs if c.name == model_name] if model_name else configs
        if len(selected) != 1:
            raise ValueError("choose exactly one model using --model")
        generator = build_model(selected[0], record=record,
                                replay=TranscriptStore(replay) if replay else None,
                                slot=f"{task.id}#1")
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
               repetitions=1, max_iterations=5, record=None, replay=None, jobs=1) -> int:
    print(f"Running Falsify benchmark over {tasks_root} ...\n")
    out = out or (
        _REPO_ROOT
        / "results"
        / f"benchmark-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    from falsify.generators.http import load_models

    models = load_models(models_path, check_credentials=replay is None) if models_path else None
    result = evaluator.run_benchmark(
        tasks_root, models=models, repetitions=repetitions,
        config=LoopConfig(max_iterations=max_iterations), checkpoint=out,
        record_path=record, replay_path=replay, jobs=jobs,
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
        expected = role == "good_fix" or "good_fix" not in benchmark.task_meta(task_dir)["roles"]
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


def _validate_task(task_dir: Path) -> int:
    from falsify import harness

    task = benchmark.load_task(task_dir)
    report = harness.validate(task_dir, task, FoundryOracle(), FoundryFunctionalTester())
    print(harness.render(report) + "\n")
    return 0 if report.ok else 1


def _check(task_dir: Path, source: Path, source_root: Path | None, out: Path,
           strict: bool = False, sarif: Path | None = None,
           summary: Path | None = None) -> int:
    import json

    from falsify import guardrail
    from falsify.scoring.report import render_markdown
    from falsify.scoring.sarif import to_sarif

    tools = guardrail.Tools(SlitherAnalyzer(), FoundryOracle(), FoundryCompiler(),
                            FoundryFunctionalTester(), versions.capture())
    support = guardrail.support_from_root(source, source_root) if source_root else None
    record = guardrail.check(task_dir, source.read_text(), tools, support, strict=strict)
    write_record(record, out)
    if sarif:
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_text(json.dumps(to_sarif(record, _repo_relative(source)), indent=2) + "\n")
    if summary:
        summary.parent.mkdir(parents=True, exist_ok=True)
        with summary.open("a", encoding="utf-8") as fh:  # appendable, like a CI job summary
            fh.write(render_markdown(record))
    print(render_record(record))
    print(f"Artifact: {out}")
    return 0 if record.gate_pass else 1


def _repo_relative(path: Path) -> str:
    """A POSIX path relative to the working directory when possible, as SARIF expects."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _transcript_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--record", type=Path,
                       help="append live model exchanges to this JSONL transcript")
    group.add_argument("--replay", type=Path,
                       help="replay a recorded transcript offline (no network or credentials)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="falsify", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"falsify {__version__}")
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
    _transcript_args(run)

    bench = sub.add_parser("bench", help="run all strategies across all tasks (benchmark mode)")
    bench.add_argument("--tasks", type=Path, default=_REPO_ROOT / "benchmark" / "tasks")
    bench.add_argument("--out", type=Path, default=None)
    bench.add_argument("--models", type=Path, help="JSON live model configurations")
    bench.add_argument("--repetitions", type=int, default=1)
    bench.add_argument("--max-iterations", type=int, default=5)
    bench.add_argument("--jobs", type=int, default=1,
                       help="run independent task/model/repetition combinations in parallel")
    _transcript_args(bench)

    ech = sub.add_parser("echidna", help="run a task's Echidna invariant (independent oracle)")
    ech.add_argument(
        "--task",
        type=Path,
        default=_REPO_ROOT / "benchmark" / "tasks" / "access_control" / "task_002_takeover",
    )

    ech.add_argument("--all", action="store_true", help="cross-check every bundled task")

    val = sub.add_parser("validate-task",
                         help="check that a task's exploits fire on known-exploitable controls "
                              "and stay silent on known-safe ones")
    val.add_argument("--task", type=Path, action="append", default=[])
    val.add_argument("--all", action="store_true", help="validate every bundled task")

    check = sub.add_parser("check", help="vet an existing contract against a trusted task harness")
    check.add_argument("--task", type=Path, required=True)
    check.add_argument("--source", type=Path, required=True)
    check.add_argument("--source-root", type=Path)
    check.add_argument("--out", type=Path, default=Path("results/guardrail.json"))
    check.add_argument("--strict", action="store_true",
                       help="also block unconfirmed detector findings and unverified harnesses")
    check.add_argument("--sarif", type=Path, help="also write SARIF 2.1.0 for code scanning")
    check.add_argument("--summary", type=Path,
                       help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")

    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return _run_task(_DEFAULT_TASK, "fixture", None)
    if args.cmd == "run":
        return _run_task(args.task, args.generator, args.out, args.models, args.model,
                         args.record, args.replay)
    if args.cmd == "bench":
        return _run_bench(args.tasks, args.out, args.models, args.repetitions,
                          args.max_iterations, args.record, args.replay, args.jobs)
    if args.cmd == "validate-task":
        tasks = args.task + (benchmark.discover_tasks(_REPO_ROOT / "benchmark/tasks")
                             if args.all else [])
        if not tasks:
            parser.error("validate-task needs --task DIR or --all")
        return max(_validate_task(t) for t in tasks)
    if args.cmd == "check":
        return _check(args.task, args.source, args.source_root, args.out, args.strict,
                      args.sarif, args.summary)
    if args.cmd == "echidna":
        if args.all:
            codes = [_run_echidna(t) for t in benchmark.discover_tasks(_REPO_ROOT / "benchmark/tasks")]
            return max(codes, default=2)
        return _run_echidna(args.task)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
