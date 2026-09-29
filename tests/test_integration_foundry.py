"""End-to-end integration test on the real toolchain (Foundry + Slither).

Skipped automatically if the tools are not installed. This is the executable proof of
the MVP "done" criterion AND the headline result: the detector-silencing repair is
caught as a false fix, and only the genuine fix is accepted.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from falsify import toolpaths

pytestmark = pytest.mark.integration

_REPO = Path(__file__).resolve().parent.parent
_TASK = _REPO / "benchmark" / "tasks" / "reentrancy" / "task_001"


def _have_tools() -> bool:
    forge = toolpaths.forge_bin()
    slither = toolpaths.slither_bin()
    return (os.path.exists(forge) or shutil.which(forge)) and (
        os.path.exists(slither) or shutil.which(slither)
    )


@pytest.mark.skipif(not _have_tools(), reason="Foundry/Slither not installed")
def test_demo_task_catches_false_fix_then_accepts_real_fix():
    from falsify import benchmark
    from falsify.analysis.slither_runner import SlitherAnalyzer
    from falsify.config import LoopConfig
    from falsify.oracle.foundry import FoundryCompiler, FoundryFunctionalTester, FoundryOracle
    from falsify.orchestrator import Orchestrator
    from falsify.types import FindingStatus, LoopVerdict

    task = benchmark.load_task(_TASK)
    orch = Orchestrator(
        generator=benchmark.build_generator(_TASK, strategy="eventually_fixer"),
        analyzer=SlitherAnalyzer(),
        oracle=FoundryOracle(),
        compiler=FoundryCompiler(),
        tester=FoundryFunctionalTester(),
        config=LoopConfig(),
    )
    rec = orch.run(task)

    # The vulnerable contract was really exploitable...
    assert any(f.status is FindingStatus.CONFIRMED for f in rec.findings)
    # ...the assembly "fix" silenced Slither but was caught as a false fix...
    assert rec.false_fixes >= 1
    # ...and the checks-effects-interactions fix was accepted.
    assert rec.verdict is LoopVerdict.SUCCESS
    assert rec.gate_pass is True
    assert rec.repairs[-1].outcome.value == "accepted"


@pytest.mark.skipif(not _have_tools(), reason="Foundry/Slither not installed")
def test_benchmark_shows_false_fixes_and_a_false_positive():
    """The headline study result, on real tooling: a Slither-only gate would approve
    still-exploitable contracts (FN) and block a safe one (FP); Falsify gets both right."""
    from falsify import evaluator

    result = evaluator.run_benchmark(_REPO / "benchmark" / "tasks")
    c = result.confusion()
    assert c.fn >= 3  # RQ1: detector-silencing false fixes + blind spots a Slither-gate approves
    assert c.fp >= 1  # RQ2: a Slither false positive the oracle refuses to confirm

    per_strategy = result.per_strategy()
    assert per_strategy["detector_gamer"]["success"] == 0      # gaming never yields a real fix
    assert per_strategy["eventually_fixer"]["success"] == 7
    assert per_strategy["proper_fixer"]["success"] == 7        # real fixes are accepted


@pytest.mark.skipif(not _have_tools(), reason="Foundry/Slither not installed")
@pytest.mark.parametrize("task_dir", sorted((_REPO / "benchmark/tasks").glob("*/*")))
def test_reference_controls_have_functional_coverage(task_dir):
    from falsify import benchmark
    from falsify.oracle.foundry import FoundryFunctionalTester
    from falsify.types import GeneratedArtifact

    task = benchmark.load_task(task_dir)
    for role in benchmark._meta(task_dir)["roles"]:
        artifact = GeneratedArtifact(task.id, "reference", benchmark.role_source(task_dir, role),
                                     task.contract_name, support_sources=task.support_sources)
        result = FoundryFunctionalTester().run(artifact, task)
        assert result.passed, result.failures
        assert result.coverage["available"], result.coverage
        assert result.coverage["lines_found"] > 0
        assert result.coverage["functions_hit"] > 0


@pytest.mark.skipif(not _have_tools(), reason="Foundry/Slither not installed")
def test_check_cli_blocks_vulnerable_and_passes_fixed(tmp_path):
    import json

    from falsify.cli import main

    for role, expected in [("vulnerable", 1), ("fixed", 0)]:
        out = tmp_path / f"{role}.json"
        code = main(["check", "--task", str(_TASK), "--source",
                     str(_TASK / "reference" / f"Vault_{role}.sol"), "--out", str(out)])
        assert code == expected
        assert json.loads(out.read_text())["gate_pass"] == (expected == 0)
