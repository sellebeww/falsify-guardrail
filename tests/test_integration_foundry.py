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
    assert per_strategy["proper_fixer"]["success"] >= 3        # real fixes are accepted
