"""Harness validation on the real toolchain."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from falsify import benchmark, harness, toolpaths
from falsify.oracle.foundry import FoundryFunctionalTester, FoundryOracle

pytestmark = pytest.mark.integration

_REPO = Path(__file__).resolve().parent.parent
_TASKS = sorted((_REPO / "benchmark" / "tasks").glob("*/*"))
_TASK = _REPO / "benchmark" / "tasks" / "reentrancy" / "task_001"

if not (Path(toolpaths.forge_bin()).exists() or shutil.which(toolpaths.forge_bin())):
    pytest.skip("Foundry not installed", allow_module_level=True)


@pytest.mark.parametrize("task_dir", _TASKS, ids=lambda p: p.name)
def test_every_bundled_harness_is_live_and_discriminating(task_dir):
    task = benchmark.load_task(task_dir)
    report = harness.validate(task_dir, task, FoundryOracle(), FoundryFunctionalTester())
    assert report.ok, harness.render(report)


def broken_copy(tmp_path: Path) -> Path:
    """reentrancy-001 with an exploit whose attacker is never funded: it can never profit."""
    task_dir = tmp_path / "task"
    shutil.copytree(_TASK, task_dir)
    poc = task_dir / "exploits" / "Reentrancy.t.sol"
    text = poc.read_text()
    assert "vm.deal(address(attacker), 1 ether);" in text
    poc.write_text(text.replace("vm.deal(address(attacker), 1 ether);", ""))
    return task_dir


def test_dead_exploit_is_caught(tmp_path):
    task_dir = broken_copy(tmp_path)
    report = harness.validate(task_dir, benchmark.load_task(task_dir), FoundryOracle())
    assert not report.ok and not report.verified
    assert any("known-exploitable" in p for p in report.all_problems())
