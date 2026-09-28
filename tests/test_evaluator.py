"""Unit tests for benchmark aggregation (synthetic records; no toolchain)."""

from __future__ import annotations

from falsify.evaluator import BenchmarkResult, RunResult
from falsify.types import (
    EvalRecord,
    ExploitResult,
    Finding,
    FindingStatus,
    LoopVerdict,
    RepairAttempt,
    RepairOutcome,
    Severity,
    ToolVersions,
    VulnClass,
)

RE = VulnClass.REENTRANCY
AC = VulnClass.ACCESS_CONTROL


def _confirmed(cat: VulnClass) -> Finding:
    return Finding(
        id="f", detector="slither:x", swc_class=cat, severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
    )


def _exp(cat: VulnClass, ok: bool) -> ExploitResult:
    return ExploitResult(poc_id="p", swc_class=cat, success=ok)


def _record(task, cat, verdict, gate, false_fixes, init_hash, attempts) -> EvalRecord:
    return EvalRecord(
        task_id=task, category=cat, model="m", versions=ToolVersions(),
        verdict=verdict, gate_pass=gate, false_fixes=false_fixes,
        findings=[_confirmed(cat)], initial_exploits=[_exp(cat, True)],
        initial_source_hash=init_hash, repairs=attempts,
    )


def _make_result() -> BenchmarkResult:
    # reentrancy eventually_fixer: vuln(TP) -> bad(FN) -> good(TN)
    re_run = _record(
        "re", RE, LoopVerdict.SUCCESS, True, 1, "re_vuln",
        [
            RepairAttempt(1, "re_bad", RepairOutcome.REJECTED,
                          exploit_results=[_exp(RE, True)], detector_classes=[]),   # FN
            RepairAttempt(2, "re_good", RepairOutcome.ACCEPTED,
                          exploit_results=[_exp(RE, False)], detector_classes=[]),   # TN
        ],
    )
    # access-control proper_fixer: vuln(TP) -> good but Slither still flags + safe (FP)
    ac_run = _record(
        "ac", AC, LoopVerdict.SUCCESS, True, 0, "ac_vuln",
        [
            RepairAttempt(1, "ac_good", RepairOutcome.ACCEPTED,
                          exploit_results=[_exp(AC, False)], detector_classes=[AC]),  # FP
        ],
    )
    return BenchmarkResult(runs=[
        RunResult("eventually_fixer", "re", RE, re_run),
        RunResult("proper_fixer", "ac", AC, ac_run),
    ])


def test_confusion_matrix_covers_all_cells():
    c = _make_result().confusion()
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 1)


def test_per_strategy_counts():
    ps = _make_result().per_strategy()
    assert ps["eventually_fixer"]["success"] == 1
    assert ps["eventually_fixer"]["false_fixes"] == 1
    assert ps["proper_fixer"]["success"] == 1
    assert ps["proper_fixer"]["false_fixes"] == 0


def test_pareto_has_a_point_per_category():
    pareto = _make_result().pareto_by_category()
    assert set(pareto) == {"reentrancy", "access_control"}
    assert pareto["reentrancy"][0].security == 1.0


def test_states_dedupe_by_hash():
    # Two runs sharing the same initial contract hash count that state once.
    r = _make_result()
    dup = RunResult("detector_gamer", "re", RE, r.runs[0].record)
    r.runs.append(dup)
    # Confusion is unchanged because states are deduped by (task_id, source_hash).
    assert (r.confusion().tp, r.confusion().fn) == (2, 1)
