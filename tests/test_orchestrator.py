"""Behavioural tests for the falsification loop (plan §3).

These run entirely offline with in-memory fakes and are the executable spec for the
project's honesty guarantees:
  * a real fix -> SUCCESS
  * detector silenced but exploit alive -> FALSE FIX, never SUCCESS  (the key one)
  * fixing one hole while opening another -> REJECTED
  * unconfirmed findings -> ORACLE_GAP, never silently "secure"
"""

from __future__ import annotations

import pytest

from falsify.config import LoopConfig
from falsify.orchestrator import Orchestrator
from falsify.types import (
    FindingFate,
    FindingStatus,
    LoopVerdict,
    RejectReason,
    RepairOutcome,
    TaskSpec,
    VulnClass,
)
from tests.fakes import (
    FakeAnalyzer,
    FakeCompiler,
    FakeOracle,
    FakeTester,
    ScriptedGenerator,
)

RE = VulnClass.REENTRANCY
AC = VulnClass.ACCESS_CONTROL


def make_task(category: VulnClass = RE) -> TaskSpec:
    return TaskSpec(
        id="t1",
        category=category,
        nl_spec="A vault with deposit and withdraw.",
        solc_pragma="^0.8.24",
        contract_name="Vault",
    )


def build(generator, analyzer, oracle, compiler=None, tester=None, config=None) -> Orchestrator:
    return Orchestrator(
        generator=generator,
        analyzer=analyzer,
        oracle=oracle,
        compiler=compiler or FakeCompiler(),
        tester=tester or FakeTester(),
        config=config or LoopConfig(),
    )


# --------------------------------------------------------------------------- #
def test_real_fix_is_success():
    gen = ScriptedGenerator(initial="VULN", repairs=["FIXED"])
    analyzer = FakeAnalyzer({"VULN": [RE]})            # FIXED flags nothing
    oracle = FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}})  # FIXED: exploit fails
    rec = build(gen, analyzer, oracle).run(make_task())

    assert rec.verdict is LoopVerdict.SUCCESS
    assert rec.gate_pass is True
    assert rec.false_fixes == 0
    assert [f.status for f in rec.findings] == [FindingStatus.CONFIRMED]
    assert rec.repairs[-1].outcome is RepairOutcome.ACCEPTED
    assert rec.repairs[-1].fates["VULN:reentrancy"] is FindingFate.NEUTRALIZED


def test_detector_silenced_is_false_fix_not_success():
    """THE negative control: repair makes Slither quiet but the PoC still works."""
    gen = ScriptedGenerator(initial="VULN", repairs=["SILENCED"])
    analyzer = FakeAnalyzer({"VULN": [RE]})  # SILENCED: detector raises nothing
    oracle = FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}, "SILENCED": {"poc_re"}})  # still exploitable
    rec = build(gen, analyzer, oracle).run(make_task())

    assert rec.verdict is not LoopVerdict.SUCCESS
    assert rec.verdict in (LoopVerdict.STAGNATION, LoopVerdict.ITER_BUDGET)
    assert rec.gate_pass is False
    assert rec.false_fixes >= 1
    assert all(a.reason is RejectReason.NOT_NEUTRALIZED for a in rec.repairs)
    assert all(
        a.fates["VULN:reentrancy"] is FindingFate.DETECTOR_SILENCED for a in rec.repairs
    )


def test_fixing_one_hole_opening_another_is_rejected():
    gen = ScriptedGenerator(initial="VULN", repairs=["NEWBUG"])
    analyzer = FakeAnalyzer({"VULN": [RE], "NEWBUG": [AC]})
    oracle = FakeOracle(
        {"poc_re": RE, "poc_ac": AC},
        {"VULN": {"poc_re"}, "NEWBUG": {"poc_ac"}},  # original gone, new one opened
    )
    rec = build(gen, analyzer, oracle).run(make_task())

    assert rec.verdict is not LoopVerdict.SUCCESS
    assert rec.repairs[0].reason is RejectReason.NEW_EXPLOIT_REGRESSION


def test_functional_regression_is_rejected():
    gen = ScriptedGenerator(initial="VULN", repairs=["BREAKS"])
    analyzer = FakeAnalyzer({"VULN": [RE]})
    oracle = FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}})  # BREAKS neutralizes exploit
    tester = FakeTester(failing=frozenset({"BREAKS"}))         # ...but breaks behaviour
    rec = build(gen, analyzer, oracle, tester=tester).run(make_task())

    assert rec.verdict is not LoopVerdict.SUCCESS
    assert rec.repairs[0].reason is RejectReason.FUNCTIONAL_REGRESSION


def test_oracle_gap_reports_unconfirmed_not_secure():
    gen = ScriptedGenerator(initial="SUSPICIOUS", repairs=["x"])
    analyzer = FakeAnalyzer({"SUSPICIOUS": [RE]})     # Slither flags it...
    oracle = FakeOracle({"poc_re": RE}, {})           # ...but no PoC confirms it
    rec = build(gen, analyzer, oracle).run(make_task())

    assert rec.verdict is LoopVerdict.ORACLE_GAP
    assert rec.gate_pass is True  # passes the *confirmed-exploit* gate, loudly caveated
    assert [f.status for f in rec.findings] == [FindingStatus.UNCONFIRMED]
    assert any("UNCONFIRMED" in n for n in rec.notes)
    assert not rec.repairs  # nothing confirmed -> loop never ran


def test_oracle_discovers_finding_slither_missed():
    """Slither flags nothing, but the exploit succeeds -> the oracle records a CONFIRMED
    finding Slither missed, and the loop fixes it (catches detector false negatives)."""
    gen = ScriptedGenerator(initial="SNEAKY", repairs=["FIXED"])
    analyzer = FakeAnalyzer({})  # detector silent on everything
    oracle = FakeOracle({"poc_re": RE}, {"SNEAKY": {"poc_re"}})  # exploitable, FIXED is not
    rec = build(gen, analyzer, oracle).run(make_task())

    assert any(
        f.detector == "oracle:poc" and f.status is FindingStatus.CONFIRMED for f in rec.findings
    )
    assert rec.verdict is LoopVerdict.SUCCESS


def test_clean_when_nothing_flagged():
    gen = ScriptedGenerator(initial="CLEAN", repairs=["x"])
    rec = build(gen, FakeAnalyzer({}), FakeOracle({"poc_re": RE}, {})).run(make_task())
    assert rec.verdict is LoopVerdict.CLEAN
    assert rec.gate_pass is True
    assert rec.findings == []


def test_out_of_scope_finding():
    gen = ScriptedGenerator(initial="C", repairs=["x"])
    analyzer = FakeAnalyzer({"C": [AC]})              # access-control flagged
    oracle = FakeOracle({"poc_re": RE}, {})           # oracle only covers reentrancy
    rec = build(gen, analyzer, oracle).run(make_task())
    assert rec.findings[0].status is FindingStatus.OUT_OF_SCOPE
    assert rec.verdict is LoopVerdict.ORACLE_GAP


def test_stagnation_on_cycle():
    gen = ScriptedGenerator(initial="VULN", repairs=["VULN"])  # model returns it unchanged
    analyzer = FakeAnalyzer({"VULN": [RE]})
    oracle = FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}})
    rec = build(gen, analyzer, oracle).run(make_task())
    assert rec.verdict is LoopVerdict.STAGNATION


def test_iter_budget_exhausted():
    gen = ScriptedGenerator(initial="VULN", repairs=["A1", "A2", "A3"])
    analyzer = FakeAnalyzer({"VULN": [RE], "A1": [RE], "A2": [RE], "A3": [RE]})
    oracle = FakeOracle(
        {"poc_re": RE},
        {"VULN": {"poc_re"}, "A1": {"poc_re"}, "A2": {"poc_re"}, "A3": {"poc_re"}},
    )
    cfg = LoopConfig(max_iterations=2, stagnation_patience=99, compile_fail_streak=99)
    rec = build(gen, analyzer, oracle, config=cfg).run(make_task())
    assert rec.verdict is LoopVerdict.ITER_BUDGET
    assert len(rec.repairs) == 2


def test_initial_compile_failure():
    gen = ScriptedGenerator(initial="BROKEN", repairs=["x"])
    compiler = FakeCompiler(noncompiling=frozenset({"BROKEN"}))
    rec = build(gen, FakeAnalyzer({}), FakeOracle({}, {}), compiler=compiler).run(make_task())
    assert rec.verdict is LoopVerdict.COMPILE_FAIL


def test_repair_compile_fail_streak():
    gen = ScriptedGenerator(initial="VULN", repairs=["BAD1", "BAD2", "BAD3"])
    analyzer = FakeAnalyzer({"VULN": [RE]})
    oracle = FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}})
    compiler = FakeCompiler(noncompiling=frozenset({"BAD1", "BAD2", "BAD3"}))
    cfg = LoopConfig(max_iterations=5, compile_fail_streak=3)
    rec = build(gen, analyzer, oracle, compiler=compiler, config=cfg).run(make_task())
    assert rec.verdict is LoopVerdict.COMPILE_FAIL
    assert len(rec.repairs) == 3


def test_gas_tax_recorded_on_success():
    gen = ScriptedGenerator(initial="VULN", repairs=["FIXED"])
    analyzer = FakeAnalyzer({"VULN": [RE]})
    oracle = FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}})
    tester = FakeTester(
        gas={"VULN": {"withdraw": 30_000}, "FIXED": {"withdraw": 32_100}}  # +2100 gas guard
    )
    rec = build(gen, analyzer, oracle, tester=tester).run(make_task())
    assert rec.verdict is LoopVerdict.SUCCESS
    assert rec.gas_tax_total() == 2_100


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
