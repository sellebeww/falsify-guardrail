"""Guardrail mode: liveness preflight and strict blocking, with in-memory tools."""

from __future__ import annotations

import json

import pytest

from falsify import guardrail
from falsify.types import LoopVerdict, VulnClass
from tests.fakes import FakeAnalyzer, FakeCompiler, FakeOracle, FakeTester

RE = VulnClass.REENTRANCY


def task_dir(tmp_path, controls=True):
    (tmp_path / "reference").mkdir()
    (tmp_path / "reference" / "Vault_vulnerable.sol").write_text("VULN")
    (tmp_path / "reference" / "Vault_fixed.sol").write_text("FIXED")
    meta = {"id": "t", "category": "reentrancy", "contract_name": "Vault"}
    if controls:
        meta["controls"] = {"exploitable": ["reference/Vault_vulnerable.sol"],
                            "safe": ["reference/Vault_fixed.sol"]}
    (tmp_path / "task.json").write_text(json.dumps(meta))
    return tmp_path


def tools(succeeds, flagged=None):
    return guardrail.Tools(
        analyzer=FakeAnalyzer(flagged or {"VULN": [RE]}),
        oracle=FakeOracle({"p1": RE}, succeeds),
        compiler=FakeCompiler(), tester=FakeTester(),
    )


def test_live_harness_passes_a_fixed_source(tmp_path):
    record = guardrail.check(task_dir(tmp_path), "FIXED", tools({"VULN": {"p1"}}))
    assert record.gate_pass and record.verdict is LoopVerdict.CLEAN


def test_live_harness_blocks_a_vulnerable_source(tmp_path):
    record = guardrail.check(task_dir(tmp_path), "VULN", tools({"VULN": {"p1"}}))
    assert not record.gate_pass


def test_dead_harness_blocks_instead_of_passing_everything(tmp_path):
    # The exploit never fires, not even on the known-exploitable control.
    record = guardrail.check(task_dir(tmp_path), "VULN", tools({}))
    assert record.verdict is LoopVerdict.TOOL_ERROR and not record.gate_pass
    assert any("harness is not live" in n for n in record.notes)


def test_without_controls_the_pass_is_annotated_and_strict_blocks(tmp_path):
    d = task_dir(tmp_path, controls=False)
    relaxed = guardrail.check(d, "FIXED", tools({}))
    assert relaxed.gate_pass
    assert any("liveness unverified" in n for n in relaxed.notes)

    strict = guardrail.check(d, "FIXED", tools({}), strict=True)
    assert not strict.gate_pass
    assert any("strict" in n for n in strict.notes)


def test_strict_blocks_unconfirmed_detector_findings(tmp_path):
    d, flagged = task_dir(tmp_path), {"FIXED": [RE]}
    relaxed = guardrail.check(d, "FIXED", tools({"VULN": {"p1"}}, flagged))
    assert relaxed.verdict is LoopVerdict.ORACLE_GAP and relaxed.gate_pass

    strict = guardrail.check(d, "FIXED", tools({"VULN": {"p1"}}, flagged), strict=True)
    assert strict.verdict is LoopVerdict.ORACLE_GAP and not strict.gate_pass


def test_strict_does_not_block_a_verified_clean_pass(tmp_path):
    record = guardrail.check(task_dir(tmp_path), "FIXED", tools({"VULN": {"p1"}}), strict=True)
    assert record.gate_pass


def test_entry_must_be_directly_inside_source_root(tmp_path):
    nested = tmp_path / "contracts" / "core"
    nested.mkdir(parents=True)
    (nested / "Vault.sol").write_text("x")
    with pytest.raises(ValueError):
        guardrail.support_from_root(nested / "Vault.sol", tmp_path / "contracts")
