"""The JSON artifact must be valid, deterministic, and answer the RQs at a glance."""

from __future__ import annotations

import json

from falsify.artifacts import record_to_dict, write_record
from falsify.config import LoopConfig
from falsify.orchestrator import Orchestrator
from falsify.types import TaskSpec, VulnClass
from tests.fakes import FakeAnalyzer, FakeCompiler, FakeOracle, FakeTester, ScriptedGenerator

RE = VulnClass.REENTRANCY


def _run_success():
    gen = ScriptedGenerator(initial="VULN", repairs=["FIXED"])
    orch = Orchestrator(
        generator=gen,
        analyzer=FakeAnalyzer({"VULN": [RE]}),
        oracle=FakeOracle({"poc_re": RE}, {"VULN": {"poc_re"}}),
        compiler=FakeCompiler(),
        tester=FakeTester(gas={"VULN": {"withdraw": 30_000}, "FIXED": {"withdraw": 31_000}}),
        config=LoopConfig(),
    )
    return orch.run(TaskSpec("t1", RE, "vault", "^0.8.24", "Vault"))


def test_record_serializes_to_valid_json(tmp_path):
    rec = _run_success()
    path = write_record(rec, tmp_path / "run.json")
    data = json.loads(path.read_text())

    assert data["verdict"] == "success"
    assert data["summary"]["gate_pass"] is True
    assert data["summary"]["false_fixes_detector_silenced"] == 0
    assert data["summary"]["gas_tax_total"] == 1_000
    # enums serialized as values, not python repr
    assert data["findings"][0]["status"] == "confirmed"
    assert data["category"] == "reentrancy"


def test_record_is_deterministic():
    rec = _run_success()
    a = json.dumps(record_to_dict(rec), sort_keys=True)
    b = json.dumps(record_to_dict(rec), sort_keys=True)
    assert a == b
