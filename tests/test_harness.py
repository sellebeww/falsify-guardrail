"""Harness controls: a failing exploit only counts when the exploit is known to be live."""

from __future__ import annotations

import json

import pytest

from falsify import benchmark, harness
from falsify.types import ExploitResult, VulnClass
from tests.fakes import FakeOracle, FakeTester

RE = VulnClass.REENTRANCY


def make_task_dir(tmp_path, meta_extra=None, files=None):
    (tmp_path / "reference").mkdir()
    files = files or {"Vault_vulnerable.sol": "VULN", "Vault_fixed.sol": "FIXED"}
    for name, text in files.items():
        (tmp_path / "reference" / name).write_text(text)
    meta = {"id": "t", "category": "reentrancy", "contract_name": "Vault",
            "roles": {"initial": "Vault_vulnerable.sol", "good_fix": "Vault_fixed.sol"}}
    meta.update(meta_extra or {})
    (tmp_path / "task.json").write_text(json.dumps(meta))
    return tmp_path, benchmark.load_task(tmp_path)


def run(task_dir, task, succeeds, registry=("p1",), tester=None, **kw):
    oracle = FakeOracle({p: RE for p in registry}, succeeds)
    return harness.validate(task_dir, task, oracle, tester, **kw)


def test_live_harness_is_valid(tmp_path):
    report = run(*make_task_dir(tmp_path), {"VULN": {"p1"}}, tester=FakeTester())
    assert report.ok and report.verified, report.all_problems()


def test_exploit_that_never_fires_is_reported_dead(tmp_path):
    report = run(*make_task_dir(tmp_path), {"VULN": {"p1"}}, registry=("p1", "p2"))
    assert not report.ok
    assert any("p2" in p and "never succeeds" in p for p in report.problems)


def test_exploitable_control_that_is_not_exploited_is_a_problem(tmp_path):
    report = run(*make_task_dir(tmp_path), {})
    assert not report.ok
    assert any("known-exploitable" in p for p in report.all_problems())


def test_exploit_firing_on_a_safe_control_is_a_problem(tmp_path):
    report = run(*make_task_dir(tmp_path), {"VULN": {"p1"}, "FIXED": {"p1"}})
    assert any("known-safe" in p for p in report.all_problems())


def test_functional_failure_on_a_control_is_a_problem(tmp_path):
    tester = FakeTester(failing=frozenset({"FIXED"}))
    report = run(*make_task_dir(tmp_path), {"VULN": {"p1"}}, tester=tester)
    assert any("functional suite fails" in p for p in report.all_problems())


def test_unexecuted_battery_is_never_evidence(tmp_path):
    class BrokenOracle(FakeOracle):
        def run(self, artifact, task):
            return [ExploitResult("p1", RE, False, executed=False)]

    task_dir, task = make_task_dir(tmp_path)
    report = harness.validate(task_dir, task, BrokenOracle({"p1": RE}, {}))
    assert not report.ok and not report.verified


def test_without_exploitable_controls_liveness_is_unverified(tmp_path):
    task_dir, task = make_task_dir(
        tmp_path, {"controls": {"safe": ["reference/Vault_fixed.sol"]}})
    report = run(task_dir, task, {})
    assert not report.verified
    assert any("cannot be verified" in p for p in report.problems)


def test_explicit_controls_replace_roles(tmp_path):
    task_dir, _ = make_task_dir(
        tmp_path, {"controls": {"exploitable": ["reference/Vault_fixed.sol"]}})
    assert harness.controls(task_dir) == [harness.Control("reference/Vault_fixed.sol", True)]


def test_exploitable_only_skips_safe_controls_and_functional(tmp_path):
    report = run(*make_task_dir(tmp_path), {"VULN": {"p1"}}, exploitable_only=True)
    assert [r.control.exploitable for r in report.results] == [True]


@pytest.mark.parametrize("path", ["/etc/passwd.sol", "../escape.sol", "reference/notes.txt"])
def test_control_paths_must_stay_inside_the_task(tmp_path, path):
    task_dir, _ = make_task_dir(tmp_path, {"controls": {"exploitable": [path]}})
    with pytest.raises(ValueError):
        harness.controls(task_dir)
