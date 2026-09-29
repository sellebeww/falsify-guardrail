"""Tests for the Echidna property oracle: parser (unit) + real run (integration)."""

from __future__ import annotations

from pathlib import Path

import pytest

from falsify.analysis.echidna_runner import EchidnaChecker, EchidnaResult, parse_output

_TASK = Path(__file__).resolve().parent.parent / "benchmark/tasks/access_control/task_002_takeover"


def test_parse_output_maps_pass_and_fail():
    text = (
        "echidna_owner_is_deployer: failed!\U0001f4a5\n"
        "echidna_balance_ok: passing\n"
        "echidna_other: passed!\U0001f389\n"
    )
    parsed = parse_output(text)
    assert parsed == {
        "echidna_owner_is_deployer": False,
        "echidna_balance_ok": True,
        "echidna_other": True,
    }


def test_failed_properties_helper():
    r = EchidnaResult(available=True, properties={"echidna_a": True, "echidna_b": False})
    assert r.failed_properties == ["echidna_b"]


@pytest.mark.integration
@pytest.mark.skipif(not EchidnaChecker().available(), reason="Echidna not installed")
@pytest.mark.parametrize("task_dir", sorted(Path("benchmark/tasks").glob("*/*")))
def test_echidna_cross_checks_every_task(task_dir):
    from falsify import benchmark

    task = benchmark.load_task(task_dir)
    prop_src, prop_contract = benchmark.echidna_property(task_dir)
    checker = EchidnaChecker(test_limit=5000)
    roles = benchmark._meta(task_dir)["roles"]
    for role in ("initial", "good_fix"):
        if role not in roles:
            continue
        result = checker.run(
            benchmark.role_source(task_dir, role), task.contract_name,
            prop_src, prop_contract, task.solc_pragma, support_sources=task.support_sources,
        )
        assert result.properties, result.raw
        assert result.passed == (role == "good_fix" or "good_fix" not in roles), result.raw
