"""Anti-circularity tests (plan §4).

The repair feedback must never carry PoC source, invariants, functional-test
source, or a reference implementation. We assert this two ways: the RepairContext
field set is a fixed allowlist, and the assembled feedback contains no
tell-tale markers of test/exploit code.
"""

from __future__ import annotations

from dataclasses import fields

from falsify.generators.base import RepairContext
from falsify.repair.feedback import FORBIDDEN_FEEDBACK_MARKERS, build_repair_context
from falsify.types import Finding, FindingStatus, Severity, TaskSpec, VulnClass

# The ONLY fields repair feedback may contain. Adding a field forces a conscious
# edit here — a tripwire against accidentally leaking oracle internals.
ALLOWED_FIELDS = {
    "task_id",
    "contract_name",
    "solc_pragma",
    "nl_spec",
    "current_source",
    "iteration",
    "confirmed_classes",
    "slither_findings",
    "exploit_confirmed",
    "functional_failures",
    "last_reject_reason",
}


def test_repair_context_field_allowlist():
    assert {f.name for f in fields(RepairContext)} == ALLOWED_FIELDS


def test_feedback_contains_only_minimal_signals():
    task = TaskSpec(
        id="t1",
        category=VulnClass.REENTRANCY,
        nl_spec="A vault with deposit and withdraw.",
        solc_pragma="^0.8.24",
        contract_name="Vault",
        task_dir="benchmark/tasks/reentrancy/t1",  # holds tests/, exploits/, properties/ (secret)
    )
    confirmed = [
        Finding(
            id="c1",
            detector="slither:reentrancy-eth",
            swc_class=VulnClass.REENTRANCY,
            severity=Severity.HIGH,
            location="Vault.sol#L20",
            status=FindingStatus.CONFIRMED,
            confirmed_by="poc_re",
        )
    ]
    ctx = build_repair_context(
        task=task,
        current_source="contract Vault { function withdraw() external {} }",
        confirmed_findings=confirmed,
        all_findings=confirmed,
        iteration=1,
        functional_failures=[],
    )

    assert ctx.exploit_confirmed is True
    assert ctx.confirmed_classes == [VulnClass.REENTRANCY]
    assert any("reentrancy" in s for s in ctx.slither_findings)

    # No secret path or PoC id leaked into any string-valued field.
    blob = " ".join(
        [ctx.task_id, ctx.contract_name, ctx.solc_pragma, ctx.nl_spec, ctx.current_source]
        + ctx.slither_findings
        + ctx.functional_failures
    )
    for secret in (task.task_dir, "poc_re", "/exploits/", "/properties/", "/tests/"):
        assert secret not in blob
    for marker in FORBIDDEN_FEEDBACK_MARKERS:
        assert marker not in blob
