"""Build the minimal repair feedback (plan §4).

This is the *only* place repair feedback is assembled. It exists as a separate,
testable unit so we can assert—by test—that PoC source, invariants, functional
test source, and reference implementations never reach the model under test.
"""

from __future__ import annotations

from falsify.generators.base import RepairContext
from falsify.types import Finding, FindingStatus, TaskSpec, VulnClass

# Substrings that must NEVER appear in feedback (would train-to-the-test).
# Used by tests as a guardrail against future leakage regressions.
FORBIDDEN_FEEDBACK_MARKERS = ("is Test", "vm.", "assert", "invariant_", "// POC", "Exploit")


def build_repair_context(
    task: TaskSpec,
    current_source: str,
    confirmed_findings: list[Finding],
    all_findings: list[Finding],
    iteration: int,
    functional_failures: list[str],
    last_reject_reason: str | None = None,
) -> RepairContext:
    confirmed_classes: list[VulnClass] = sorted(
        {f.swc_class for f in confirmed_findings}, key=lambda c: c.value
    )
    # Human-readable detector text only — never the finding's underlying PoC.
    slither_findings = [
        f"{f.detector} [{f.severity.value}]" + (f" at {f.location}" if f.location else "")
        for f in all_findings
        if f.status
        in (FindingStatus.CANDIDATE, FindingStatus.CONFIRMED, FindingStatus.UNCONFIRMED)
    ]
    return RepairContext(
        task_id=task.id,
        contract_name=task.contract_name,
        solc_pragma=task.solc_pragma,
        nl_spec=task.nl_spec,
        current_source=current_source,
        iteration=iteration,
        confirmed_classes=confirmed_classes,
        slither_findings=slither_findings,
        exploit_confirmed=bool(confirmed_findings),
        functional_failures=list(functional_failures),
        last_reject_reason=last_reject_reason,
    )
