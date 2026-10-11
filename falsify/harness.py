"""Validate that a task harness can tell exploitable code from safe code.

A failing exploit is only meaningful if the exploit could have succeeded. A PoC that never
passes (a broken setUp, a stale interface, a wrong assertion) would report every candidate
as "not exploited". Controls guard against that: sources whose outcome is known in advance.

- An *exploitable* control must be exploited by the battery, and every PoC must succeed on
  at least one exploitable control. Otherwise that PoC can never confirm anything.
- A *safe* control must not be exploited by any PoC.
- Every control must pass the functional suite, so that functional tests, not exploits,
  are never what separates a control from its counterpart.

Controls come from `task.json`. An explicit `controls` block wins:

    "controls": {"exploitable": ["reference/Vault_vulnerable.sol"],
                 "safe": ["reference/Vault_fixed.sol"]}

Without it, fixture roles are used: `initial` and `bad_fix` are exploitable, `good_fix` is
safe. A task whose initial contract is safe must declare `controls` explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from falsify import benchmark
from falsify.oracle.base import FunctionalTester, Oracle
from falsify.types import GeneratedArtifact, TaskSpec


@dataclass(frozen=True)
class Control:
    path: str           # relative to the task directory
    exploitable: bool


@dataclass
class ControlResult:
    control: Control
    exploited: list[str] = field(default_factory=list)  # PoC ids that succeeded
    functional_failures: list[str] | None = None        # None: functional suite not run
    problems: list[str] = field(default_factory=list)


@dataclass
class HarnessReport:
    task_id: str
    results: list[ControlResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)    # task-level problems

    @property
    def verified(self) -> bool:
        """True when an exploitable control was actually exploited: the battery is live."""
        return any(r.control.exploitable and r.exploited for r in self.results)

    @property
    def ok(self) -> bool:
        return not self.problems and all(not r.problems for r in self.results)

    def all_problems(self) -> list[str]:
        return self.problems + [f"{r.control.path}: {p}" for r in self.results for p in r.problems]


def controls(task_dir: str | Path) -> list[Control]:
    meta = benchmark.task_meta(task_dir)
    declared = meta.get("controls")
    if declared is not None:
        out = [Control(p, True) for p in declared.get("exploitable", [])]
        out += [Control(p, False) for p in declared.get("safe", [])]
    else:
        roles = meta.get("roles", {})
        out = [Control(f"reference/{roles[role]}", exploitable)
               for role, exploitable in (("initial", True), ("bad_fix", True), ("good_fix", False))
               if role in roles]
    for c in out:
        path = PurePosixPath(c.path)
        if path.is_absolute() or ".." in path.parts or path.suffix != ".sol":
            raise ValueError(f"control path must be a .sol file inside the task: {c.path}")
    return out


def validate(task_dir: str | Path, task: TaskSpec, oracle: Oracle,
             tester: FunctionalTester | None = None, exploitable_only: bool = False
             ) -> HarnessReport:
    """Run the exploit battery (and, given a tester, the functional suite) on each control.

    `exploitable_only` checks PoC liveness alone, which is all a guardrail run needs before
    trusting a "not exploited" outcome.
    """
    task_dir = Path(task_dir)
    report = HarnessReport(task.id)
    selected = [c for c in controls(task_dir) if c.exploitable or not exploitable_only]
    all_pocs: set[str] = set()
    live_pocs: set[str] = set()
    for control in selected:
        artifact = GeneratedArtifact(
            task.id, "control", (task_dir / control.path).read_text(), task.contract_name,
            support_sources=dict(task.support_sources), solc_pragma=task.solc_pragma,
        )
        result = ControlResult(control)
        exploits = oracle.run(artifact, task)
        if not exploits or any(not r.executed for r in exploits):
            result.problems.append("exploit battery missing or failed to build/execute")
        else:
            all_pocs |= {r.poc_id for r in exploits}
            result.exploited = sorted(r.poc_id for r in exploits if r.success)
            if control.exploitable:
                live_pocs |= set(result.exploited)
                if not result.exploited:
                    result.problems.append("no exploit succeeds on a known-exploitable control")
            elif result.exploited:
                result.problems.append(
                    "exploit succeeds on a known-safe control: " + ", ".join(result.exploited))
        if tester is not None:
            functional = tester.run(artifact, task)
            result.functional_failures = list(functional.failures)
            if not functional.passed:
                result.problems.append(
                    "functional suite fails: " + ", ".join(functional.failures))
        report.results.append(result)

    if not any(c.exploitable for c in selected):
        report.problems.append(
            "no exploitable control declared; exploit liveness cannot be verified")
    else:
        dead = sorted(all_pocs - live_pocs)
        if dead:
            report.problems.append(
                "exploit never succeeds on any exploitable control (it cannot confirm "
                "anything): " + ", ".join(dead))
    return report


def render(report: HarnessReport) -> str:
    lines = [f"Harness validation for {report.task_id}"]
    for r in report.results:
        kind = "exploitable" if r.control.exploitable else "safe"
        exploited = ", ".join(p.split("::")[-1] for p in r.exploited) or "-"
        functional = ("not run" if r.functional_failures is None
                      else "fail" if r.functional_failures else "pass")
        status = "OK" if not r.problems else "PROBLEM"
        lines.append(f"  {kind:<11}  {r.control.path:<40}  exploited: {exploited:<32}"
                     f"  functional: {functional:<7}  {status}")
    for problem in report.all_problems():
        lines.append(f"  - {problem}")
    lines.append(f"Result: {'VALID' if report.ok else 'INVALID'}")
    return "\n".join(lines)
