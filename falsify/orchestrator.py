"""The falsification loop (plan §3).

Generate -> static analysis -> exploit oracle -> classify -> repair loop, where a
repair is ACCEPTED only if (a) every confirming PoC now fails, (b) functional tests
pass, (c) it compiles, and (d) no *new* exploit appears. Detector-silencing (Slither
goes quiet but the PoC still works) is recorded as a FALSE FIX, never a success.

All external tools are injected, so the entire loop is unit-testable with in-memory
fakes and no blockchain toolchain.
"""

from __future__ import annotations

import platform
import subprocess
from datetime import UTC, datetime

from falsify.analysis.base import StaticAnalyzer
from falsify.config import LoopConfig
from falsify.generators.base import Generator
from falsify.oracle.base import Compiler, FunctionalTester, Oracle
from falsify.repair.feedback import build_repair_context
from falsify.types import (
    GATE_PASSING,
    EvalRecord,
    ExploitResult,
    Finding,
    FindingFate,
    FindingStatus,
    LoopVerdict,
    RejectReason,
    RepairAttempt,
    RepairOutcome,
    Severity,
    TaskSpec,
    ToolVersions,
)


def _succeeding(results: list[ExploitResult]) -> set[str]:
    return {r.poc_id for r in results if r.success}


class Orchestrator:
    def __init__(
        self,
        generator: Generator,
        analyzer: StaticAnalyzer,
        oracle: Oracle,
        compiler: Compiler,
        tester: FunctionalTester,
        config: LoopConfig | None = None,
        versions: ToolVersions | None = None,
    ) -> None:
        self.generator = generator
        self.analyzer = analyzer
        self.oracle = oracle
        self.compiler = compiler
        self.tester = tester
        self.config = config or LoopConfig()
        self.versions = versions or ToolVersions(python=platform.python_version())

    # ------------------------------------------------------------------ #
    def run(self, task: TaskSpec) -> EvalRecord:
        self._record = None
        try:
            record = self._run(task)
            transport = getattr(self.generator, "_transport", None)
            record.model_calls = list(getattr(transport, "calls", []))
            return record
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            record = self._record or EvalRecord(
                task_id=task.id, category=task.category, model=self.generator.name,
                versions=self.versions, verdict=LoopVerdict.TOOL_ERROR, gate_pass=False,
                solc_pragma=task.solc_pragma,
            )
            record.verdict = LoopVerdict.TOOL_ERROR
            record.notes.append(f"evaluation failed: {type(exc).__name__}: {exc}")
            transport = getattr(self.generator, "_transport", None)
            record.model_calls = list(getattr(transport, "calls", []))
            return self._finalize(record)

    def _run(self, task: TaskSpec) -> EvalRecord:
        cfg = self.config
        started = datetime.now(UTC).isoformat()

        artifact = self.generator.generate(task.nl_spec, task.contract_name, task.solc_pragma)

        artifact.support_sources = dict(task.support_sources)
        artifact.solc_pragma = task.solc_pragma

        record = self._record = EvalRecord(
            task_id=task.id,
            solc_pragma=task.solc_pragma,
            sources={artifact.code_hash(): {"entry": artifact.source,
                                            "support": artifact.support_sources}},
            category=task.category,
            model=self.generator.name,
            versions=self.versions,
            verdict=LoopVerdict.CLEAN,  # provisional; set precisely below
            gate_pass=False,
            initial_source_hash=artifact.code_hash(),
            final_source_hash=artifact.code_hash(),
            timestamps={"started": started},
        )

        # Initial contract must compile to do anything meaningful.
        cr = self.compiler.compile(artifact, task.solc_pragma)
        if not cr.ok:
            record.verdict = LoopVerdict.COMPILE_FAIL
            record.notes.append(f"initial generation failed to compile: {cr.error}")
            return self._finalize(record)

        # Static analysis -> candidate findings; oracle battery -> confirmation.
        findings = self.analyzer.analyze(artifact)
        initial_exploits = self.oracle.run(artifact, task)
        record.initial_exploits = initial_exploits
        if not initial_exploits or any(not r.executed for r in initial_exploits):
            record.verdict = LoopVerdict.TOOL_ERROR
            record.notes.append("oracle battery missing or failed to execute")
            return self._finalize(record)
        self._classify(findings, initial_exploits)
        self._add_oracle_discovered(findings, initial_exploits)
        record.findings = findings

        # Functional baseline (also the gas baseline).
        base_functional = self.tester.run(artifact, task)
        record.gas_baseline = base_functional.gas
        record.gas_final = base_functional.gas
        record.coverage_baseline = base_functional.coverage
        record.coverage_final = base_functional.coverage
        if not base_functional.passed:
            record.notes.append(
                "initial contract fails functional tests: " + ", ".join(base_functional.failures)
            )

        confirmed = [f for f in findings if f.status is FindingStatus.CONFIRMED]

        # No confirmed exploit -> nothing the gated loop can act on.
        if not confirmed:
            if not base_functional.passed:
                record.verdict = LoopVerdict.FUNCTIONAL_FAIL
                return self._finalize(record)
            if not findings:
                record.verdict = LoopVerdict.CLEAN
            else:
                record.verdict = LoopVerdict.ORACLE_GAP
                record.notes.append(
                    "candidate findings present but none confirmable — UNCONFIRMED != SECURE"
                )
            # Unconfirmed findings are RQ2 candidates (tracked in record.findings),
            # never counted as false fixes.
            return self._finalize(record)

        # ---------------------- repair loop ------------------------------ #
        succeeding_C = _succeeding(initial_exploits)
        original_confirming = {f.confirmed_by for f in confirmed if f.confirmed_by}
        current = artifact
        seen_hashes = {current.code_hash()}
        remaining_prev = len(original_confirming)
        stagnation = 0
        compile_streak = 0
        last_reason: str | None = None
        verdict: LoopVerdict | None = None

        for it in range(1, cfg.max_iterations + 1):
            ctx = build_repair_context(
                task=task,
                current_source=current.source,
                confirmed_findings=confirmed,
                all_findings=findings,
                iteration=it,
                functional_failures=base_functional.failures,
                last_reject_reason=last_reason,
            )
            candidate = self.generator.repair(ctx)
            candidate.support_sources = dict(task.support_sources)
            candidate.solc_pragma = task.solc_pragma
            h = candidate.code_hash()
            record.sources[h] = {"entry": candidate.source, "support": candidate.support_sources}

            # (c) compile gate
            ccr = self.compiler.compile(candidate, task.solc_pragma)
            if not ccr.ok:
                compile_streak += 1
                last_reason = RejectReason.COMPILE_FAILED.value
                record.repairs.append(
                    RepairAttempt(it, h, RepairOutcome.REJECTED, RejectReason.COMPILE_FAILED)
                )
                if compile_streak >= cfg.compile_fail_streak:
                    verdict = LoopVerdict.COMPILE_FAIL
                    break
                continue
            compile_streak = 0

            # Evaluate the candidate.
            cand_exploits = self.oracle.run(candidate, task)
            expected = {r.poc_id for r in initial_exploits}
            executed = {r.poc_id for r in cand_exploits if r.executed}
            if not expected.issubset(executed) or any(not r.executed for r in cand_exploits):
                record.repairs.append(RepairAttempt(
                    it, h, RepairOutcome.REJECTED, RejectReason.TOOL_ERROR,
                    exploit_results=cand_exploits,
                ))
                last_reason = "oracle battery failed to execute"
                continue
            succeeding_Cp = _succeeding(cand_exploits)
            cand_findings = self.analyzer.analyze(candidate)
            flagged_classes = {f.swc_class for f in cand_findings}

            not_neutralized = succeeding_C & succeeding_Cp
            new_successes = succeeding_Cp - succeeding_C  # regression: opened a new hole
            functional = self.tester.run(candidate, task)

            # Fates for the anti-Goodhart metrics (RQ1).
            fates: dict[str, FindingFate] = {}
            false_fix_events = 0
            for f in confirmed:
                still = f.confirmed_by in succeeding_Cp
                flagged = f.swc_class in flagged_classes
                if not still:
                    fates[f.id] = FindingFate.NEUTRALIZED
                elif not flagged and f.detector.startswith("slither"):
                    fates[f.id] = FindingFate.DETECTOR_SILENCED  # detector quiet, exploit alive
                    false_fix_events += 1
                else:
                    fates[f.id] = FindingFate.STILL_EXPLOITABLE
            record.false_fixes += false_fix_events

            # Repair-acceptance predicate (plan §3).
            if not_neutralized:
                reason = RejectReason.NOT_NEUTRALIZED
            elif new_successes:
                reason = RejectReason.NEW_EXPLOIT_REGRESSION
            elif not functional.passed:
                reason = RejectReason.FUNCTIONAL_REGRESSION
            else:
                reason = None

            outcome = RepairOutcome.ACCEPTED if reason is None else RepairOutcome.REJECTED
            attempt = RepairAttempt(
                iteration=it,
                source_hash=h,
                outcome=outcome,
                reason=reason,
                fates=fates,
                gas_delta_total=functional.gas.total_delta(record.gas_baseline),
                exploit_results=cand_exploits,
                detector_findings=[f.id for f in cand_findings],
                detector_classes=sorted(flagged_classes, key=lambda c: c.value),
            )
            record.repairs.append(attempt)

            if outcome is RepairOutcome.ACCEPTED:
                current = candidate
                record.gas_final = functional.gas
                record.coverage_final = functional.coverage
                verdict = LoopVerdict.SUCCESS
                break

            # ---- rejected: stopping-condition bookkeeping ----
            last_reason = reason.value if reason else None
            if h in seen_hashes:  # cycled back to an earlier contract
                verdict = LoopVerdict.STAGNATION
                record.notes.append(f"stagnation: repair at iter {it} repeats an earlier contract")
                break
            seen_hashes.add(h)

            remaining_now = len(original_confirming & succeeding_Cp)
            if remaining_now < remaining_prev:
                remaining_prev = remaining_now
                stagnation = 0
            else:
                stagnation += 1
                if stagnation >= cfg.stagnation_patience:
                    verdict = LoopVerdict.STAGNATION
                    record.notes.append(
                        f"stagnation: no reduction in confirmed set for {stagnation} iters"
                    )
                    break

        if verdict is None:
            verdict = LoopVerdict.ITER_BUDGET

        record.verdict = verdict
        record.final_source_hash = current.code_hash()
        return self._finalize(record)

    # ------------------------------------------------------------------ #
    def _classify(self, findings: list[Finding], exploits: list[ExploitResult]) -> None:
        """Set each finding's status from the oracle result (plan §3)."""
        covered = self.oracle.covered_classes()
        success_by_class: dict = {}
        for r in exploits:
            if r.success:
                success_by_class.setdefault(r.swc_class, r.poc_id)
        for f in findings:
            if f.swc_class in success_by_class:
                f.status = FindingStatus.CONFIRMED
                f.confirmed_by = success_by_class[f.swc_class]
            elif f.swc_class in covered:
                f.status = FindingStatus.UNCONFIRMED
            else:
                f.status = FindingStatus.OUT_OF_SCOPE

    def _add_oracle_discovered(
        self, findings: list[Finding], exploits: list[ExploitResult]
    ) -> None:
        """A succeeding PoC with no matching Slither finding is a vulnerability the detector
        MISSED. Record it as CONFIRMED — the oracle is ground truth, not just a validator of
        Slither's candidates. This makes Falsify catch detector false negatives too."""
        flagged = {f.swc_class for f in findings}
        for r in exploits:
            if r.success and r.swc_class not in flagged:
                findings.append(
                    Finding(
                        id=f"oracle:{r.swc_class.value}",
                        detector="oracle:poc",
                        swc_class=r.swc_class,
                        severity=Severity.HIGH,
                        status=FindingStatus.CONFIRMED,
                        confirmed_by=r.poc_id,
                    )
                )
                flagged.add(r.swc_class)

    def _finalize(self, record: EvalRecord) -> EvalRecord:
        record.gate_pass = record.verdict in GATE_PASSING
        record.timestamps["ended"] = datetime.now(UTC).isoformat()
        return record
