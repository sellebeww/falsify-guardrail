"""Foundry-backed compiler, functional tester, and exploit oracle (plan §3, §5).

Each candidate contract is dropped into a hermetic temp Foundry project (no forge-std
or external libs — tests declare a minimal cheatcode interface inline), then `forge`
builds and runs the relevant test files. A PoC "succeeds" iff its forge test PASSES;
"exploit failed" (test fails/reverts) means UNCONFIRMED, never SECURE.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from falsify import toolpaths
from falsify.oracle.base import CompileResult, FunctionalResult
from falsify.types import (
    ExploitResult,
    GasProfile,
    GeneratedArtifact,
    TaskSpec,
    VulnClass,
)

_FOUNDRY_TOML = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
solc = "{solc}"
optimizer = true
optimizer_runs = 200
"""

BUILD_TIMEOUT = 180
TEST_TIMEOUT = 180


@dataclass
class _TestOutcome:
    name: str
    passed: bool
    gas: int
    reason: str = ""
    executed: bool = True


def _solc_pin(pragma: str, default: str = "0.8.24") -> str:
    # Turn "^0.8.24" / ">=0.8.20" into a concrete pin; MVP fixes on the installed solc.
    import re

    m = re.search(r"(\d+\.\d+\.\d+)", pragma or "")
    return m.group(1) if m else default


class ForgeProject:
    """A disposable Foundry project holding one contract plus some test files."""

    def __init__(
        self,
        contract_source: str,
        contract_name: str,
        solc_pragma: str,
        test_files: dict[str, str] | None = None,
        keep: bool = False,
        support_sources: dict[str, str] | None = None,
    ) -> None:
        self.contract_source = contract_source
        self.contract_name = contract_name
        pin = _solc_pin(solc_pragma)
        installed = Path(os.environ.get("SOLC_SELECT_DIR", Path.home() / ".solc-select"))
        installed = installed / "artifacts" / f"solc-{pin}" / f"solc-{pin}"
        self.solc = str(installed) if installed.is_file() else pin
        self.test_files = test_files or {}
        self.keep = keep
        self.support_sources = support_sources or {}
        self._dir: Path | None = None

    def __enter__(self) -> Self:
        self._dir = Path(tempfile.mkdtemp(prefix="falsify-forge-"))
        (self._dir / "src").mkdir()
        (self._dir / "test").mkdir()
        (self._dir / "foundry.toml").write_text(_FOUNDRY_TOML.format(solc=self.solc))
        from falsify.sources import write_sources

        write_sources(self._dir / "src", self.contract_name,
                      self.contract_source, self.support_sources)
        for name, source in self.test_files.items():
            (self._dir / "test" / name).write_text(source)
        return self

    def __exit__(self, *exc) -> None:
        if self._dir and not self.keep:
            shutil.rmtree(self._dir, ignore_errors=True)

    # -- forge invocations ------------------------------------------------ #
    def build(self) -> CompileResult:
        proc = subprocess.run(
            [toolpaths.forge_bin(), "build"],
            cwd=self._dir,
            capture_output=True,
            text=True,
            check=False,
            env=toolpaths.subprocess_env(),
            timeout=BUILD_TIMEOUT,
        )
        if proc.returncode == 0:
            return CompileResult(ok=True)
        # forge prints the diagnostic to stderr (and sometimes stdout)
        err = (proc.stderr or "") + (proc.stdout or "")
        return CompileResult(ok=False, error=err.strip()[:2000])

    def test(self) -> tuple[bool, list[_TestOutcome]]:
        """Return (build_ok, outcomes). Non-zero exit is normal when a test fails."""
        proc = subprocess.run(
            [toolpaths.forge_bin(), "test", "--json"],
            cwd=self._dir,
            capture_output=True,
            text=True,
            check=False,
            env=toolpaths.subprocess_env(),
            timeout=TEST_TIMEOUT,
        )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            # No JSON => the test suite failed to compile/build against this contract.
            return False, []
        outcomes: list[_TestOutcome] = []
        if not isinstance(data, dict):
            return False, []
        for suite_name, suite_data in data.items():
            for fn, res in suite_data.get("test_results", {}).items():
                kind = res.get("kind", {})
                gas = 0
                if isinstance(kind, dict):
                    inner = kind.get("Unit") or kind.get("Fuzz") or {}
                    gas = int(inner.get("gas", 0) or inner.get("mean_gas", 0) or 0)
                outcomes.append(
                    _TestOutcome(
                        name=f"{suite_name}::{fn}",
                        passed=res.get("status") == "Success",
                        gas=gas,
                        reason=res.get("reason") or "",
                        executed=res.get("status") in {"Success", "Failure"}
                        and fn.startswith("test"),
                    )
                )
        return bool(outcomes) and all(o.executed for o in outcomes), outcomes

    def coverage(self) -> dict:
        from falsify.coverage import parse_lcov

        proc = subprocess.run(
            [toolpaths.forge_bin(), "coverage", "--report", "lcov",
             "--report-file", "coverage.info"],
            cwd=self._dir, capture_output=True, text=True, check=False,
            env=toolpaths.subprocess_env(), timeout=TEST_TIMEOUT,
        )
        report = self._dir / "coverage.info"
        if proc.returncode or not report.exists():
            return {"available": False, "error": "forge coverage failed"}
        return parse_lcov(report.read_text())

    def gas_report(self, contract_name: str) -> GasProfile:
        """Per-function mean gas for `contract_name` (from `forge test --gas-report --json`)."""
        proc = subprocess.run(
            [toolpaths.forge_bin(), "test", "--gas-report", "--json"],
            cwd=self._dir,
            capture_output=True,
            text=True,
            check=False,
            env=toolpaths.subprocess_env(),
            timeout=TEST_TIMEOUT,
        )
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return GasProfile()
        target = f"src/{contract_name}.sol:{contract_name}"
        for entry in report if isinstance(report, list) else []:
            if entry.get("contract") == target:
                fns = entry.get("functions", {})
                return GasProfile(entries={sig: int(v.get("mean", 0)) for sig, v in fns.items()})
        return GasProfile()


def _read_task_sols(task: TaskSpec, subdir: str) -> dict[str, str]:
    if not task.task_dir:
        return {}
    d = Path(task.task_dir) / subdir
    if not d.is_dir():
        return {}
    return {p.name: p.read_text() for p in sorted(d.glob("*.t.sol"))}


# --------------------------------------------------------------------------- #
class FoundryCompiler:
    """Compile-only gate: builds the contract by itself (no tests)."""

    def compile(self, artifact: GeneratedArtifact, solc_pragma: str) -> CompileResult:
        with ForgeProject(artifact.source, artifact.contract_name, solc_pragma,
                          support_sources=artifact.support_sources) as proj:
            return proj.build()


class FoundryFunctionalTester:
    """Runs the task's human-owned functional suite against the candidate."""

    def run(self, artifact: GeneratedArtifact, task: TaskSpec) -> FunctionalResult:
        tests = _read_task_sols(task, "tests")
        if not tests:
            return FunctionalResult(passed=False, failures=["<no functional tests>"])
        with ForgeProject(
            artifact.source, artifact.contract_name, task.solc_pragma, test_files=tests,
            support_sources=artifact.support_sources
        ) as proj:
            build_ok, outcomes = proj.test()
            if not build_ok:
                return FunctionalResult(
                    passed=False, failures=["<functional suite failed to build>"]
                )
            # Per-function gas of the contract under test (RQ3), measured in the same project.
            gas = proj.gas_report(artifact.contract_name)
            coverage = proj.coverage()
        failures = [o.name for o in outcomes if not o.passed]
        return FunctionalResult(passed=not failures, failures=failures, gas=gas, coverage=coverage)


class FoundryOracle:
    """Runs the deterministic PoC battery. A passing PoC test == a confirmed exploit."""

    def __init__(self, covered: set[VulnClass] | None = None) -> None:
        # Classes we ship at least one PoC template for (plan §7).
        self._covered = covered or {VulnClass.REENTRANCY, VulnClass.ACCESS_CONTROL}

    def covered_classes(self) -> set[VulnClass]:
        return set(self._covered)

    def run(self, artifact: GeneratedArtifact, task: TaskSpec) -> list[ExploitResult]:
        pocs = _read_task_sols(task, "exploits")
        if not pocs:
            return []
        with ForgeProject(
            artifact.source, artifact.contract_name, task.solc_pragma, test_files=pocs,
            support_sources=artifact.support_sources
        ) as proj:
            build_ok, outcomes = proj.test()
        if not build_ok:
            # PoC could not build against this contract -> cannot confirm (not "safe").
            return [
                ExploitResult(poc_id=name, swc_class=task.category, success=False,
                              revert_reason="poc failed to build or execute", executed=False)
                for name in pocs
            ]
        results = []
        for o in outcomes:
            results.append(
                ExploitResult(
                    poc_id=o.name,
                    swc_class=task.category,
                    success=o.passed,
                    revert_reason="" if o.passed else o.reason,
                    gas_used=o.gas,
                )
            )
        return results
