"""Core data model for Falsify.

Everything here is stdlib-only so the falsification logic stays testable offline,
with no blockchain toolchain or API key. The enums encode the §3 oracle state
machine directly, so the project's honesty guarantees ("UNCONFIRMED != SECURE",
"detector-silencing is a false fix") are represented as types rather than prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# --------------------------------------------------------------------------- #
# Enumerations                                                                 #
# --------------------------------------------------------------------------- #
class VulnClass(str, Enum):
    """Vulnerability classes the oracle has PoC templates for.

    MVP scope is deliberately just two classes (see plan §7).
    """

    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class FindingStatus(str, Enum):
    """Lifecycle of a static-analysis finding under the exploit oracle (plan §3)."""

    CANDIDATE = "candidate"          # raised by Slither, not yet tested
    CONFIRMED = "confirmed"          # a PoC exploit succeeds -> real
    UNCONFIRMED = "unconfirmed"      # template exists, no PoC succeeded -> NOT "safe"
    OUT_OF_SCOPE = "out_of_scope"    # no PoC template for this class


class RepairOutcome(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class RejectReason(str, Enum):
    NOT_NEUTRALIZED = "not_neutralized"       # original exploit still succeeds
    FUNCTIONAL_REGRESSION = "functional_regression"  # functional tests fail
    TOOL_ERROR = "tool_error"
    COMPILE_FAILED = "compile_failed"
    NEW_EXPLOIT_REGRESSION = "new_exploit_regression"  # fixed one, opened another


class FindingFate(str, Enum):
    """What happened to a *confirmed* finding after a repair attempt.

    DETECTOR_SILENCED is the central anti-Goodhart signal (RQ1): the detector went
    quiet but the exploit still works -> a false fix, never counted as success.
    """

    NEUTRALIZED = "neutralized"                 # PoC no longer succeeds -> real fix
    DETECTOR_SILENCED = "detector_silenced"     # Slither quiet, PoC still succeeds -> FALSE FIX
    STILL_EXPLOITABLE = "still_exploitable"     # PoC still succeeds, Slither still flags


class LoopVerdict(str, Enum):
    """Terminal state of the repair loop (plan §3). Distinct and logged;
    an unconfirmed result is never silently upgraded to 'secure'."""

    TOOL_ERROR = "tool_error"
    FUNCTIONAL_FAIL = "functional_fail"
    SUCCESS = "success"            # confirmed findings existed and were neutralized
    CLEAN = "clean"               # no candidate findings at all (still: UNCONFIRMED != SECURE)
    ORACLE_GAP = "oracle_gap"     # candidates exist but none confirmable -> honestly unconfirmed
    ITER_BUDGET = "iter_budget"   # confirmed findings remain; iteration budget exhausted
    STAGNATION = "stagnation"     # loop cycled / stopped reducing the confirmed set
    COMPILE_FAIL = "compile_fail" # repairs failed to compile repeatedly


#: Verdicts that pass the confirmed-exploit gate (guardrail mode).
GATE_PASSING = frozenset({LoopVerdict.SUCCESS, LoopVerdict.CLEAN, LoopVerdict.ORACLE_GAP})


# --------------------------------------------------------------------------- #
# Value objects                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ToolVersions:
    """Recorded into every artifact for reproducibility (plan §5, §9)."""

    python: str = ""
    forge: str = ""
    slither: str = ""
    solc: str = ""
    echidna: str = ""
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class GasProfile:
    """Per-function gas (from `forge test --gas-report` / snapshots)."""

    entries: dict[str, int] = field(default_factory=dict)

    def total(self) -> int:
        return sum(self.entries.values())

    def delta(self, baseline: GasProfile) -> dict[str, int]:
        """Signed per-function gas change vs a baseline (missing keys treated as 0)."""
        keys = set(self.entries) | set(baseline.entries)
        return {k: self.entries.get(k, 0) - baseline.entries.get(k, 0) for k in sorted(keys)}

    def total_delta(self, baseline: GasProfile) -> int:
        return self.total() - baseline.total()


# --------------------------------------------------------------------------- #
# Benchmark task (human-owned; see plan §4 anti-circularity)                   #
# --------------------------------------------------------------------------- #
@dataclass
class TaskSpec:
    """A benchmark task. The generator sees only `nl_spec`; the tests, invariants
    and PoCs are human-owned and never shown to the model under test (plan §4)."""

    id: str
    category: VulnClass
    nl_spec: str
    solc_pragma: str
    contract_name: str
    support_sources: dict[str, str] = field(default_factory=dict)
    task_dir: str | None = None   # root of the on-disk benchmark task (tests/, exploits/, ...)


# --------------------------------------------------------------------------- #
# Pipeline artifacts                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class GeneratedArtifact:
    """A produced contract."""

    task_id: str
    model: str
    source: str                      # the Solidity source
    contract_name: str

    support_sources: dict[str, str] = field(default_factory=dict)
    solc_pragma: str = "^0.8.24"

    def code_hash(self) -> str:
        import hashlib
        import json

        payload = self.source
        if self.support_sources:
            payload += json.dumps(self.support_sources, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    id: str
    detector: str                    # e.g. "slither:reentrancy-eth"
    swc_class: VulnClass
    severity: Severity
    location: str = ""
    status: FindingStatus = FindingStatus.CANDIDATE
    confirmed_by: str | None = None   # poc_id that confirmed it, if any


@dataclass
class ExploitResult:
    poc_id: str
    swc_class: VulnClass
    success: bool
    revert_reason: str = ""
    gas_used: int = 0
    executed: bool = True


@dataclass
class RepairAttempt:
    iteration: int
    source_hash: str
    outcome: RepairOutcome
    reason: RejectReason | None = None
    fates: dict[str, FindingFate] = field(default_factory=dict)  # finding_id -> fate
    gas_delta_total: int = 0
    exploit_results: list[ExploitResult] = field(default_factory=list)
    detector_findings: list[str] = field(default_factory=list)   # finding ids still raised
    detector_classes: list[VulnClass] = field(default_factory=list)  # vuln classes Slither flagged


@dataclass
class EvalRecord:
    """The full, serializable record of one task/model run (plan §9)."""

    task_id: str
    category: VulnClass
    model: str
    versions: ToolVersions
    verdict: LoopVerdict
    gate_pass: bool
    findings: list[Finding] = field(default_factory=list)
    initial_exploits: list[ExploitResult] = field(default_factory=list)
    repairs: list[RepairAttempt] = field(default_factory=list)
    false_fixes: int = 0             # count of DETECTOR_SILENCED events (RQ1)
    initial_source_hash: str = ""
    final_source_hash: str = ""
    gas_baseline: GasProfile = field(default_factory=GasProfile)
    gas_final: GasProfile = field(default_factory=GasProfile)
    coverage_baseline: dict = field(default_factory=dict)
    coverage_final: dict = field(default_factory=dict)
    timestamps: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    solc_pragma: str = ""
    sources: dict[str, dict] = field(default_factory=dict)
    model_calls: list[dict] = field(default_factory=list)

    def gas_tax_total(self) -> int:
        """RQ3: total gas overhead of the accepted repairs vs the baseline."""
        return self.gas_final.total_delta(self.gas_baseline)
