"""Serialize EvalRecord (and friends) to a stable JSON artifact (plan §9).

Deterministic key order; enums by value; dataclasses expanded recursively so the
whole run — findings, exploit results, repair attempts, verdict, gas, tool versions —
is reproducible and diff-friendly.
"""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import Path
from typing import Any

from falsify.types import EvalRecord


def to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {to_jsonable(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    return obj


def record_to_dict(record: EvalRecord) -> dict:
    d = to_jsonable(record)
    # Derived, human-facing summary so the artifact answers the RQs at a glance.
    d["summary"] = {
        "verdict": record.verdict.value,
        "gate_pass": record.gate_pass,
        "confirmed_findings": sum(
            1 for f in record.findings if f.status.value == "confirmed"
        ),
        "unconfirmed_findings": sum(
            1 for f in record.findings if f.status.value == "unconfirmed"
        ),
        "false_fixes_detector_silenced": record.false_fixes,  # RQ1
        "repair_attempts": len(record.repairs),
        "gas_tax_total": record.gas_tax_total(),              # RQ3
        "caveat": "UNCONFIRMED != SECURE; oracle coverage is partial (see docs/limitations.md)",
    }
    return d


def write_record(record: EvalRecord, path: str | Path) -> Path:
    return _write_json(record_to_dict(record), path)


def benchmark_to_dict(result) -> dict:
    """Serialize a BenchmarkResult (duck-typed to avoid an import cycle)."""
    c = result.confusion()
    return {
        "confusion": {"tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn},
        "confusion_legend": {
            "fn": "RQ1: Slither clean but exploitable — false fixes a detector-gate approves",
            "fp": "RQ2: Slither flags but safe — false positives a detector-gate blocks on",
        },
        "per_strategy": result.per_strategy(),
        "pareto_by_category": {
            cat: [{"model": p.label, "security": p.security, "gas": p.gas} for p in pts]
            for cat, pts in result.pareto_by_category().items()
        },
        "runs": [
            {
                "strategy": r.strategy,
                "task_id": r.task_id,
                "category": r.category.value,
                "verdict": r.record.verdict.value,
                "gate_pass": r.record.gate_pass,
                "false_fixes": r.record.false_fixes,
                "gas_tax_total": r.record.gas_tax_total(),
            }
            for r in result.runs
        ],
    }


def write_benchmark(result, path: str | Path) -> Path:
    return _write_json(benchmark_to_dict(result), path)


def _write_json(data: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
