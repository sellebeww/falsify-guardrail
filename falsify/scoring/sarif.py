"""SARIF 2.1.0 output for code-scanning integrations.

Confirmed findings are errors, unconfirmed detector findings are warnings (they are not
proven false positives), and a blocked gate without a confirmed finding (tool error,
functional failure) is reported as an error on the entry file so it is never silent.
"""

from __future__ import annotations

import re

from falsify import __version__
from falsify.redact import sanitize
from falsify.types import EvalRecord, FindingStatus

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LINE = re.compile(r"#L(\d+)$")

_RULES = {
    "falsify/confirmed": "A supplied exploit succeeded against the contract.",
    "falsify/unconfirmed": "A detector finding that no supplied exploit confirmed. "
                           "Unconfirmed is not proof of safety.",
    "falsify/blocked": "The guardrail blocked without a confirmed finding, for example a "
                       "tool error, a harness that cannot fire, or failing functional tests.",
}


def _location(uri: str, location: str) -> dict:
    physical: dict = {"artifactLocation": {"uri": uri}}
    m = _LINE.search(location or "")
    if m:
        physical["region"] = {"startLine": int(m.group(1))}
    return {"physicalLocation": physical}


def _result(rule: str, level: str, text: str, uri: str, location: str = "") -> dict:
    return {"ruleId": rule, "level": level, "message": {"text": text},
            "locations": [_location(uri, location)]}


def to_sarif(record: EvalRecord, source_uri: str) -> dict:
    results = []
    for f in record.findings:
        cls = f.swc_class.value.replace("_", " ")
        if f.status is FindingStatus.CONFIRMED:
            results.append(_result(
                "falsify/confirmed", "error",
                f"Confirmed {cls}: exploit {f.confirmed_by} succeeded ({f.detector}).",
                source_uri, f.location))
        elif f.status is FindingStatus.UNCONFIRMED:
            results.append(_result(
                "falsify/unconfirmed", "warning",
                f"Unconfirmed {cls} candidate from {f.detector}; no supplied exploit "
                "succeeded. This is not proof of safety.", source_uri, f.location))
    if not record.gate_pass and not any(r["ruleId"] == "falsify/confirmed" for r in results):
        detail = "; ".join(sanitize(n) for n in record.notes) or "no further detail"
        results.append(_result(
            "falsify/blocked", "error",
            f"Guardrail blocked with verdict {record.verdict.value}: {detail}", source_uri))
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Falsify",
                "version": __version__,
                "informationUri": "https://github.com/sellebeww/falsify-guardrail",
                "rules": [{"id": rid, "shortDescription": {"text": text}}
                          for rid, text in _RULES.items()],
            }},
            "results": results,
            "properties": {"verdict": record.verdict.value, "gate_pass": record.gate_pass,
                           "task_id": record.task_id},
        }],
    }
