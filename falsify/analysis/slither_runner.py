"""Slither-backed static analyzer (plan §5).

Produces CANDIDATE findings only — fast and noisy, never a security gate. Slither
exits non-zero when it has findings, so we parse the JSON regardless of exit code.
Detectors are mapped to the vuln classes the oracle can confirm; unmapped detectors
are ignored for MVP (documented in docs/limitations.md).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from falsify import toolpaths
from falsify.types import Finding, GeneratedArtifact, Severity, VulnClass

# Slither detector `check` -> our vuln class (MVP scope).
_DETECTOR_CLASS: dict[str, VulnClass] = {
    "reentrancy-eth": VulnClass.REENTRANCY,
    "reentrancy-no-eth": VulnClass.REENTRANCY,
    "reentrancy-benign": VulnClass.REENTRANCY,
    "reentrancy-events": VulnClass.REENTRANCY,
    "reentrancy-unlimited-gas": VulnClass.REENTRANCY,
    "suicidal": VulnClass.ACCESS_CONTROL,
    "arbitrary-send-eth": VulnClass.ACCESS_CONTROL,
    "arbitrary-send-erc20": VulnClass.ACCESS_CONTROL,
    "unprotected-upgrade": VulnClass.ACCESS_CONTROL,
    "tx-origin": VulnClass.ACCESS_CONTROL,
}

_IMPACT_SEVERITY: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}


class SlitherAnalyzer:
    name = "slither"

    def analyze(self, artifact: GeneratedArtifact) -> list[Finding]:
        with tempfile.TemporaryDirectory(prefix="falsify-slither-") as tmp:
            sol = Path(tmp) / f"{artifact.contract_name}.sol"
            from falsify.oracle.foundry import _solc_pin
            from falsify.sources import write_sources

            write_sources(Path(tmp), artifact.contract_name, artifact.source,
                          artifact.support_sources)
            env = toolpaths.subprocess_env()
            env["SOLC_VERSION"] = _solc_pin(artifact.solc_pragma)
            out = Path(tmp) / "slither.json"
            subprocess.run(
                [toolpaths.slither_bin(), str(sol), "--json", str(out)],
                cwd=tmp,
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=180,
            )
            if not out.exists():
                raise RuntimeError("Slither did not produce a report")
            data = json.loads(out.read_text() or "{}")
            if not data.get("success"):
                raise RuntimeError("Slither analysis failed")

        findings: list[Finding] = []
        for i, det in enumerate(data.get("results", {}).get("detectors", [])):
            check = det.get("check", "")
            swc = _DETECTOR_CLASS.get(check)
            if swc is None:
                continue  # unmapped for MVP
            findings.append(
                Finding(
                    id=f"slither:{check}:{i}",
                    detector=f"slither:{check}",
                    swc_class=swc,
                    severity=_IMPACT_SEVERITY.get(det.get("impact", ""), Severity.MEDIUM),
                    location=_first_location(det),
                )
            )
        return findings


def _first_location(det: dict) -> str:
    for el in det.get("elements", []):
        sm = el.get("source_mapping", {})
        lines = sm.get("lines") or []
        if lines:
            fn = Path(sm.get("filename_short", "")).name
            return f"{fn}#L{lines[0]}"
    return ""
