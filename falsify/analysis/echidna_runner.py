"""Echidna property-fuzzing checker (plan §5): an INDEPENDENT, human-authored oracle.

Echidna fuzzes transactions from many senders trying to falsify `echidna_*` invariants
written by us (never by the model under test — plan §4). It is report-only and optional:
the loop's gate remains the deterministic Foundry PoC. Echidna serves as a second oracle
that cross-checks results and can catch violations a single hand-written PoC misses.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from falsify import toolpaths

# Fixed seed + single worker make every campaign reproducible (plan §9).
_CONFIG = (
    "testMode: property\nallContracts: true\ntestLimit: {limit}\n"
    "seed: {seed}\nworkers: 1\n"
)
_RESULT_RE = re.compile(r"(echidna_\w+):\s*(passing|passed|failed)", re.IGNORECASE)
TIMEOUT = 300


@dataclass
class EchidnaResult:
    available: bool
    passed: bool = False
    properties: dict[str, bool] = field(default_factory=dict)  # name -> held?
    raw: str = ""

    @property
    def failed_properties(self) -> list[str]:
        return [name for name, held in self.properties.items() if not held]


def parse_output(text: str) -> dict[str, bool]:
    """Map each `echidna_*` property to whether it held (True) or was falsified (False)."""
    return {name: verdict.lower() != "failed" for name, verdict in _RESULT_RE.findall(text)}


class EchidnaChecker:
    def __init__(self, test_limit: int = 5000, seed: int = 1337) -> None:
        self.test_limit = test_limit
        self.seed = seed

    def available(self) -> bool:
        bin_ = toolpaths.echidna_bin()
        return Path(bin_).exists() or bin_ != "echidna"

    def run(
        self,
        contract_source: str,
        contract_name: str,
        property_source: str,
        property_contract: str,
        solc_pragma: str = "^0.8.24",
    ) -> EchidnaResult:
        if not self.available():
            return EchidnaResult(available=False)
        with tempfile.TemporaryDirectory(prefix="falsify-echidna-") as tmp:
            d = Path(tmp)
            (d / f"{contract_name}.sol").write_text(contract_source)
            (d / f"{property_contract}.sol").write_text(property_source)
            (d / "echidna.yaml").write_text(_CONFIG.format(limit=self.test_limit, seed=self.seed))
            proc = subprocess.run(
                [
                    toolpaths.echidna_bin(),
                    f"{property_contract}.sol",
                    "--contract",
                    property_contract,
                    "--config",
                    "echidna.yaml",
                ],
                cwd=d,
                capture_output=True,
                text=True,
                check=False,
                env=toolpaths.subprocess_env(),
                timeout=TIMEOUT,
            )
        out = proc.stdout + proc.stderr
        props = parse_output(out)
        return EchidnaResult(
            available=True,
            passed=bool(props) and all(props.values()),
            properties=props,
            raw=out[-4000:],
        )
