"""Capture tool versions into a ToolVersions record (plan §5, §9).

Recorded into every artifact so a run is reproducible and diffable.
"""

from __future__ import annotations

import platform
import re
import subprocess

from falsify import toolpaths
from falsify.types import ToolVersions


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=toolpaths.subprocess_env(),
        )
        return (out.stdout + out.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:  # tool missing / not runnable
        return f"unavailable ({exc.__class__.__name__})"


def _first_semver(text: str) -> str:
    m = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?", text)
    return m.group(0) if m else text.splitlines()[0][:80] if text else ""


def capture() -> ToolVersions:
    forge = _run([toolpaths.forge_bin(), "--version"])
    slither = _run([toolpaths.slither_bin(), "--version"])
    solc = _run([toolpaths.solc_bin(), "--version"])
    echidna = _run([toolpaths.echidna_bin(), "--version"])
    return ToolVersions(
        python=platform.python_version(),
        forge=_first_semver(forge),
        slither=_first_semver(slither),
        solc=_first_semver(solc),
        echidna=_first_semver(echidna),
        extra={"forge_full": forge.splitlines()[0][:120] if forge else ""},
    )
