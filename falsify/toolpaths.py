"""Locate external tool binaries robustly (plan §5).

Resolution order for each tool: explicit env override -> the project's own .venv ->
the standard Foundry install dir -> whatever is on PATH. Centralised so every runner
and the version capture agree, and so a subprocess env can be built with the right
directories on PATH (Slither needs `solc` reachable; crytic-compile shells out to it).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VENV_BIN = _REPO_ROOT / ".venv" / "bin"
_FOUNDRY_BIN = Path(os.environ.get("FOUNDRY_DIR", Path.home() / ".foundry")) / "bin"
_BREW_BIN = Path("/opt/homebrew/bin")
_BREW_BIN_INTEL = Path("/usr/local/bin")


def _resolve(name: str, env_var: str, candidates: list[Path]) -> str:
    override = os.environ.get(env_var)
    if override:
        return override
    for c in candidates:
        if c.exists():
            return str(c)
    found = shutil.which(name)
    return found or name  # fall back to bare name; runner will surface a clear error


def forge_bin() -> str:
    return _resolve("forge", "FALSIFY_FORGE", [_FOUNDRY_BIN / "forge"])


def slither_bin() -> str:
    return _resolve("slither", "FALSIFY_SLITHER", [_VENV_BIN / "slither"])


def solc_bin() -> str:
    return _resolve("solc", "FALSIFY_SOLC", [_VENV_BIN / "solc"])


def echidna_bin() -> str:
    return _resolve(
        "echidna",
        "FALSIFY_ECHIDNA",
        [_VENV_BIN / "echidna", _BREW_BIN / "echidna", _BREW_BIN_INTEL / "echidna"],
    )


def subprocess_env() -> dict[str, str]:
    """An env whose PATH includes the venv, Foundry, and Homebrew bin dirs (so `solc`,
    `forge`, and `echidna` resolve inside child processes regardless of the parent shell;
    Echidna's crytic-compile shells out to `solc`)."""
    env = dict(os.environ)
    extra = os.pathsep.join(
        str(p) for p in (_VENV_BIN, _FOUNDRY_BIN, _BREW_BIN, _BREW_BIN_INTEL) if p.exists()
    )
    env["PATH"] = extra + os.pathsep + env.get("PATH", "") if extra else env.get("PATH", "")
    return env
