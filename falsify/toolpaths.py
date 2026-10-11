"""Locate external tool binaries and build the environment their subprocesses run in.

Resolution order for each tool: explicit env override -> the project's own .venv ->
the standard Foundry install dir -> whatever is on PATH. Centralised so every runner
and the version capture agree.

Tool subprocesses execute untrusted Solidity: Foundry exposes cheatcodes such as
`vm.envString` to every contract, so anything in the child environment is readable by the
contract under test. `subprocess_env` therefore passes an explicit allowlist, never the
host environment.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import tempfile
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


def echidna_bin() -> str:
    return _resolve(
        "echidna",
        "FALSIFY_ECHIDNA",
        [_VENV_BIN / "echidna", _BREW_BIN / "echidna", _BREW_BIN_INTEL / "echidna"],
    )


DEFAULT_SOLC = "0.8.24"


def solc_pin(pragma: str) -> str:
    """Turn "^0.8.24" / ">=0.8.20" into a concrete compiler version (the first one named)."""
    m = re.search(r"(\d+\.\d+\.\d+)", pragma or "")
    return m.group(1) if m else DEFAULT_SOLC


def solc_artifact(version: str) -> Path | None:
    """The solc-select binary for an exact compiler version, if one is installed.

    solc-select stores artifacts under `$VIRTUAL_ENV/.solc-select` when a venv is active
    and `~/.solc-select` otherwise, so both are searched (after an explicit override).
    """
    roots = [os.environ.get("SOLC_SELECT_DIR"),
             os.environ.get("VIRTUAL_ENV") and Path(os.environ["VIRTUAL_ENV"]) / ".solc-select",
             _VENV_BIN.parent / ".solc-select",
             Path.home() / ".solc-select"]
    for root in filter(None, roots):
        candidate = Path(root) / "artifacts" / f"solc-{version}" / f"solc-{version}"
        if candidate.is_file():
            return candidate
    return None


#: Every variable a tool subprocess may receive. Nothing else from the host passes through.
SUBPROCESS_ENV_KEYS = frozenset({
    "PATH",          # locate forge, slither, echidna and solc
    "HOME",          # a disposable directory: tools cache there, never in the host home
    "SOLC_VERSION",  # the pinned compiler, read by crytic-compile's solc-select shim
})

_sandbox_home: Path | None = None


def _home() -> Path:
    """One disposable HOME per process, removed at exit.

    It hides host dotfiles and global tool configuration such as `~/.foundry/foundry.toml`.
    """
    global _sandbox_home
    if _sandbox_home is None or not _sandbox_home.is_dir():
        _sandbox_home = Path(tempfile.mkdtemp(prefix="falsify-home-"))
        atexit.register(shutil.rmtree, _sandbox_home, True)
    return _sandbox_home


def _pinned_solc_dir(version: str) -> Path | None:
    """A directory whose `solc` is exactly `version`, independent of solc-select's HOME."""
    artifact = solc_artifact(version)
    if artifact is None:
        return None
    link_dir = _home() / "solc" / version
    link = link_dir / "solc"
    if not link.exists():
        link_dir.mkdir(parents=True, exist_ok=True)
        link.symlink_to(artifact)
    return link_dir


def subprocess_env(solc_version: str | None = None) -> dict[str, str]:
    """The complete environment for a tool subprocess (see `SUBPROCESS_ENV_KEYS`).

    PATH puts the pinned `solc` first, then the venv, Foundry and Homebrew bin dirs, so
    tools resolve regardless of the parent shell. Host secrets, model API keys and
    `FOUNDRY_*` configuration are not inherited.
    """
    dirs = [p for p in (_VENV_BIN, _FOUNDRY_BIN, _BREW_BIN, _BREW_BIN_INTEL) if p.exists()]
    pinned = _pinned_solc_dir(solc_version) if solc_version else None
    if pinned:
        dirs.insert(0, pinned)
    path = os.pathsep.join([*map(str, dirs), os.environ.get("PATH", "")]).rstrip(os.pathsep)
    env = {"PATH": path, "HOME": str(_home())}
    if solc_version:
        env["SOLC_VERSION"] = solc_version
    return env
