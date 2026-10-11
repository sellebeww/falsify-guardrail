"""Tool subprocesses execute untrusted Solidity, so they must not inherit host secrets."""

from __future__ import annotations

from pathlib import Path

from falsify import toolpaths

SENTINEL = "sentinel-6f1d2c9a-not-a-real-secret"


def _leaks(env: dict[str, str]) -> list[str]:
    return [k for k, v in env.items() if SENTINEL in v]


def test_host_secrets_are_not_inherited(monkeypatch):
    for var in ("FALSIFY_TEST_SECRET", "MODEL_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(var, SENTINEL)
    env = toolpaths.subprocess_env()
    assert _leaks(env) == []
    assert set(env) <= toolpaths.SUBPROCESS_ENV_KEYS


def test_tool_configuration_cannot_be_injected_through_env(monkeypatch):
    # FOUNDRY_* variables reconfigure forge (e.g. FOUNDRY_FFI=true enables shell access).
    monkeypatch.setenv("FOUNDRY_FFI", "true")
    monkeypatch.setenv("FOUNDRY_FS_PERMISSIONS", '[{access="read", path="/"}]')
    env = toolpaths.subprocess_env()
    assert not any(k.startswith(("FOUNDRY_", "DAPP_")) for k in env)


def test_home_is_disposable_not_the_host_home():
    env = toolpaths.subprocess_env()
    home = Path(env["HOME"])
    assert home != Path.home()
    assert home.is_dir()
    assert toolpaths.subprocess_env()["HOME"] == env["HOME"]  # one per process, not per call


def test_pinned_solc_is_first_on_path(tmp_path, monkeypatch):
    artifact = tmp_path / "artifacts" / "solc-0.8.99" / "solc-0.8.99"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("#!/bin/sh\n")
    artifact.chmod(0o755)
    monkeypatch.setenv("SOLC_SELECT_DIR", str(tmp_path))

    env = toolpaths.subprocess_env(solc_version="0.8.99")
    first = Path(env["PATH"].split(":")[0])
    assert (first / "solc").resolve() == artifact.resolve()
    assert env["SOLC_VERSION"] == "0.8.99"
