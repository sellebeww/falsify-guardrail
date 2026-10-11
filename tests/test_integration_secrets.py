"""A contract under test must not be able to read host secrets and smuggle them out.

The contract below asks the Foundry cheatcode address for an environment variable and
reverts with its value. Before environment isolation, that value reached the exploit
result's revert reason and from there the JSON artifact uploaded by CI.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from falsify import toolpaths

pytestmark = pytest.mark.integration

_REPO = Path(__file__).resolve().parent.parent
_TASK = _REPO / "benchmark" / "tasks" / "reentrancy" / "task_001"
SENTINEL_VAR = "FALSIFY_TEST_SECRET"
SENTINEL = "sentinel-6f1d2c9a-not-a-real-secret"

EXFILTRATING_VAULT = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface Vm {{
    function envString(string calldata name) external view returns (string memory);
}}

contract Vault {{
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    mapping(address => uint256) public balances;

    function deposit() external payable {{
        balances[msg.sender] += msg.value;
    }}

    function withdraw() external view {{
        revert(vm.envString("{SENTINEL_VAR}"));
    }}
}}
"""


def _have_tools() -> bool:
    forge, slither = toolpaths.forge_bin(), toolpaths.slither_bin()
    return bool((os.path.exists(forge) or shutil.which(forge))
                and (os.path.exists(slither) or shutil.which(slither)))


@pytest.mark.skipif(not _have_tools(), reason="Foundry/Slither not installed")
def test_contract_cannot_exfiltrate_host_env_through_artifacts(tmp_path, monkeypatch, capsys):
    from falsify.cli import main

    monkeypatch.setenv(SENTINEL_VAR, SENTINEL)
    source = tmp_path / "Vault.sol"
    source.write_text(EXFILTRATING_VAULT)
    out = tmp_path / "guardrail.json"

    main(["check", "--task", str(_TASK), "--source", str(source), "--out", str(out)])
    printed = capsys.readouterr()
    artifact = out.read_text()

    assert SENTINEL not in artifact
    assert SENTINEL not in printed.out + printed.err

    # The contract really ran under the oracle; otherwise the absence proves nothing.
    exploits = json.loads(artifact)["initial_exploits"]
    assert exploits and all(e["executed"] for e in exploits)
    assert any(SENTINEL_VAR in e["revert_reason"] for e in exploits), exploits
