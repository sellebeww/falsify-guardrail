"""Tests for the provider-neutral LLM adapter, driven by the record/replay transport.

Verifies what Falsify controls around any model call: prompt construction, Solidity
extraction, the anti-circularity boundary, and — in the integration test — driving the real
Foundry + Slither loop with recorded model responses.
"""

from __future__ import annotations

import dataclasses
import os
import shutil

import pytest

from falsify import toolpaths
from falsify.generators.base import RepairContext
from falsify.generators.llm import (
    SYSTEM_PROMPT,
    LLMGenerator,
    RecordedTransport,
    build_repair_prompt,
    extract_solidity,
)
from falsify.types import VulnClass

RE = VulnClass.REENTRANCY


_BASE_CTX = RepairContext(
    task_id="t",
    contract_name="Vault",
    solc_pragma="^0.8.24",
    nl_spec="a vault",
    current_source="contract Vault { function withdraw() external {} }",
    iteration=1,
    confirmed_classes=[RE],
    slither_findings=["slither:reentrancy-eth [high]"],
    exploit_confirmed=True,
    functional_failures=[],
)


def _ctx(**overrides) -> RepairContext:
    return dataclasses.replace(_BASE_CTX, **overrides)


def test_extract_solidity_handles_fenced_and_plain():
    assert extract_solidity("```solidity\ncontract A {}\n```") == "contract A {}"
    assert extract_solidity("```\ncontract B {}\n```") == "contract B {}"
    assert extract_solidity("contract C {}") == "contract C {}"


def test_generate_extracts_source_from_transport_response():
    gen = LLMGenerator(RecordedTransport(["```solidity\ncontract Vault {}\n```"]), name="llm-test")
    art = gen.generate("a vault", "Vault", "^0.8.24")
    assert art.source == "contract Vault {}"
    assert art.model == "llm-test"


def test_repair_prompt_carries_signals_but_not_poc():
    prompt = build_repair_prompt(_ctx())
    assert "reentrancy" in prompt          # the class signal is present
    assert "contract Vault" in prompt      # the model's own code is present
    # PoC-only strings must never appear (they live in exploit files the model never sees).
    for leak in ("NOT EXPLOITED", "hevm cheat code", "Attacker", "invariant_"):
        assert leak not in prompt


def test_repair_sends_system_and_prompt_through_transport():
    transport = RecordedTransport(["```solidity\ncontract Vault { }\n```"])
    LLMGenerator(transport).repair(_ctx(current_source="contract Vault {}"))
    assert len(transport.prompts) == 1
    system, prompt = transport.prompts[0]
    assert system == SYSTEM_PROMPT
    assert "reentrancy" in prompt


# --------------------------------------------------------------------------- #
def _have_tools() -> bool:
    forge, slither = toolpaths.forge_bin(), toolpaths.slither_bin()
    return bool(
        (os.path.exists(forge) or shutil.which(forge))
        and (os.path.exists(slither) or shutil.which(slither))
    )


@pytest.mark.integration
@pytest.mark.skipif(not _have_tools(), reason="Foundry/Slither not installed")
def test_replay_adapter_drives_the_real_loop():
    """The LLM adapter, replaying recorded responses, drives the real loop to a fix."""
    from pathlib import Path

    from falsify import benchmark
    from falsify.analysis.slither_runner import SlitherAnalyzer
    from falsify.oracle.foundry import FoundryCompiler, FoundryFunctionalTester, FoundryOracle
    from falsify.orchestrator import Orchestrator
    from falsify.types import LoopVerdict

    task_dir = Path(__file__).resolve().parent.parent / "benchmark/tasks/reentrancy/task_001"
    orch = Orchestrator(
        generator=benchmark.build_replay_generator(task_dir, "eventually_fixer"),
        analyzer=SlitherAnalyzer(),
        oracle=FoundryOracle(),
        compiler=FoundryCompiler(),
        tester=FoundryFunctionalTester(),
    )
    rec = orch.run(benchmark.load_task(task_dir))
    assert rec.model.startswith("llm-replay")
    assert rec.false_fixes >= 1
    assert rec.verdict is LoopVerdict.SUCCESS
