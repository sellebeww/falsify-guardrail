"""Provider-neutral LLM generator/repair adapter.

The adapter owns everything model-facing that Falsify controls — prompt construction,
Solidity extraction, and the anti-circularity boundary (plan §4) — and delegates the actual
model call to an injected *transport*: any callable `(system, prompt) -> text`. Plug in a
client for whichever model you want to evaluate; Falsify ships no vendor-specific client.

`RecordedTransport` replays canned responses (plan §9 replay mode), so the adapter and the
full loop are testable offline and deterministically.

Generation sees only the spec; repair sees only the minimal RepairContext — never the PoC,
invariants, or functional-test source.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from falsify.generators.base import RepairContext
from falsify.types import GeneratedArtifact

# (system, prompt) -> raw model text.
Transport = Callable[[str, str], str]

SYSTEM_PROMPT = (
    "You are a senior Solidity engineer. Return ONE complete, compilable contract in a "
    "single ```solidity code block and nothing else. Do not include tests or comments "
    "explaining vulnerabilities."
)


def extract_solidity(text: str) -> str:
    """Pull the Solidity source out of a model response (fenced block if present)."""
    m = re.search(r"```(?:solidity)?\s*(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def build_generate_prompt(nl_spec: str, contract_name: str, solc_pragma: str) -> str:
    return (
        f"Implement a Solidity contract named `{contract_name}` using pragma "
        f"`{solc_pragma}` that satisfies this specification:\n\n{nl_spec}"
    )


def build_repair_prompt(ctx: RepairContext) -> str:
    classes = ", ".join(c.value for c in ctx.confirmed_classes) or "none"
    findings = "\n".join(f"- {s}" for s in ctx.slither_findings) or "- (none)"
    fails = ", ".join(ctx.functional_failures) or "none"
    return (
        f"The following `{ctx.contract_name}` contract (pragma `{ctx.solc_pragma}`) has a "
        f"CONFIRMED, exploitable vulnerability of class: {classes}.\n"
        f"Static-analysis findings:\n{findings}\n"
        f"Failing functional tests: {fails}\n"
        f"An automated exploit currently succeeds against it: {ctx.exploit_confirmed}.\n"
        f"Previous attempt was rejected because: {ctx.last_reject_reason or 'n/a'}.\n\n"
        "Rewrite the contract so it is no longer exploitable while preserving its intended "
        "behaviour. Do not merely rename or restructure to evade the detector — actually "
        "remove the vulnerability.\n\n"
        f"Current source:\n```solidity\n{ctx.current_source}\n```"
    )


class RecordedTransport:
    """Replays canned responses in order (clamping at the last). Records the prompts it
    received, so tests can assert the anti-circularity boundary."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._i = 0
        self.prompts: list[tuple[str, str]] = []

    def __call__(self, system: str, prompt: str) -> str:
        self.prompts.append((system, prompt))
        if not self._responses:
            return ""
        resp = self._responses[min(self._i, len(self._responses) - 1)]
        self._i += 1
        return resp


class LLMGenerator:
    def __init__(self, transport: Transport, name: str = "llm") -> None:
        self._transport = transport
        self.name = name

    def generate(self, nl_spec: str, contract_name: str, solc_pragma: str) -> GeneratedArtifact:
        raw = self._transport(SYSTEM_PROMPT, build_generate_prompt(nl_spec, contract_name, solc_pragma))
        return GeneratedArtifact(
            task_id="generate",
            model=self.name,
            source=extract_solidity(raw),
            contract_name=contract_name,
        )

    def repair(self, ctx: RepairContext) -> GeneratedArtifact:
        raw = self._transport(SYSTEM_PROMPT, build_repair_prompt(ctx))
        return GeneratedArtifact(
            task_id=ctx.task_id,
            model=self.name,
            source=extract_solidity(raw),
            contract_name=ctx.contract_name,
        )
