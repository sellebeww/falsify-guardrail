"""Load on-disk benchmark tasks and build repair strategies (plan §7).

A task directory contains: task.json (metadata + role->file map), spec.md (the only
thing the model sees), reference/*.sol (fixture contracts keyed by role), tests/*.t.sol
(human functional suite), exploits/*.t.sol (human PoCs), properties/ (invariants, v0.2).

`roles` maps canonical roles to reference files:
  - initial    : the as-generated contract the loop starts from (usually buggy; for an
                 RQ2 false-positive task it is actually safe but Slither flags it)
  - bad_fix    : a plausible-but-wrong "fix" (silences the detector or looks guarded,
                 yet the PoC still succeeds) — used to exercise false-fix detection
  - good_fix   : a genuine fix (PoC no longer succeeds, functional tests still pass)

Only `initial` is required; bad_fix/good_fix are optional (a strategy skips roles a task
does not define).

A *strategy* is a named repair sequence over these roles — a scripted control whose
behaviour we compare on identical tasks in fixture benchmark mode.
"""

from __future__ import annotations

import json
from pathlib import Path

from falsify.generators.fixture import FixtureGenerator
from falsify.types import TaskSpec, VulnClass

# Named fixture strategies; these are not live models.
STRATEGIES: dict[str, list[str]] = {
    "proper_fixer": ["good_fix"],                      # fixes correctly on the first try
    "detector_gamer": ["bad_fix", "bad_fix", "bad_fix"],  # only games the detector, never fixes
    "eventually_fixer": ["bad_fix", "good_fix"],       # games once, then fixes for real
}

# The strategy the single-run `demo`/`run` uses (reproduces vuln -> bad -> good).
DEFAULT_STRATEGY = "eventually_fixer"


def _meta(task_dir: Path) -> dict:
    return json.loads((task_dir / "task.json").read_text())


def load_task(task_dir: str | Path) -> TaskSpec:
    task_dir = Path(task_dir)
    meta = _meta(task_dir)
    spec_file = meta.get("spec_file", "spec.md")
    spec_path = task_dir / spec_file
    nl_spec = spec_path.read_text() if spec_path.exists() else meta.get("nl_spec", "")
    return TaskSpec(
        id=meta["id"],
        category=VulnClass(meta["category"]),
        nl_spec=nl_spec,
        solc_pragma=meta.get("solc_pragma", "^0.8.24"),
        contract_name=meta["contract_name"],
        task_dir=str(task_dir),
        support_sources={p.relative_to(task_dir / "support").as_posix(): p.read_text()
                         for p in sorted((task_dir / "support").rglob("*.sol"))},
    )


def build_generator(
    task_dir: str | Path, strategy: str = DEFAULT_STRATEGY, name: str | None = None
) -> FixtureGenerator:
    """Build a deterministic generator: initial = `vulnerable`, repairs = the strategy's roles."""
    task_dir = Path(task_dir)
    meta = _meta(task_dir)
    roles = meta["roles"]
    ref = task_dir / "reference"
    initial = (ref / roles["initial"]).read_text()
    repairs = [(ref / roles[r]).read_text() for r in STRATEGIES[strategy] if r in roles]
    return FixtureGenerator(
        initial_source=initial,
        repair_sources=repairs,
        contract_name=meta["contract_name"],
        name=name or f"fixture:{strategy}",
    )


def build_replay_generator(task_dir: str | Path, strategy: str = DEFAULT_STRATEGY):
    """An LLMGenerator whose transport REPLAYS the task's reference contracts as if a model
    produced them. Exercises the real adapter (prompt construction, Solidity extraction,
    loop wiring) end-to-end, offline and deterministically (plan §9 replay mode)."""
    from falsify.generators.llm import LLMGenerator, RecordedTransport

    task_dir = Path(task_dir)
    meta = _meta(task_dir)
    roles = meta["roles"]
    ref = task_dir / "reference"

    def wrap(role: str) -> str:
        return f"```solidity\n{(ref / roles[role]).read_text()}\n```"

    responses = [wrap("initial")] + [wrap(r) for r in STRATEGIES[strategy] if r in roles]
    return LLMGenerator(RecordedTransport(responses), name=f"llm-replay:{strategy}")


def role_source(task_dir: str | Path, role: str) -> str:
    task_dir = Path(task_dir)
    return (task_dir / "reference" / _meta(task_dir)["roles"][role]).read_text()


def echidna_property(task_dir: str | Path) -> tuple[str, str] | None:
    """(property_source, property_contract) for a task's human-authored Echidna invariant,
    or None if the task defines none."""
    task_dir = Path(task_dir)
    ec = _meta(task_dir).get("echidna")
    if not ec:
        return None
    src = (task_dir / "properties" / ec["property_file"]).read_text()
    return src, ec["property_contract"]


def discover_tasks(root: str | Path) -> list[Path]:
    """All task directories under `root` (each containing a task.json), sorted."""
    root = Path(root)
    return sorted(p.parent for p in root.rglob("task.json"))
