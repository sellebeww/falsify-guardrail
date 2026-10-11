"""Record a live campaign once, then replay it offline with identical results."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from falsify import evaluator
from falsify.generators.http import ModelConfig, build_model
from falsify.generators.transcript import TranscriptStore
from falsify.types import LoopVerdict, ToolVersions, VulnClass
from tests.fakes import FakeAnalyzer, FakeCompiler, FakeOracle, FakeTester
from tests.test_http_transport import config, server  # noqa: F401  (pytest fixture)

_TASK = Path(__file__).resolve().parent.parent / "benchmark/tasks/reentrancy/task_001"


@pytest.fixture
def offline_tools(monkeypatch):
    monkeypatch.setattr(evaluator, "SlitherAnalyzer", lambda: FakeAnalyzer({}))
    monkeypatch.setattr(evaluator, "FoundryCompiler", FakeCompiler)
    monkeypatch.setattr(evaluator, "FoundryFunctionalTester", FakeTester)
    monkeypatch.setattr(evaluator, "FoundryOracle",
                        lambda: FakeOracle({"p": VulnClass.REENTRANCY}, {}))
    monkeypatch.setattr(evaluator.versions, "capture", ToolVersions)


def reply(n: int) -> dict:
    return {"choices": [{"message": {"content": f"```solidity\ncontract Vault {{}} // {n}\n```"}}],
            "usage": {"total_tokens": 10 + n}}


def one_task(tmp_path: Path) -> Path:
    root = tmp_path / "tasks"
    shutil.copytree(_TASK, root / "t1")
    return root


def test_replay_reproduces_a_recorded_campaign_without_requests(server, tmp_path, offline_tools):  # noqa: F811
    tasks = one_task(tmp_path)
    server.queue = [(200, reply(n), {}) for n in range(3)]
    models = [ModelConfig("first", "model-a", config(server).endpoint)]
    transcript = tmp_path / "transcript.jsonl"

    live = evaluator.run_benchmark(tasks, models=models, repetitions=3, record_path=transcript)
    sent = len(server.requests)
    replayed = evaluator.run_benchmark(tasks, models=models, repetitions=3,
                                       replay_path=transcript)

    assert len(server.requests) == sent  # nothing reached the endpoint
    live_sources = [r.record.sources for r in live.runs]
    assert len({json.dumps(s, sort_keys=True) for s in live_sources}) == 3  # distinct per rep
    assert [r.record.sources for r in replayed.runs] == live_sources  # each rep its own
    assert [c["usage"] for r in replayed.runs for c in r.record.model_calls] == \
        [c["usage"] for r in live.runs for c in r.record.model_calls]
    assert all(c["replayed"] for r in replayed.runs for c in r.record.model_calls)


def test_replay_that_diverges_from_the_recording_is_a_tool_error(server, tmp_path, offline_tools):  # noqa: F811
    tasks = one_task(tmp_path)
    models = [ModelConfig("first", "model-a", config(server).endpoint)]
    transcript = tmp_path / "transcript.jsonl"
    evaluator.run_benchmark(tasks, models=models, record_path=transcript)

    (tasks / "t1" / "spec.md").write_text("A different specification.")
    result = evaluator.run_benchmark(tasks, models=models, replay_path=transcript)
    [run] = result.runs
    assert run.record.verdict is LoopVerdict.TOOL_ERROR
    assert any("diverged" in n for n in run.record.notes)


def test_replay_needs_no_credentials(tmp_path):
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")
    cfg = ModelConfig("m", "m", "https://example.invalid/v1/chat",
                      api_key_env="FALSIFY_UNSET_KEY_FOR_TEST")
    generator = build_model(cfg, replay=TranscriptStore(transcript))
    assert generator.name == "replay:m"


def test_record_and_replay_are_exclusive(tmp_path):
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("")
    cfg = ModelConfig("m", "m", "http://localhost:1/chat")
    with pytest.raises(ValueError):
        build_model(cfg, record=transcript, replay=TranscriptStore(transcript))


def test_corrupt_transcript_is_rejected(tmp_path):
    transcript = tmp_path / "t.jsonl"
    transcript.write_text('{"model": "m"}\n')
    with pytest.raises(ValueError, match="line 1"):
        TranscriptStore(transcript)


def test_record_and_replay_require_live_models(tmp_path):
    with pytest.raises(ValueError):
        evaluator.run_benchmark("benchmark/tasks", record_path=tmp_path / "t.jsonl")
