"""Regression coverage for external-source guardrails and incomplete tool evidence."""
import json
from pathlib import Path

import pytest

from falsify import benchmark
from falsify.coverage import parse_lcov
from falsify.evaluator import BenchmarkResult, RunResult
from falsify.sources import write_sources
from falsify.types import ExploitResult, LoopVerdict, RepairOutcome
from tests.fakes import FakeAnalyzer, FakeOracle, FakeTester, ScriptedGenerator
from tests.test_orchestrator import RE, build, make_task


def test_functional_failure_cannot_pass_clean_gate():
    rec = build(ScriptedGenerator('CLEAN', []), FakeAnalyzer({}),
                FakeOracle({'p': RE}, {}), tester=FakeTester(frozenset({'CLEAN'}))).run(make_task())
    assert not rec.gate_pass
    assert rec.verdict is LoopVerdict.FUNCTIONAL_FAIL


def test_failed_or_missing_oracle_cannot_be_accepted_as_repair():
    class BrokenOracle(FakeOracle):
        def run(self, artifact, task):
            if artifact.source == 'BROKEN':
                return [ExploitResult('p', RE, False, executed=False)]
            return super().run(artifact, task)

    rec = build(ScriptedGenerator('VULN', ['BROKEN']), FakeAnalyzer({'VULN': [RE]}),
                BrokenOracle({'p': RE}, {'VULN': {'p'}})).run(make_task())
    assert not rec.gate_pass
    assert all(r.outcome is RepairOutcome.REJECTED for r in rec.repairs)
    matrix = BenchmarkResult([RunResult('test', rec.task_id, RE, rec)]).confusion()
    assert matrix.tn == 0  # broken oracle never counts as a negative observation


def test_every_initial_exploit_must_be_stopped_even_in_same_class():
    rec = build(ScriptedGenerator('VULN', ['HALF']), FakeAnalyzer({'VULN': [RE]}),
                FakeOracle({'p1': RE, 'p2': RE}, {'VULN': {'p1', 'p2'}, 'HALF': {'p2'}})
                ).run(make_task())
    assert not rec.gate_pass


def test_analyzer_error_blocks_with_record():
    class BrokenAnalyzer:
        def analyze(self, artifact):
            raise RuntimeError('tool unavailable')

    rec = build(ScriptedGenerator('C', []), BrokenAnalyzer(), FakeOracle({'p': RE}, {}))
    assert rec.run(make_task()).verdict is LoopVerdict.TOOL_ERROR


def test_empty_oracle_blocks():
    rec = build(ScriptedGenerator('C', []), FakeAnalyzer({}), FakeOracle({}, {})).run(make_task())
    assert not rec.gate_pass


def test_lcov_excludes_test_harness_and_preserves_denominators():
    text = ('SF:src/A.sol\nLF:5\nLH:3\nFNF:2\nFNH:1\nend_of_record\n'
            'SF:test/A.t.sol\nLF:100\nLH:100\nFNF:10\nFNH:10\nend_of_record\n'
            'SF:src/lib/B.sol\nLF:4\nLH:0\nFNF:1\nFNH:0\nend_of_record\n')
    cov = parse_lcov(text)
    assert (cov['lines_hit'], cov['lines_found']) == (3, 9)
    assert (cov['functions_hit'], cov['functions_found']) == (1, 3)
    assert not parse_lcov('')['available']


@pytest.mark.parametrize('path', ['../Escape.sol', '/tmp/Escape.sol', 'A.sol', 'x.txt'])
def test_support_sources_cannot_escape_or_replace_entry(tmp_path, path):
    with pytest.raises(ValueError):
        write_sources(tmp_path, 'A', 'contract A {}', {path: 'bad'})


def test_dataset_has_independent_properties_and_multiple_compilers():
    paths = benchmark.discover_tasks(Path('benchmark/tasks'))
    assert len(paths) == 8
    tasks = [benchmark.load_task(p) for p in paths]
    assert len({t.id for t in tasks}) == 8
    assert len({t.solc_pragma for t in tasks}) >= 2
    assert any(t.support_sources for t in tasks)
    for path in paths:
        assert benchmark.echidna_property(path)
        assert list((path / 'tests').glob('*.t.sol'))
        assert list((path / 'exploits').glob('*.t.sol'))
        assert 'initial' in json.loads((path / 'task.json').read_text())['roles']


def test_skipped_exploit_is_not_evidence_of_neutralization(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from falsify.oracle.foundry import ForgeProject

    skipped = {'test/Poc.t.sol:Poc': {'test_results': {'test_attack()': {'status': 'Skipped'}}}}
    monkeypatch.setattr('falsify.oracle.foundry.subprocess.run',
                        lambda *a, **kw: SimpleNamespace(stdout=json.dumps(skipped), returncode=0))
    with ForgeProject('contract A {}', 'A', '^0.8.24') as project:
        executed, _ = project.test()
    assert not executed


def test_oracle_blind_spot_is_not_counted_as_detector_silencing():
    rec = build(ScriptedGenerator('VULN', ['STILL']), FakeAnalyzer({}),
                FakeOracle({'p': RE}, {'VULN': {'p'}, 'STILL': {'p'}})).run(make_task())
    assert not rec.gate_pass
    assert rec.false_fixes == 0
