"""Exercise actual HTTP serialization via a loopback mock server, never a paid API."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from falsify.generators.http import HTTPTransport, ModelConfig, load_models
from falsify.generators.llm import LLMGenerator


@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            status, reply, headers = (self.server.queue.pop(0) if self.server.queue
                                      else (self.server.status, self.server.reply, {}))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())

        def log_message(self, *args):
            pass

    srv = HTTPServer(('127.0.0.1', 0), Handler)
    srv.requests = []
    srv.queue = []
    srv.status = 200
    srv.reply = {'choices': [{'message': {'content': '```solidity\ncontract A {}\n```'}}],
                 'usage': {'total_tokens': 20}}
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join()


def config(server):
    return ModelConfig('local', 'test-model', f'http://127.0.0.1:{server.server_port}/v1/chat/completions')


def test_real_http_adapter_roundtrip(server):
    transport = HTTPTransport(config(server))
    artifact = LLMGenerator(transport).generate('Store a number.', 'A', '^0.8.24')
    assert artifact.source == 'contract A {}'
    request = server.requests[0]
    assert request['model'] == 'test-model'
    assert request['max_tokens'] == 2048
    assert 'Store a number.' in request['messages'][1]['content']
    assert transport.calls[0]['usage']['total_tokens'] == 20


@pytest.mark.parametrize('status,reply', [(429, {}), (200, {}),
    (200, {'choices': [{'message': {'content': 'partial'}, 'finish_reason': 'length'}]})])
def test_http_errors_are_not_solidity(server, status, reply):
    server.status, server.reply = status, reply
    with pytest.raises(RuntimeError):
        HTTPTransport(config(server))('system', 'prompt')


def test_plaintext_remote_endpoint_rejected():
    with pytest.raises(ValueError):
        ModelConfig('bad', 'bad', 'http://example.com/v1/chat/completions')


def test_config_rejects_duplicate_names_before_any_requests(tmp_path):
    path = tmp_path / 'models.json'
    entry = {'name': 'same', 'model': 'a', 'endpoint': 'http://localhost:8000/chat'}
    path.write_text(json.dumps({'models': [entry, entry]}))
    with pytest.raises(ValueError, match='unique'):
        load_models(path)


def test_live_benchmark_uses_each_model_on_identical_tasks_and_checkpoints(server, tmp_path, monkeypatch):
    from falsify import evaluator
    from falsify.types import ToolVersions, VulnClass
    from tests.fakes import FakeAnalyzer, FakeCompiler, FakeOracle, FakeTester

    monkeypatch.setattr(evaluator, 'SlitherAnalyzer', lambda: FakeAnalyzer({}))
    monkeypatch.setattr(evaluator, 'FoundryCompiler', FakeCompiler)
    monkeypatch.setattr(evaluator, 'FoundryFunctionalTester', FakeTester)
    monkeypatch.setattr(evaluator, 'FoundryOracle',
                        lambda: FakeOracle({'p': VulnClass.REENTRANCY}, {}))
    monkeypatch.setattr(evaluator.versions, 'capture', ToolVersions)
    endpoint = config(server).endpoint
    models = [ModelConfig('first', 'model-a', endpoint), ModelConfig('second', 'model-b', endpoint)]
    output = tmp_path / 'live.json'
    result = evaluator.run_benchmark('benchmark/tasks', models=models, repetitions=2,
                                     checkpoint=output)
    assert result.mode == 'live'
    assert len(result.runs) == 32
    assert len(server.requests) == 32
    for start in range(0, 32, 4):
        batch = server.requests[start:start + 4]
        assert [r['model'] for r in batch] == ['model-a', 'model-a', 'model-b', 'model-b']
        assert len({r['messages'][1]['content'] for r in batch}) == 1
    saved = json.loads(output.read_text())
    assert len(saved['runs']) == 32
    assert saved['runs'][0]['record']['sources']
    assert saved['runs'][0]['record']['model_calls'][0]['usage']['total_tokens'] == 20
    assert result.pareto_by_category() == {}


def test_retries_are_off_by_default(server):
    server.queue = [(503, {}, {})]
    with pytest.raises(RuntimeError, match='503'):
        HTTPTransport(config(server))('system', 'prompt')
    assert len(server.requests) == 1


def test_opt_in_retries_honor_retry_after_then_succeed(server):
    server.queue = [(429, {}, {'Retry-After': '7'}), (503, {}, {})]
    sleeps = []
    cfg = ModelConfig('local', 'test-model', config(server).endpoint, max_retries=2,
                      retry_backoff=0.5)
    transport = HTTPTransport(cfg, sleep=sleeps.append)
    assert transport('system', 'prompt') == '```solidity\ncontract A {}\n```'
    assert sleeps == [7.0, 1.0]  # Retry-After, then exponential backoff for attempt 2
    assert transport.calls[0]['attempts'] == 3


def test_client_errors_are_never_retried(server):
    server.queue = [(400, {}, {})]
    cfg = ModelConfig('local', 'test-model', config(server).endpoint, max_retries=3)
    with pytest.raises(RuntimeError, match='400'):
        HTTPTransport(cfg, sleep=lambda s: None)('system', 'prompt')
    assert len(server.requests) == 1


def test_retry_after_is_capped(server):
    server.queue = [(429, {}, {'Retry-After': '86400'})]
    sleeps = []
    cfg = ModelConfig('local', 'test-model', config(server).endpoint, max_retries=1)
    HTTPTransport(cfg, sleep=sleeps.append)('system', 'prompt')
    assert sleeps == [60.0]


@pytest.mark.parametrize('field,value', [('max_retries', 11), ('max_retries', -1),
                                         ('retry_backoff', 0)])
def test_retry_settings_are_bounded(field, value):
    with pytest.raises(ValueError):
        ModelConfig('m', 'm', 'http://localhost:1/chat', **{field: value})
