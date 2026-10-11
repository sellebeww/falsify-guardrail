"""Second layer: untrusted text is sanitized wherever it is persisted or displayed."""

from __future__ import annotations

import json

from falsify.artifacts import record_to_dict
from falsify.redact import REASON_LIMIT, sanitize
from falsify.scoring.report import render_record
from falsify.types import (
    EvalRecord,
    ExploitResult,
    LoopVerdict,
    RepairAttempt,
    RepairOutcome,
    ToolVersions,
    VulnClass,
)

SENTINEL = "sentinel-6f1d2c9a-not-a-real-secret"


def _record(reason: str, note: str = "") -> EvalRecord:
    result = ExploitResult("Reentrancy::test_x()", VulnClass.REENTRANCY, False, reason)
    return EvalRecord(
        task_id="t", category=VulnClass.REENTRANCY, model="m", versions=ToolVersions(),
        verdict=LoopVerdict.TOOL_ERROR, gate_pass=False, initial_exploits=[result],
        repairs=[RepairAttempt(1, "h", RepairOutcome.REJECTED, exploit_results=[result])],
        notes=[note] if note else [],
    )


def test_host_secret_is_redacted_from_every_persisted_reason(monkeypatch):
    monkeypatch.setenv("FALSIFY_TEST_SECRET", SENTINEL)
    record = _record(f"leak: {SENTINEL}", note=f"compiler said {SENTINEL}")
    artifact = json.dumps(record_to_dict(record))
    assert SENTINEL not in artifact
    assert "[redacted:FALSIFY_TEST_SECRET]" in artifact
    assert SENTINEL not in render_record(record)


def test_sanitizing_the_artifact_leaves_the_oracle_data_untouched(monkeypatch):
    monkeypatch.setenv("FALSIFY_TEST_SECRET", SENTINEL)
    record = _record(SENTINEL)
    record_to_dict(record)
    assert record.initial_exploits[0].revert_reason == SENTINEL


def test_hex_encoded_secret_is_redacted(monkeypatch):
    monkeypatch.setenv("SOME_VALUE", SENTINEL)
    hexed = "0x" + SENTINEL.encode().hex().upper()
    assert SENTINEL.encode().hex() not in sanitize(f"custom error 0xdeadbeef: {hexed}").lower()


def test_secret_split_by_control_characters_is_still_redacted(monkeypatch):
    monkeypatch.setenv("SOME_VALUE", SENTINEL)
    split = SENTINEL[:6] + "\x1b[0m" + SENTINEL[6:]
    assert SENTINEL not in sanitize(split)


def test_known_credential_formats_are_redacted():
    # Built at runtime so the repository contains no token-shaped literals.
    tokens = ["sk-" + "A1b2" * 6, "gh" + "p_" + "x" * 36, "AK" + "IA" + "ABCDEFGHIJKLMNOP"]
    for token in tokens:
        assert token not in sanitize(f"reverted with {token}")


def test_control_characters_and_bidi_overrides_are_stripped():
    text = sanitize("NOT\x1b[31m EXPLOITED\x00\u202e\nnext line")
    assert text == "NOT EXPLOITED next line"


def test_selectors_hashes_and_ordinary_reasons_survive():
    digest = "ab" * 32
    reason = f"custom error 0x1a2b3c4d: {digest}"
    assert sanitize(reason) == reason
    assert sanitize("NOT EXPLOITED") == "NOT EXPLOITED"


def test_long_reason_is_capped_but_keeps_its_prefix():
    reason = "custom error 0x1a2b3c4d: " + "z" * 5000
    out = sanitize(reason)
    assert out.startswith("custom error 0x1a2b3c4d: ")
    assert len(out) < REASON_LIMIT + 40
