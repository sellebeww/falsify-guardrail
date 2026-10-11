"""SARIF and Markdown outputs carry the verdict faithfully and stay inert."""

from __future__ import annotations

from falsify.scoring.report import render_markdown
from falsify.scoring.sarif import to_sarif
from falsify.types import (
    EvalRecord,
    ExploitResult,
    Finding,
    FindingStatus,
    LoopVerdict,
    Severity,
    ToolVersions,
    VulnClass,
)

RE = VulnClass.REENTRANCY


def record(verdict, gate, findings=(), exploits=(), notes=()):
    return EvalRecord(task_id="reentrancy-001", category=RE, model="m", versions=ToolVersions(),
                      verdict=verdict, gate_pass=gate, findings=list(findings),
                      initial_exploits=list(exploits), notes=list(notes))


def finding(status, location="Vault.sol#L17", detector="slither:reentrancy-eth"):
    return Finding("f", detector, RE, Severity.HIGH, location, status, "Reentrancy::test()")


def results(sarif):
    return sarif["runs"][0]["results"]


def test_confirmed_finding_is_an_error_at_its_line():
    s = to_sarif(record(LoopVerdict.ITER_BUDGET, False, [finding(FindingStatus.CONFIRMED)]),
                 "contracts/Vault.sol")
    [r] = results(s)
    assert r["ruleId"] == "falsify/confirmed" and r["level"] == "error"
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "contracts/Vault.sol"
    assert loc["region"]["startLine"] == 17
    assert s["version"] == "2.1.0" and s["runs"][0]["properties"]["gate_pass"] is False


def test_unconfirmed_finding_is_a_warning_not_a_safety_claim():
    s = to_sarif(record(LoopVerdict.ORACLE_GAP, True, [finding(FindingStatus.UNCONFIRMED)]),
                 "Vault.sol")
    [r] = results(s)
    assert r["level"] == "warning" and "not proof of safety" in r["message"]["text"]


def test_blocked_gate_without_findings_is_never_silent():
    s = to_sarif(record(LoopVerdict.TOOL_ERROR, False, notes=["harness is not live"]),
                 "Vault.sol")
    [r] = results(s)
    assert r["ruleId"] == "falsify/blocked" and "harness is not live" in r["message"]["text"]


def test_clean_pass_has_no_results():
    assert results(to_sarif(record(LoopVerdict.CLEAN, True), "Vault.sol")) == []


def test_oracle_finding_without_line_points_at_the_file():
    f = finding(FindingStatus.CONFIRMED, location="", detector="oracle:poc")
    [r] = results(to_sarif(record(LoopVerdict.ITER_BUDGET, False, [f]), "Vault.sol"))
    assert "region" not in r["locations"][0]["physicalLocation"]


def test_markdown_summary_shows_gate_and_exploits():
    exploit = ExploitResult("Reentrancy::test_reentrancy_profits()", RE, True)
    md = render_markdown(record(LoopVerdict.ITER_BUDGET, False,
                                [finding(FindingStatus.CONFIRMED)], [exploit]))
    assert "BLOCK" in md and "`iter_budget`" in md and "**succeeded**" in md


def test_markdown_neutralizes_untrusted_text():
    md = render_markdown(record(LoopVerdict.TOOL_ERROR, False,
                                notes=["a | b `rm -rf` \x1b[31mred"]))
    assert "a \\| b 'rm -rf' red" in md and "\x1b" not in md
