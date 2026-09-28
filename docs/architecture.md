# Architecture

Falsify orchestrates five injected components (all Protocols, so the loop is unit-testable
with in-memory fakes and no toolchain):

| Component | Interface | Real impl | Fake (tests) |
|---|---|---|---|
| Generator | [`generators/base.py`](../falsify/generators/base.py) | `LLMGenerator`, `FixtureGenerator` | `ScriptedGenerator` |
| Static analyzer | [`analysis/base.py`](../falsify/analysis/base.py) | `SlitherAnalyzer` | `FakeAnalyzer` |
| Compiler | [`oracle/base.py`](../falsify/oracle/base.py) | `FoundryCompiler` | `FakeCompiler` |
| Functional tester | [`oracle/base.py`](../falsify/oracle/base.py) | `FoundryFunctionalTester` | `FakeTester` |
| Exploit oracle | [`oracle/base.py`](../falsify/oracle/base.py) | `FoundryOracle` | `FakeOracle` |

The [`Orchestrator`](../falsify/orchestrator.py) owns the loop and the §3 semantics; see
[oracle-spec.md](oracle-spec.md). Three things sit alongside the loop:

- **Oracle-discovered findings.** A PoC that succeeds with no matching Slither finding is
  recorded as a CONFIRMED, oracle-discovered finding, so Falsify catches detector *false
  negatives* (blind spots), not just validates Slither's candidates.
- **Echidna** ([`analysis/echidna_runner.py`](../falsify/analysis/echidna_runner.py)) — an
  independent, human-authored property-fuzzing oracle (`falsify echidna`), report-only and
  optional. It cross-checks the Foundry result from a different engine.
- **Per-function gas.** `FoundryFunctionalTester` reads `forge test --gas-report --json`, so
  RQ3 gas tax is reported per contract function (e.g. `withdraw() +2`), not per test.

## Hermetic Foundry projects

Each candidate contract is dropped into a fresh temp Foundry project containing only that
contract plus the relevant human-owned test files. There is **no forge-std or OpenZeppelin
dependency** — test files declare a minimal cheatcode interface inline and assert with
`require`, so a passing test simply does not revert. This keeps runs fast, hermetic, and
free of network installs.

## Data flow

`TaskSpec` → `GeneratedArtifact` → `Finding[]` (candidate) → `ExploitResult[]` (classify) →
repair loop producing `RepairAttempt[]` → `EvalRecord` → JSON
([`artifacts.py`](../falsify/artifacts.py)) + report ([`scoring/report.py`](../falsify/scoring/report.py)).

## Two modes, one engine

- **Guardrail mode** (`falsify run`) — is this AI-written contract safe to merge? Exit code is
  the gate signal.
- **Benchmark mode** (`falsify bench`, [`evaluator.py`](../falsify/evaluator.py)) — several repair
  strategies ("models") on identical tasks → a Slither-vs-oracle confusion matrix (RQ1 false fixes
  / RQ2 false positives) + Pareto(security vs gas) per category
  ([`scoring/pareto.py`](../falsify/scoring/pareto.py)).
