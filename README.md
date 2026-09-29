# Falsify

**A proof-of-concept guardrail for generated Solidity, backed by executable exploits.**

Falsify combines Slither findings, independent Foundry exploit harnesses, functional tests,
line/function coverage, and gas measurements. A repair passes only when every previously
successful exploit stops succeeding, functional tests pass, and no supplied exploit newly
succeeds. Missing tests and tool failures block evaluation.

**UNCONFIRMED means no supplied exploit succeeded. It never means SECURE.** Eight curated
tasks are case studies, not a representative sample. RQ1/RQ2/RQ3 outputs are descriptive
observations, not statistical findings or evidence of production readiness.

## Run locally

```bash
make setup       # Foundry, Slither, solc 0.8.24 + 0.8.20, optional Echidna
make demo        # deterministic fixture: vulnerable -> false fix -> real fix
make bench       # three scripted strategies across all eight tasks
make echidna     # independent property campaigns for all eight tasks
make test        # unit tests, including a local HTTP mock server; no paid API
make test-int    # real toolchain integration tests
make lint
```

The demo catches a repair that hides an ETH transfer in assembly: Slither's warning
disappears while the supplied exploit still drains the vault. The next repair uses
checks-effects-interactions and passes the supplied tests. Reproduce measurements locally;
gas values depend on compiler, EVM and test suite.

## Check a contract from another repository

Provide a **trusted task harness** describing the contract interface, functional expectations,
and exploit scenarios. Falsify does not automatically invent meaningful tests for arbitrary
contracts.

```bash
falsify check --task path/to/trusted-task --source contracts/Vault.sol \
  --source-root contracts --out results/guardrail.json
```

This evaluates the supplied source without generating or repairing it. Exit 0 means the
supplied functional and exploit checks completed and passed the bounded gate; nonzero blocks.
`--source-root` includes additional `.sol` files while preserving relative imports. The entry
file must live directly inside that root. Package remappings and arbitrary Foundry projects
are not supported yet.

The repository root is a reusable **composite GitHub Action**:

```yaml
name: Solidity guardrail
on: [push, pull_request]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: sellebeww/falsify-guardrail@<commit-containing-action>
        with:
          task: security/falsify/vault
          source: contracts/Vault.sol
          source-root: contracts
          solc-version: '0.8.24'
          artifact: results/falsify.json
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: falsify-report
          path: results/falsify.json
```

Replace the placeholder with a published commit containing `action.yml`. The caller owns the
harness and artifact retention. Use isolated runners and review harness changes: this action
executes caller-supplied Solidity tests. Local CI includes positive and negative action checks.
See [the action contract](docs/guardrail.md).

## Compare actual models

The default benchmark uses **fixtures**, not LLMs. `proper_fixer`, `detector_gamer`, and
`eventually_fixer` replay reference sources and test the gate's behavior.

The live mode sends identical task specifications to each configured chat-completions endpoint:

```bash
# Edit endpoint/model IDs in a copy of examples/models.json first.
falsify bench --models examples/models.json --repetitions 3 --max-iterations 2 \
  --out results/live.json
falsify run --generator live --models examples/models.json --model local-model-a \
  --task benchmark/tasks/reentrancy/task_001 --out results/live-single.json
```

Use `api_key_env` to name an environment variable for a remote credential; never put a key in
configuration files. Requests have timeout/output-token limits and no automatic retries.
Each completed task/model/repetition is checkpointed. No external model inference has been
verified in this change: the HTTP path has been tested against a local mock, and model
credentials/endpoints are still needed for a real campaign. See [benchmark protocol](docs/benchmarking.md).

## Dataset and independent evidence

| Task | Pattern | Compiler | Sources | Echidna property |
| --- | --- | --- | --- | --- |
| reentrancy-001 | External call before balance update | 0.8.24 | Single | No unearned profit |
| reentrancy-002-guarded-fp | Custom lock, detector discrepancy | 0.8.24 | Single | No unearned profit |
| reentrancy-003-multifile | Inherited ledger and recipient withdrawal | 0.8.24 | Multiple | No unearned profit |
| access-control-001 | Unrestricted treasury destruction | 0.8.24 | Single | Unauthorized caller cannot drain |
| access-control-002-takeover | Unrestricted owner replacement | 0.8.24 | Single | Ownership remains with deployer |
| access-control-003-origin | `tx.origin` authorization through intermediary | 0.8.20 | Single | Unauthorized intermediary cannot profit |
| access-control-004-roles | Unrestricted operator grant | 0.8.24 | Single | Unauthorized caller cannot profit |
| access-control-005-initializer | Owner reinitialization | 0.8.24 | Single | Unauthorized caller cannot profit |

Every task has functional tests, a deterministic Foundry exploit, and an Echidna property.
Echidna is a separate report-only cross-check, with a fixed seed and bounded campaign;
passing fuzz tests do not prove an invariant. Models see the specification and minimal repair
feedback, never the functional tests, exploit source, or invariant source.

Coverage measures production `src/` files with `forge coverage` and records line/function
numerators and denominators, excluding test harnesses. Baseline and accepted-final coverage
appear in JSON artifacts. Coverage is descriptive, not a security score or acceptance threshold.

## Interpreting results

- **RQ1:** detector-clean states with a successful supplied exploit demonstrate blind spots.
  A detector-silenced repair is a particular event; not every blind spot is a false repair.
- **RQ2:** detector findings without a successful supplied exploit are unconfirmed candidates.
  Legacy `fp`/`tn` JSON keys do **not** mean proven false positives or proven safety.
- **RQ3:** gas deltas compare an accepted repair with its own initial contract. Fixture Pareto
  views describe this tiny dataset; live models have different generated baselines, so the
  report does not rank them using that fixture Pareto calculation.

This project explores the composition of existing static analysis, exploit validation and
repair evaluation techniques. It does not claim to invent exploit-based validation.

Read [architecture](docs/architecture.md), [oracle semantics](docs/oracle-spec.md),
[threat model](docs/threat-model.md), [limitations](docs/limitations.md), and
[validation record](docs/validation.md). Licensed under [Apache-2.0](LICENSE); Solidity files
with existing MIT headers retain those terms, reproduced in [LICENSE-MIT](LICENSE-MIT).
