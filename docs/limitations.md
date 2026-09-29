# Limitations

Falsify can demonstrate exploitability; it cannot prove safety.

- **Eight curated tasks, two vulnerability classes.** Seven vulnerable examples and one
  guarded discrepancy fixture are proof-of-concept cases. Related patterns and multiple
  states of one task are correlated. They are not eight independent samples from a population
  of real contracts, and expansion from four to eight does not establish statistical validity.
- **Fixture versus live models.** Default strategies are deterministic scripts. A configurable
  live HTTP adapter and repeated multi-model runner exist, but local mock HTTP tests are not
  evidence of an actual provider/model run. A real campaign needs chosen endpoints, credentials
  where applicable, and a budget. No model ranking is claimed from fixtures.
- **Incomplete oracles.** Supplied PoCs can miss attacks. Detector-positive/unconfirmed is
  not necessarily a false positive; detector-negative/unconfirmed is not necessarily safe.
  Exploit harness build/execution failures, missing suites and tool errors block the gate.
- **Echidna is bounded.** Every task has a property and vulnerable/fixed controls (except the
  guarded task, which has only a non-violating reference). Seed 1337, one worker and 5,000 tests
  provide a reproducible cross-check, not an exhaustive proof. Some properties use scenario
  actors and overlapping behavioral assumptions with Foundry. They are independent tooling,
  not independent evidence that covers every vulnerability.
- **Compiler and project scope.** Tested pins are 0.8.20 and 0.8.24. Multi-file support handles
  one generated entry contract plus task-owned fixed support files or caller-provided relative
  sources. It does not generate arbitrary multi-file projects, resolve package remappings,
  handle proxy deployments or support every Solidity/EVM version.
- **Coverage is descriptive.** LCOV covers production lines and functions reached by functional
  tests, excluding PoC and property campaigns. Unavailable coverage is explicit, never zero
  or 100%. Coverage instrumentation differs from optimized gas measurement. No coverage
  threshold is an acceptance gate; high coverage does not imply useful assertions or security.
- **Gas is suite-specific.** Per-function mean gas and sums are not transaction-weighted costs.
  Compiler, EVM, warm/cold state and exercised functions affect results. Live models generate
  different initial implementations; gas deltas are only within-run comparisons.
- **Trusted harnesses.** Test quality, immutable expectations, source dependency boundaries
  and CI runner isolation matter. Never treat a model-authored test or a maliciously changed
  task as trusted evidence. A disposable project directory is not a security sandbox.
- **Feedback and contamination.** Even minimal feedback can help overfit a harness. Public
  tasks may be in training data. Generation nondeterminism and provider model updates limit
  reproducibility. Repeated trials do not make a tiny curated dataset representative.
- **Analysis scope.** Only mapped Slither detectors enter the two supported vulnerability
  classes. Other findings are not an exhaustive audit. Severity follows detector impact or
  the default high severity assigned to an oracle-discovered exploit.
