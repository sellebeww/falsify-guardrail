# Limitations (stated plainly)

These are first-class caveats, not footnotes. Falsify is a falsifier: it can confirm
exploitability, but it cannot prove safety.

- **Oracle incompleteness — the big one.** "Exploit failed" means **UNCONFIRMED, not SECURE.**
  The deterministic PoC library covers a limited set of patterns (MVP: reentrancy). A contract
  can pass the gate and still be vulnerable to something we have no PoC for.
- **Exploit weakness ≠ contract safety.** A PoC may fail because it is not clever enough, not
  because the contract is safe. This is especially true for cross-contract / economic attacks,
  where even LLM exploit generators are weak. Our deterministic library is narrower still.
- **Feedback leakage risk.** If too much oracle signal reaches the repair model, it can learn to
  fool the test rather than fix the bug. We minimize feedback deliberately; this is a tunable
  research parameter, not a solved problem.
- **Small dataset.** The benchmark currently has four tasks (three genuinely-vulnerable, one
  false-positive fixture) across two classes. Results are illustrative, not statistically
  significant. No scale claims until the benchmark grows.
- **RQ2 relies on one honest fixture.** The false positive (FP=1) comes from a vault with a
  *custom* reentrancy guard that Slither's `reentrancy-eth` detector does not recognise — a real,
  reproducible false positive, not a manufactured one. The genuine fixes in the other tasks
  cleared their detectors, so they contribute no FP. Broadening the RQ2 evidence (more detectors,
  more patterns) is future work.
- **Gas figures** are specific to the pinned solc/EVM version and to the functional suite that
  exercises each function (mean gas per function from `forge test --gas-report`).
- **Model nondeterminism** limits exact reproducibility of live model runs; the fixture and
  replay generators give fully deterministic runs for analysis and CI.
- **Benchmark contamination.** Tasks may appear in a model's training data; prefer novel,
  hand-authored tasks and treat contaminated results with suspicion.
- **Novelty.** The exploit-as-oracle idea and the "fixes don't really fix" finding exist in
  prior work (V2E, PoCo, arXiv:2501.04600). Falsify's claim is the closed-loop composition and
  the false-fix measurement for LLM loops — not the oracle itself.
