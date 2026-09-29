# Threat model & scope

## What Falsify is
A **defensive evaluation tool**. It measures whether an LLM's smart-contract repair actually
removes a vulnerability, using automated exploits as the oracle. It is used as a CLI/CI
guardrail and as a proof-of-concept benchmark.

## Where exploits run
Bundled tasks and explicitly supplied local contracts run inside a **local Foundry EVM**
(`forge test`) in a disposable directory. Bundled harnesses do not target live contracts.
External harnesses are caller-controlled executable tests: use isolated runners and do not
assume a temporary directory is a sandbox or prevents a malicious harness from using network
or filesystem capabilities provided by the underlying tools.

## Anti-circularity (why the results mean something)
- The functional tests, invariants, and PoC exploits are **task-owned** and live in the
  benchmark; the model under test never sees them (enforced structurally — see
  [`repair/feedback.py`](../falsify/repair/feedback.py) and its allowlist test).
- The exploit oracle is authored independently of the solution and encodes the *attack*, not
  the defense.
- Repair feedback is minimal by construction: vuln class + Slither text + an "exploit
  confirmed" boolean + failing functional-test names. Never the PoC source or invariants —
  leaking those would train-to-the-test.

## Trust boundaries
- A `CONFIRMED` result means the supplied exploit test passed; its assertions must faithfully
  encode exploitation. A malicious or incorrect harness can invalidate that conclusion.
- An `UNCONFIRMED` result is **not** a safety claim — it means the deterministic PoC library
  did not (yet) demonstrate exploitability. See [limitations.md](limitations.md).
