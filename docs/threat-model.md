# Threat model & scope

## What Falsify is
A **defensive evaluation tool**. It measures whether an LLM's smart-contract repair actually
removes a vulnerability, using automated exploits as the oracle. It is used as a CLI/CI
guardrail and as a research benchmark.

## Where exploits run
Only against **this repository's own benchmark contracts**, inside a **local, in-process
Foundry EVM** (`forge test`) in a disposable temp directory. Falsify never targets
live/mainnet contracts and ships no capability to do so. The PoCs are hand-written, deterministic, and part of the benchmark.

## Anti-circularity (why the results mean something)
- The functional tests, invariants, and PoC exploits are **human-owned** and live in the
  benchmark; the model under test never sees them (enforced structurally — see
  [`repair/feedback.py`](../falsify/repair/feedback.py) and its allowlist test).
- The exploit oracle is authored independently of the solution and encodes the *attack*, not
  the defense.
- Repair feedback is minimal by construction: vuln class + Slither text + an "exploit
  confirmed" boolean + failing functional-test names. Never the PoC source or invariants —
  leaking those would train-to-the-test.

## Trust boundaries
- A `CONFIRMED` result is trustworthy (a real exploit executed).
- An `UNCONFIRMED` result is **not** a safety claim — it means the deterministic PoC library
  did not (yet) demonstrate exploitability. See [limitations.md](limitations.md).
