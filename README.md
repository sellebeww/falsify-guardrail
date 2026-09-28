# Falsify

**An exploit-confirmed guardrail for LLM-generated smart contracts.**

Most systems that use an LLM to write or repair Solidity run a loop:
`generate → static analysis (Slither) → feedback → regenerate`. Two things make their
"secure" claims untrustworthy:

1. **Unvalidated findings.** A Slither finding is never proven exploitable, so false
   positives trigger pointless rewrites.
2. **Detector-silencing (Goodhart).** A "fix" can make Slither go quiet while the bug
   survives. The metric is optimized, not the security.

Falsify treats every finding as a **conjecture** and an automated exploit as an attempted
**falsification**. A finding counts only when a PoC exploit *succeeds*; a repair is accepted
only when the previously-succeeding exploit now *fails*, functional tests still pass, no new
exploit appears, and gas is recorded.

> **"Exploit failed" means UNCONFIRMED, never SECURE.**

## The result, on real tooling

`make demo` runs one reentrancy task through live Slither + Foundry. The fixture model tries a
detector-silencing "fix" first, then a real one:

```
Verdict: SUCCESS     Gate: PASS
Findings: 1 confirmed, 0 unconfirmed, 0 out-of-scope   (max severity: high)
False fixes caught (detector-silenced, RQ1): 1
Gas tax total of accepted repairs (RQ3): +5
Repair iterations:
  #1  rejected  not_neutralized         fates: reentrancy-eth=detector_silenced
  #2  accepted  -                       fates: reentrancy-eth=neutralized
```

Iteration #1 moved the ETH transfer into inline assembly — Slither's `reentrancy-eth` warning
**disappeared**, but the PoC still drained the vault. A Slither-gated loop would have accepted
it. Falsify rejected it as a **false fix** and only accepted the checks-effects-interactions fix.

## Benchmark mode

`make bench` runs several repair *strategies* ("models") across every task and compares, over
each distinct contract state, what a **Slither-only gate** would conclude vs. ground truth
(the **exploit oracle**). On the current set (reentrancy + access-control):

```
Ground truth (exploit oracle) vs a Slither-only gate, over 10 distinct contract states:
                    exploitable      safe
  Slither flags        TP=2          FP=1     <- FP = RQ2 false positives
  Slither clean        FN=4          TN=3     <- FN = RQ1 false fixes / blind spots

  A Slither-only gate would APPROVE 4 still-exploitable contract(s) (RQ1),
  and BLOCK 1 provably-safe contract(s) (RQ2). Falsify's oracle gets both right.

Per strategy (model):
  detector_gamer     runs=4  real-fixes=0  blocked=3  false-fixes-caught=6
  eventually_fixer   runs=4  real-fixes=3  blocked=0  false-fixes-caught=3
  proper_fixer       runs=4  real-fixes=3  blocked=0  false-fixes-caught=0
```

Falsify is right in **both** directions where a detector-only gate is wrong:

- **FN=4 (RQ1 — approved but exploitable).** Four contracts Slither calls clean but the oracle
  drains: two detector-*silencing* fixes (reentrancy hidden in inline assembly; an access-control
  `kill()` wrapped in a vacuous `require` that quiets `suicidal`), plus two Slither *blind spots*
  (an ownership-takeover bug Slither's mapped detectors never see at all). A Slither-gate approves
  all four; Falsify's exploit oracle catches every one — including bugs Slither never reported.
- **FP=1 (RQ2 — blocked but safe).** A vault with a *custom* reentrancy guard Slither doesn't
  recognise: flagged `reentrancy-eth`, but the PoC can't drain it. A Slither-gate would churn
  "fixing" a safe contract; Falsify reports the finding UNCONFIRMED and moves on.

## Architecture

```
              benchmark/ (human-owned: spec, tests, invariants, PoCs)
                              │  (the model never reads tests/PoCs — §4)
                              ▼
 TaskSpec ─▶ Generator ─▶ contract.sol ─▶ Slither ─▶ candidate findings
           (LLM / fixture)      │          (fast, noisy)      │
                                │                             ▼
                                │                    Exploit Oracle ◀─ deterministic
                                │                  (Foundry PoCs)        PoC library
                                │                             │
                                │        confirmed / unconfirmed / out-of-scope
                                ▼                             ▼
                           Repair Loop ◀── minimal feedback (class + Slither text +
                          (LLM / fixture)   "exploit confirmed" + failing tests;
                                │            NOT the PoC source)
                                ▼
        re-run oracle battery (regression) + functional tests + gas → accept / reject / stop
                                │
                                ▼
                      Scorer/Reporter → JSON artifact
```

## Quickstart

```bash
make setup    # venv + Foundry + solc 0.8.24 + Slither + Echidna
make demo     # end-to-end reentrancy task, offline & deterministic
make bench    # all strategies × all tasks -> RQ confusion matrix + Pareto
make echidna  # independent Echidna invariant cross-check (access-control takeover)
make test     # fast unit tests (no toolchain needed)
make test-int # integration tests on the real toolchain
```

### Independent second oracle (Echidna)

The Foundry PoC is the loop's gate, but Falsify also ships human-authored **Echidna**
invariants as an independent property-fuzzing oracle (`make echidna`). On the ownership-takeover
task, `owner == deployer` is **falsified** on the vulnerable contract and **holds** on the fix —
confirming the Foundry result from a completely different engine (plan §4 anti-circularity).

The demo is offline and deterministic: it uses a recorded **fixture generator** (no API key).
To drive the **LLM adapter** through the real loop, use `make run GEN=replay`: the adapter
replays recorded model responses, verifying prompt construction, Solidity extraction, and loop
wiring offline. To evaluate a live model, construct `LLMGenerator(transport)` with any callable
`transport(system, prompt) -> text` for the model under test — Falsify ships no vendor-specific
client.

## Contribution (positioned honestly)

Exploit-generation-as-oracle already exists ([V2E](https://arxiv.org/abs/2604.13611),
[PoCo](https://doi.org/10.1145/3816704), ReX, [EvoPoC](https://arxiv.org/abs/2605.02868)), and
"do automated fixes truly mitigate exploits?" was already studied for 20 traditional APR tools
by [arXiv:2501.04600](https://arxiv.org/abs/2501.04600). Falsify does **not** claim to invent
these. Our contribution is their composition and measurement:

- **Exploit-confirmation as the acceptance *gate inside* an LLM generate-repair loop** — not
  post-hoc validation, not detector-gated repair.
- **Explicit detector-silencing / false-fix measurement for LLM loops** (RQ1).
- **Pareto(confirmed-security vs gas) per contract category** on identical tasks (RQ3).

See [docs/architecture.md](docs/architecture.md), [docs/oracle-spec.md](docs/oracle-spec.md),
[docs/threat-model.md](docs/threat-model.md), and [docs/limitations.md](docs/limitations.md).

## Research questions

- **RQ1 — false fix rate:** what fraction of Slither-satisfying "fixes" are still exploitable?
- **RQ2 — exploitability:** what fraction of Slither findings on LLM code are really exploitable?
- **RQ3 — gas tax:** what does each confirmed fix cost in gas?

## Status

Two vulnerability classes (reentrancy + access-control) across four benchmark tasks, the full
loop on real Foundry + Slither, oracle-discovered findings, an independent Echidna oracle,
per-function gas reporting, benchmark mode with three repair strategies, a deterministic offline
demo, JSON artifacts, CI, and a reproducible Docker image. Roadmap: more tasks per class, more
patterns for RQ2, and a hybrid exploit-proposer that must still replay through the deterministic
gate. **Scope/ethics:** exploits run only against this repo's own benchmark contracts inside a
local, in-process Foundry EVM — never against live contracts. This is a defensive evaluation
tool.
