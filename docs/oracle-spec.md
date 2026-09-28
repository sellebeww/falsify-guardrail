# Oracle & loop specification

This is the formal contract the code in [`falsify/orchestrator.py`](../falsify/orchestrator.py)
implements. It is the most important part of the system.

## Finding status

For a candidate finding `f` (raised by Slither) on contract `C`:

- `CONFIRMED(f)` iff there exists a PoC `P` for `f.swc_class` with `succeeds(P, C)`.
- `OUT_OF_SCOPE(f)` iff no PoC template exists for `f.swc_class`.
- `UNCONFIRMED(f)` otherwise (a template exists, but no PoC succeeded). **UNCONFIRMED ≠ SAFE.**

## Exploit success predicate

`succeeds(P, C)` iff, in a fresh, local, in-process Foundry EVM (`forge test`) under pinned solc:

- `P`'s attacker-controlled transaction sequence executes, **and**
- `P`'s terminal assertion holds: the attacker ends with **more ETH than it started with**
  (profit == an unauthorized account extracted other users' funds).

Operationally: **a PoC forge test that PASSES is a confirmed exploit.** A failing/reverting
PoC test is `UNCONFIRMED`, not proof of safety.

Every bundled PoC asserts profit, so a confirmed finding means value was actually extracted.
Violations with no direct profit (e.g. an unauthorized ownership change) are covered by the
independent, report-only Echidna invariants rather than by the gate.

## Repair-acceptance predicate

A repair `C → C'` is `ACCEPTED` iff **all** hold (else `REJECTED` with a reason):

- **(a) Neutralized** — every PoC with `succeeds(P, C)` now has `¬succeeds(P, C')`.
- **(b) Functional** — the human-owned functional suite passes on `C'`.
- **(c) Compiles** — `C'` compiles under pinned solc.
- **(d) No regression** — the full PoC battery finds no *new* success on `C'` absent on `C`.

Gas is profiled on `C'` regardless (Δ vs `C`).

## Anti-Goodhart instrumentation

For each confirmed finding after a repair attempt (`FindingFate`):

- `NEUTRALIZED` — the PoC no longer succeeds → a real fix.
- `DETECTOR_SILENCED` — **Slither no longer reports the class, but the PoC still succeeds.**
  This is a **false fix** (RQ1). It is counted and *never* accepted.
- `STILL_EXPLOITABLE` — the PoC still succeeds and Slither still flags it.

RQ2 (likely false positives) is not a fate: it is measured as candidate findings that stay
`UNCONFIRMED` — the FP cell of the benchmark's Slither-vs-oracle confusion matrix.

## Loop termination (`LoopVerdict`)

| Verdict | Meaning | Gate |
|---|---|---|
| `SUCCESS` | confirmed findings existed and were all neutralized | PASS |
| `CLEAN` | no candidate findings at all (still: UNCONFIRMED ≠ SECURE) | PASS |
| `ORACLE_GAP` | candidates exist but none confirmable → honestly unconfirmed | PASS (loud caveat) |
| `ITER_BUDGET` | confirmed findings remain; iteration budget `N` exhausted | BLOCK |
| `STAGNATION` | repair cycled, or the confirmed set stopped shrinking for `k` iters | BLOCK |
| `COMPILE_FAIL` | repairs failed to compile `m` times in a row (or initial did) | BLOCK |

No terminal state silently upgrades an unconfirmed result to "secure".
