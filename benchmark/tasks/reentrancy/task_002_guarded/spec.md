# Task: Guarded Ether Vault (false-positive fixture)

Same interface as the reentrancy vault: `Vault` (pragma `^0.8.24`) with `deposit()`,
`withdraw()`, and a public `balances` mapping.

This fixture exists to exercise **RQ2 (false positives)**: the contract is written in the
call-before-effect shape that Slither's `reentrancy-eth` detector flags, but it is protected
by a custom reentrancy guard, so no exploit succeeds. The correct behaviour for an
exploit-confirmed guardrail is to report the Slither finding as UNCONFIRMED — not to force a
change to an already-safe contract.

> This `spec.md` is the ONLY artifact shown to the model under test (plan §4).
