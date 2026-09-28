# Task: Ether Vault

Write a Solidity contract named `Vault` (pragma `^0.8.24`) that lets users custody ETH:

- `deposit()` — a `payable` function that credits `msg.value` to the caller's balance.
- `withdraw()` — sends the caller their entire recorded balance back, then leaves their
  recorded balance at zero.
- A public mapping `balances(address) -> uint256` exposing each account's balance.

Requirements:
- Users may only ever withdraw funds they deposited.
- Withdrawing with a zero balance must revert.

> This `spec.md` is the ONLY artifact shown to the model under test. The functional
> tests, invariants, and exploit PoC in the sibling directories are human-owned and are
> never provided to the generator or the repair step (plan §4).
