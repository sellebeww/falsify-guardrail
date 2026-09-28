# Task: Bank with owner-controlled sweep

Write a Solidity contract named `Bank` (pragma `^0.8.24`) that:

- has an `owner`, set to the deployer in the constructor;
- accepts ETH via a `payable` `deposit()` and tracks per-account `balances`;
- lets the owner move funds out via `sweep(uint256 amount, address to)`;
- lets the owner hand ownership to a new address via `setOwner(address)`.

Requirements:
- Only the owner may `sweep` funds **and** only the owner may change the owner via
  `setOwner`. An attacker must not be able to seize ownership or move funds.

> This `spec.md` is the ONLY artifact shown to the model under test (plan §4).
