// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// HUMAN-AUTHORED Echidna invariant (plan §4) — never written by the model under test.
// Echidna deploys this contract (which deploys the Bank and is therefore its owner) and
// fuzzes transactions from many senders against all contracts, trying to make an
// echidna_* property return false. The invariant: ownership must never leave the deployer.
//
//   vulnerable Bank -> Echidna calls setOwner() from an attacker -> property FALSIFIED
//   fixed Bank      -> setOwner is owner-gated -> property HOLDS

import {Bank} from "./Bank.sol";

contract EchidnaBank {
    Bank public bank;
    address private immutable deployer;

    constructor() payable {
        bank = new Bank(); // this contract is the initial owner
        deployer = address(this);
    }

    function echidna_owner_is_deployer() public view returns (bool) {
        return bank.owner() == deployer;
    }
}
