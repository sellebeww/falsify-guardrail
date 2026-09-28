// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// HUMAN-OWNED functional suite (plan §4): the owner can custody and sweep funds, and can
// hand ownership to a new owner. Passes on every stage (the fix preserves behaviour).

import {Bank} from "../src/Bank.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
    function prank(address who) external;
}

contract Functional {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Bank bank;

    function setUp() public {
        bank = new Bank();
    }

    function test_owner_can_sweep_deposits() public {
        vm.deal(address(this), 10 ether);
        bank.deposit{value: 3 ether}();
        address recipient = address(0xD00D);
        bank.sweep(3 ether, recipient); // this contract is the owner
        require(recipient.balance == 3 ether, "sweep did not deliver funds");
    }

    function test_owner_can_transfer_ownership() public {
        address next = address(0xBEEF);
        bank.setOwner(next); // owner may hand over ownership
        require(bank.owner() == next, "ownership not transferred");
    }
}
