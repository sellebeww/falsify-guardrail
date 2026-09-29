// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// HUMAN-OWNED functional suite. Never shown to the model under test (plan §4).
// No forge-std dependency: a minimal cheatcode interface is declared inline, and
// checks use require() so a passing test simply does not revert.

import {Vault} from "../src/Vault.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
    function prank(address who) external;
}

contract Functional {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    function test_deposit_then_withdraw_roundtrip() public {
        address user = address(0xBEEF);
        vm.deal(user, 5 ether);
        vm.prank(user);
        vault.deposit{value: 2 ether}();
        require(vault.balances(user) == 2 ether, "deposit not recorded");

        uint256 pre = user.balance;
        vm.prank(user);
        vault.withdraw();
        require(user.balance == pre + 2 ether, "withdraw did not return funds");
        require(vault.balances(user) == 0, "balance not cleared");
    }

    function test_withdraw_to_recipient() public {
        vm.deal(address(this), 2 ether);
        vault.deposit{value: 1 ether}();
        address payable recipient = payable(address(0xABCD));
        uint beforeBalance = recipient.balance;
        vault.withdrawTo(recipient);
        require(recipient.balance == beforeBalance + 1 ether, "recipient unpaid");
        require(vault.balances(address(this)) == 0, "balance not cleared");
    }
    function test_cannot_withdraw_without_balance() public {
        address user = address(0xCAFE);
        vm.prank(user);
        try vault.withdraw() {
            revert("withdraw with zero balance should revert");
        } catch {}
    }
}
