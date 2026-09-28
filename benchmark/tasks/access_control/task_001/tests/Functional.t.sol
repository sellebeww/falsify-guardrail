// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// HUMAN-OWNED functional suite (plan §4). Verifies the treasury's intended behaviour:
// funds are held, and the owner can perform the privileged emergency kill.

import {Treasury} from "../src/Treasury.sol";

interface Vm {
    function deal(address who, uint256 amount) external;
}

contract Functional {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Treasury t;

    function setUp() public {
        t = new Treasury();
    }

    function test_deposit_is_held() public {
        vm.deal(address(this), 5 ether);
        t.deposit{value: 2 ether}();
        require(address(t).balance == 2 ether, "deposit not held");
    }

    function test_owner_can_kill_and_recover_funds() public {
        vm.deal(address(this), 5 ether);
        t.deposit{value: 2 ether}();
        uint256 pre = address(this).balance;
        t.kill(); // this test contract is the owner
        require(address(this).balance == pre + 2 ether, "owner could not recover funds");
    }

    receive() external payable {}
}
