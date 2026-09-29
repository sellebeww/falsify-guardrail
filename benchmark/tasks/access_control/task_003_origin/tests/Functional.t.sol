// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Wallet} from "../src/Wallet.sol";
interface Vm { function deal(address,uint) external; function prank(address,address) external; }
contract Functional {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Wallet b;
    function setUp() public { b = new Wallet(); vm.deal(address(b), 3 ether); }
    function test_owner_release() public {
        address payable recipient = payable(address(0xBEEF));
        uint beforeBalance = recipient.balance;
        vm.prank(address(this), address(this)); b.release(recipient, 1 ether);
        require(recipient.balance == beforeBalance + 1 ether, "unpaid");
    }
    function test_deposit() public {
        vm.deal(address(this), 1 ether); b.deposit{value: 1 ether}();
        require(address(b).balance == 4 ether, "deposit");
    }
}
