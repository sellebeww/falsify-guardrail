// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Wallet {
    address public owner;
    constructor() { owner = msg.sender; }
    
    function deposit() external payable {}
    function release(address payable to, uint amount) external {
        require(tx.origin == owner, "owner");
        require(to != address(0), "recipient");
        (bool ok,) = to.call{value: amount}(""); require(ok, "transfer");
    }
}
