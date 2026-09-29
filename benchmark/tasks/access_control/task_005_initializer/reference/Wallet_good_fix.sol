// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Wallet {
    address public owner;
    constructor() { owner = msg.sender; }
    function initialize(address who) external { require(owner == address(0), "initialized"); owner = who; }
    function deposit() external payable {}
    function release(address payable to, uint amount) external {
        require(msg.sender == owner, "owner");
        (bool ok,) = to.call{value: amount}(""); require(ok, "transfer");
    }
}
