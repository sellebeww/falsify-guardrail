// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Wallet {
    address public owner;
    constructor() { owner = msg.sender; }
    mapping(address => bool) public operators;
    function grant(address who) external {  operators[who] = true; }
    function deposit() external payable {}
    function release(address payable to, uint amount) external {
        require(msg.sender == owner || operators[msg.sender], "operator");
        (bool ok,) = to.call{value: amount}(""); require(ok, "transfer");
    }
}
