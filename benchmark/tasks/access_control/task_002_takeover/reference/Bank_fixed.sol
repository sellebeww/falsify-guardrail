// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 2 (a real fix): `setOwner` is restricted to the current owner, so an attacker
/// can neither seize ownership nor sweep the funds. The takeover PoC no longer profits.
contract Bank {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function setOwner(address o) external onlyOwner {
        owner = o;
    }

    function sweep(uint256 amount, address to) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
