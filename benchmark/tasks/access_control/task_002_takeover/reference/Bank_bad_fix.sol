// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 1 (a bogus "fix"): adds a zero-address check to `setOwner` that does nothing to
/// stop an attacker from seizing ownership. The takeover still works; Falsify rejects it.
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

    function setOwner(address o) external {
        require(o != address(0), "zero owner"); // vacuous: any non-zero caller still takes over
        owner = o;
    }

    function sweep(uint256 amount, address to) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
