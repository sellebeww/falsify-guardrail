// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 0 (as-generated): `sweep()` is correctly owner-gated, but `setOwner()` is NOT —
/// so anyone can seize ownership and then sweep the funds. Slither's mapped detectors
/// do not flag this (the send is owner-gated; an unprotected setter is not a mapped check),
/// so a Slither-gated loop sees a "clean" contract. Falsify's oracle confirms the takeover.
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
        owner = o; // UNPROTECTED -> ownership takeover
    }

    function sweep(uint256 amount, address to) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
