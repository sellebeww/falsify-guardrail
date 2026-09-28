// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 2 (a real fix): `kill()` is restricted to the owner with a genuine check.
/// Slither's `suicidal` detector clears AND the PoC can no longer destroy the treasury
/// from an unauthorized account — a true fix, accepted by Falsify.
contract Treasury {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {}

    function kill() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}
