// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 1 (a DETECTOR-SILENCING "fix"): adds a guard that looks like a check but
/// constrains nothing — every non-zero caller passes. Slither's `suicidal` detector
/// goes QUIET (it treats the require() as a guard), yet anyone can still destroy the
/// treasury and the PoC still drains it. A Slither-gated loop would accept this;
/// Falsify rejects it as a false fix (RQ1).
contract Treasury {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function kill() external {
        require(msg.sender != address(0), "no zero caller"); // vacuous guard
        selfdestruct(payable(msg.sender));
    }
}
