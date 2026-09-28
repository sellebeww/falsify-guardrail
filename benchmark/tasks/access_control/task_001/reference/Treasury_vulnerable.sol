// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 0 (as-generated): the emergency `kill()` has NO access control, so anyone
/// can self-destruct the treasury and take its balance. Slither flags `suicidal`;
/// the PoC confirms an unauthorized caller drains the funds.
contract Treasury {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function kill() external {
        selfdestruct(payable(msg.sender)); // anyone can call -> unauthorized drain
    }
}
