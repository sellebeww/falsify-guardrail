// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 0 (as-generated): classic reentrancy — external call BEFORE the state
/// update, so a malicious receiver can re-enter withdraw() and drain the vault.
/// Slither flags `reentrancy-eth`; the PoC confirms it is really exploitable.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}(""); // interaction ...
        require(ok, "transfer failed");
        balances[msg.sender] = 0;                          // ... before effect (vulnerable)
    }

    receive() external payable {}
}
