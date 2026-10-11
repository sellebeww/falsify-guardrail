// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Exploitable control for the guarded fixture: the same vault with the custom guard
/// removed. The exploit must succeed here; otherwise its failure on the guarded vault
/// would say nothing about the guard.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
