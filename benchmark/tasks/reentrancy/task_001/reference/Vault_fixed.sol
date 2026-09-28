// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 2 (a REAL fix): checks-effects-interactions — zero the balance BEFORE
/// the external call. Re-entry finds a zero balance and reverts, so the PoC no
/// longer profits, while honest deposit/withdraw still works.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;                          // effect ...
        (bool ok, ) = msg.sender.call{value: amount}(""); // ... before interaction (safe)
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
