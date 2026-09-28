// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stage 1 (a DETECTOR-SILENCING "fix"): the ETH send is moved into inline
/// assembly, which makes Slither's `reentrancy-eth` detector go quiet — yet the
/// state update still happens AFTER the external call, so the contract is exactly
/// as reentrant as before. A Slither-gated loop would accept this as "fixed".
/// Falsify rejects it: the PoC still drains the vault (false fix -> RQ1).
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        address to = msg.sender;
        assembly {
            let ok := call(gas(), to, amount, 0, 0, 0, 0)
            if iszero(ok) { revert(0, 0) }
        }
        balances[msg.sender] = 0; // STILL after the interaction -> still reentrant
    }

    receive() external payable {}
}
