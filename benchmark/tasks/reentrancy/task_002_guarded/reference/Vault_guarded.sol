// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// An RQ2 (false-positive) fixture. This vault DOES call before updating state — the
/// classic reentrancy shape Slither's `reentrancy-eth` detector flags — but a custom
/// (non-OpenZeppelin) reentrancy guard actually blocks re-entry, so the exploit cannot
/// profit. Slither does not recognise the custom guard and raises a finding anyway.
///
/// A Slither-gated loop would keep "fixing" a contract that is already safe. Falsify
/// runs the PoC, finds it CANNOT be confirmed, and reports the finding as UNCONFIRMED
/// (a likely false positive) instead of forcing a needless change.
contract Vault {
    mapping(address => uint256) public balances;
    uint256 private _lock; // custom reentrancy guard

    modifier noReenter() {
        require(_lock == 0, "reentrant");
        _lock = 1;
        _;
        _lock = 0;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external noReenter {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}(""); // call-before-effect: Slither flags this...
        require(ok, "transfer failed");
        balances[msg.sender] = 0;                          // ...but noReenter makes re-entry revert
    }

    receive() external payable {}
}
