// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Ledger} from "./Ledger.sol";
contract Vault is Ledger {
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external { payout(payable(msg.sender)); }
    function withdrawTo(address payable recipient) external { payout(recipient); }
    function payout(address payable recipient) internal {
        uint amount = balances[msg.sender];
        require(amount > 0, "empty");
        
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "transfer");
        balances[msg.sender] = 0;
    }
}
