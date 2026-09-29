// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Vault} from "./Vault.sol";
contract Probe {
    Vault v;
    uint depth;
    constructor(Vault target) { v = target; }
    function exercise() external payable {
        v.deposit{value: msg.value}();
        try v.withdraw() {} catch {}
    }
    receive() external payable {
        if (depth < 3) {
            depth++;
            try v.withdraw() {} catch {}
            depth--;
        }
    }
}
contract EchidnaVault {
    Vault v;
    Probe probe;
    bool violated;
    constructor() payable { v = new Vault(); probe = new Probe(v); }
    function exercise(uint8 amount) external {
        uint stake = (uint(amount) + 1) * 1e12;
        if (address(this).balance < stake * 4) return;
        v.deposit{value: stake * 3}();
        uint beforeBalance = address(probe).balance;
        probe.exercise{value: stake}();
        if (address(probe).balance > beforeBalance + stake) violated = true;
    }
    function echidna_no_unearned_profit() public view returns (bool) { return !violated; }
    receive() external payable {}
}
