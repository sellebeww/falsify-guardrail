// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Wallet} from "./Wallet.sol";
contract Stranger {
    function exercise(Wallet b) external { b.grant(address(this)); b.release(payable(address(this)), 1 ether); }
    receive() external payable {}
}

contract EchidnaWallet {
    Wallet b;
    Stranger stranger;
    bool violated;
    constructor() payable { b = new Wallet(); stranger = new Stranger(); }
    function exercise() external {
        if (address(this).balance < 1 ether) return;
        
        b.deposit{value: 1 ether}();
        uint beforeBalance = address(stranger).balance;
        try stranger.exercise(b) {} catch {}
        if (address(stranger).balance > beforeBalance) violated = true;
    }
    function echidna_unauthorized_cannot_profit() public view returns (bool) { return !violated; }
}
