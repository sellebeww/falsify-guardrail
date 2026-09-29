// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Wallet} from "./Wallet.sol";
contract OriginWallet is Wallet { constructor(address who) { owner = who; } }
contract Stranger {
    function exercise(Wallet b) external {  b.release(payable(address(this)), 1 ether); }
    receive() external payable {}
}

contract EchidnaWallet {
    Wallet b;
    Stranger stranger;
    bool violated;
    constructor() payable {  stranger = new Stranger(); }
    function exercise() external {
        if (address(this).balance < 1 ether) return;
        Wallet b = new OriginWallet(tx.origin);
        b.deposit{value: 1 ether}();
        uint beforeBalance = address(stranger).balance;
        try stranger.exercise(b) {} catch {}
        if (address(stranger).balance > beforeBalance) violated = true;
    }
    function echidna_unauthorized_cannot_profit() public view returns (bool) { return !violated; }
}
