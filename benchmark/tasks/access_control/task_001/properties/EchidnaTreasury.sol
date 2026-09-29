// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Treasury} from "./Treasury.sol";
contract Stranger {
    function exercise(Treasury t) external { try t.kill() {} catch {} }
    receive() external payable {}
}
contract EchidnaTreasury {
    Treasury t;
    Stranger stranger;
    bool violated;
    constructor() payable { t = new Treasury(); stranger = new Stranger(); }
    function exercise() external {
        if (address(this).balance < 1 ether) return;
        t.deposit{value: 1 ether}();
        uint beforeBalance = address(t).balance;
        stranger.exercise(t);
        if (address(t).balance < beforeBalance) violated = true;
    }
    function echidna_unauthorized_cannot_drain() public view returns (bool) { return !violated; }
}
