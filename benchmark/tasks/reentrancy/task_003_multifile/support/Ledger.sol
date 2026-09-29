// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
abstract contract Ledger { mapping(address => uint256) public balances; }
