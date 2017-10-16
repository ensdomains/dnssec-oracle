pragma solidity ^0.4.17;

import "./algorithm.sol";

contract DummyAlgorithm is Algorithm {
    function verify(bytes key, bytes data, bytes signature) public view returns(bool) { return true; }
}
