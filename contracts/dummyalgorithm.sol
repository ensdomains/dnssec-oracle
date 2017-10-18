pragma solidity ^0.4.17;

import "./algorithm.sol";

contract DummyAlgorithm is Algorithm {
    function verify(bytes, bytes, bytes) public view returns(bool) { return true; }
}
