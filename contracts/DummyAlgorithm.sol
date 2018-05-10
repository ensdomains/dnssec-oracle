pragma solidity ^0.4.17;

import "./Algorithm.sol";

/**
* @dev Implements a dummy DNSSEC (signing) algorithm that approves all
*      signatures, for testing.
*/
contract DummyAlgorithm is Algorithm {
    function verify(bytes, bytes, bytes) external view returns (bool) { return true; }
}
