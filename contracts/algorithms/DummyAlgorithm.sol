pragma solidity >0.4.23;

import "./Algorithm.sol";

/**
* @dev Implements a dummy DNSSEC (signing) algorithm that approves all
*      signatures, for testing.
*/
contract DummyAlgorithm is Algorithm {
    function verify(bytes calldata, bytes calldata, bytes calldata) external view returns (bool) { return true; }
}
