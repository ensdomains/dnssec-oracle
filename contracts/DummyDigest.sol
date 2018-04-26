pragma solidity ^0.4.17;

import "./Digest.sol";

/**
 * @dev Implements a dummy DNSSEC digest that approves all hashes, for testing.
 */
contract DummyDigest is Digest {
    function verify(bytes, bytes) public view returns (bool) { return true; }
}
