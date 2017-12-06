pragma solidity ^0.4.17;

import "./digest.sol";

contract DummyDigest is Digest {
    function verify(bytes, bytes) public view returns (bool) { return true; }
}
