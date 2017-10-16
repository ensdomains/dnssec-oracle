pragma solidity ^0.4.17;

import "./digest.sol";

contract DummyDigest is Digest {
  function verify(bytes data, bytes hash) public view returns (bool) { return true; }
}
