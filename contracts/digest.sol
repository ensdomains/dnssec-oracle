pragma solidity ^0.4.17;

contract Digest {
  function verify(bytes data, bytes hash) public view returns (bool);
}
