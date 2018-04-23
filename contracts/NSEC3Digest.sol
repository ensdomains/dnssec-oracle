pragma solidity ^0.4.17;

interface NSEC3Digest {
    function hash(bytes salt, bytes data, uint iterations) public pure returns (bytes);
}
