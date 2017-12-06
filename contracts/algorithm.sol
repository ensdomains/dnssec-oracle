pragma solidity ^0.4.17;

interface Algorithm {
    function verify(bytes key, bytes data, bytes signature) public view returns (bool);
}
