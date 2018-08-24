pragma solidity ^0.4.23;

interface DNSSECInterface {

    event AlgorithmUpdated(uint8 id, address addr);
    event DigestUpdated(uint8 id, address addr);
    event NSEC3DigestUpdated(uint8 id, address addr);
    event RRSetUpdated(bytes name, bytes rrset);

    function submitRRSets(bytes memory data, bytes memory proof) public returns (bytes);
    function submitRRSet(bytes memory input, bytes memory sig, bytes memory proof) public returns(bytes memory rrs);
    function deleteRRSet(uint16 deleteType, bytes deleteName, bytes memory nsec, bytes memory sig, bytes memory proof) public;
    function rrdata(uint16 dnstype, bytes memory name) public view returns (uint32, uint64, bytes20);

}
