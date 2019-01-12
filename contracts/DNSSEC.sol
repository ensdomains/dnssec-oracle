pragma solidity ^0.5.0;

interface DNSSEC {

    event AlgorithmUpdated(uint8 id, address addr);
    event DigestUpdated(uint8 id, address addr);
    event NSEC3DigestUpdated(uint8 id, address addr);
    event RRSetUpdated(bytes name, bytes rrset);

    function submitRRSets(bytes calldata data, bytes calldata proof) external returns (bytes memory);
    function submitRRSet(bytes calldata input, bytes calldata sig, bytes calldata proof) external returns (bytes memory);
    function deleteRRSet(uint16 deleteType, bytes calldata deleteName, bytes calldata nsec, bytes calldata sig, bytes calldata proof) external;
    function rrdata(uint16 dnstype, bytes calldata name) external view returns (uint32, uint64, bytes20);

}
