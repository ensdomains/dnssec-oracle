pragma solidity ^0.4.23;

import "./Algorithm.sol";

//   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-256 curve and
//      SHA-256 use the algorithm number 13.
contract ECCAlgorithm is Algorithm {

    CurveInterface public curve;

    constructor(CurveInterface _curve) public {
        curve = _curve;
    }

    function verify(bytes key, bytes data, bytes signature) external view returns (bool) {
        curve.validateSignature(data, signature, key); // @todo this probably isn't correct
    }

}
