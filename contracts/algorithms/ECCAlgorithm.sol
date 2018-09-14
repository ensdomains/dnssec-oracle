pragma solidity ^0.4.23;

import "./Algorithm.sol";
import "../BytesUtils.sol";
import "@ensdomains/curvearithmetics/contracts/CurveInterface.sol";

//   o  DNSKEY and RRSIG RRs signifying ECDSA with the P-256 curve and
//      SHA-256 use the algorithm number 13.
contract ECCAlgorithm is Algorithm {

    using BytesUtils for *;

    CurveInterface public curve;

    constructor(CurveInterface _curve) public {
        curve = _curve;
    }

    function verify(bytes key, bytes data, bytes signature) external view returns (bool) {
        return curve.validateSignature(sha256(data), parseSignature(signature), parseKey(key));
    }

    function parseSignature(bytes data) internal view returns (uint256[2]) {
        return [data.readUint256(0), data.readUint256(32)];
    }

    function parseKey(bytes data) internal view returns (uint256[2]) {
        return [data.readUint256(4), data.readUint256(36)];
    }
}
