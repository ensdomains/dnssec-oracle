pragma solidity ^0.5.0;

import "./Algorithm.sol";
import "../BytesUtils.sol";
import "elliptic-solidity/contracts/curves/EllipticCurve.sol";

contract P256SHA256Algorithm is Algorithm {

    using BytesUtils for *;

    EllipticCurve public curve;

    constructor(EllipticCurve _curve) public {
        curve = _curve;
    }

    /**
    * @dev Verifies a signature.
    * @param key The public key to verify with.
    * @param data The signed data to verify.
    * @param signature The signature to verify.
    * @return True iff the signature is valid.
    */
    function verify(bytes calldata key, bytes calldata data, bytes calldata signature) external view returns (bool) {
        return curve.validateSignature(sha256(data), parseSignature(signature), parseKey(key));
    }

    function parseSignature(bytes memory data) internal pure returns (uint256[2] memory) {
        return [uint256(data.readBytes32(0)), uint256(data.readBytes32(32))];
    }

    function parseKey(bytes memory data) internal pure returns (uint256[2] memory) {
        return [uint256(data.readBytes32(4)), uint256(data.readBytes32(36))];
    }
}
