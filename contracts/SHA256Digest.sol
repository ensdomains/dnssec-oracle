pragma solidity ^0.4.23;

import "./Digest.sol";
import "./BytesUtils.sol";

/**
 * @dev Implements the DNSSEC SHA256 digest.
 */
contract SHA256Digest is Digest {
    using BytesUtils for *;

    function verify(bytes data, bytes hash) external pure returns (bool) {
        return sha256(data) == hash.readBytes32(0);
    }
}
