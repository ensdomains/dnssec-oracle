pragma solidity ^0.4.17;

import "./Digest.sol";
import "./BytesUtils.sol";
import "./sha1/contracts/sha1.sol";

/**
 * @dev Implements the DNSSEC SHA1 digest.
 */
contract SHA1Digest {
    using BytesUtils for *;

    function verify(bytes data, bytes hash) public view returns (bool) {
        bytes32 expected = hash.readBytes20(0);
        bytes20 computed = SHA1.sha1(data);
        return expected == computed;
    }
}
