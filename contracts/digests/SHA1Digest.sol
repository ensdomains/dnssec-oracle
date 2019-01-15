pragma solidity >0.4.23;

import "./Digest.sol";
import "../BytesUtils.sol";
import "@ensdomains/solsha1/contracts/SHA1.sol";

/**
* @dev Implements the DNSSEC SHA1 digest.
*/
contract SHA1Digest {
    using BytesUtils for *;

    function verify(bytes calldata data, bytes calldata hash) external pure returns (bool) {
        bytes32 expected = hash.readBytes20(0);
        bytes20 computed = SHA1.sha1(data);
        return expected == computed;
    }
}
