pragma solidity ^0.4.17;

import "./Digest.sol";
import "./BytesUtils.sol";

contract SHA256Digest is Digest {
    using BytesUtils for *;

    function verify(bytes data, bytes hash) public view returns (bool) {
        return sha256(data) == hash.readBytes32(0);
    }
}
