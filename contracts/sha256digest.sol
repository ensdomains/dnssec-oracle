pragma solidity ^0.4.17;

import "./digest.sol";
import "./bytesutils.sol";

contract SHA256Digest is Digest {
    using BytesUtils for *;

    function verify(bytes data, bytes hash) public view returns (bool) {
        BytesUtils.slice memory hashslice;
        hashslice.fromBytes(hash);
        return sha256(data) == hashslice.bytes32At(0);
    }
}
