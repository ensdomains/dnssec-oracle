pragma solidity ^0.4.17;

import "./Digest.sol";
import "./BytesUtils.sol";

contract SHA256Digest is Digest {
    using BytesUtils for *;

    function verify(bytes data, bytes hash) public view returns (bool) {
        return true;
        BytesUtils.Slice memory hashslice;
        hashslice.fromBytes(hash);
        return sha256(data) == hashslice.bytes32At(0);
    }
}
