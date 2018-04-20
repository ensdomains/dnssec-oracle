pragma solidity ^0.4.17;

import "./Digest.sol";
import "./BytesUtils.sol";
import "./sha1/contracts/sha1.sol";

contract SHA1Digest {
    using BytesUtils for *;

    function verify(bytes data, bytes hash) public view returns (bool) {
        BytesUtils.Slice memory hashslice;
        hashslice.fromBytes(hash);
        bytes32 expected = hashslice.bytes32At(0);
        bytes20 computed = SHA1.sha1(data);
        return expected == computed;
    }
}
