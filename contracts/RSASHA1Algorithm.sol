pragma solidity ^0.4.17;

import "./Algorithm.sol";
import "./BytesUtils.sol";
import "./RSAVerify.sol";
import "./sha1/contracts/sha1.sol";

contract RSASHA1Algorithm is Algorithm {
    using BytesUtils for *;

    function verify(bytes key, bytes data, bytes sig) public view returns (bool) {
        bytes memory exponent;
        bytes memory modulus;

        uint16 exponentLen = uint16(key.readUint8(4));
        if (exponentLen != 0) {
            exponent = key.substring(5, exponentLen);
            modulus = key.substring(exponentLen + 5, key.length - exponentLen - 5);
        } else {
            exponentLen = key.readUint16(5);
            exponent = key.substring(7, exponentLen);
            modulus = key.substring(exponentLen + 7, key.length - exponentLen - 7);
        }

        // Recover the message from the signature
        var (ok, result) = RSAVerify.rsarecover(modulus, exponent, sig);

        // Verify it ends with the hash of our data
        bytes20 hash = SHA1.sha1(data);
        bytes20 sigresult = result.readBytes20(result.length - 20);
        return ok && hash == sigresult;
    }
}
