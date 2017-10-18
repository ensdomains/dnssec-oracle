pragma solidity ^0.4.17;

import "./algorithm.sol";
import "./bytesutils.sol";
import "./rsaverify.sol";

contract RSASHA256Algorithm is Algorithm {
    using BytesUtils for *;

    function verify(bytes key, bytes data, bytes sig) public view returns (bool) {
        BytesUtils.slice memory dnskey;
        dnskey.fromBytes(key);

        BytesUtils.slice memory exponent;
        exponent.copyFrom(dnskey);
        BytesUtils.slice memory modulus;
        modulus.copyFrom(dnskey);

        BytesUtils.slice memory sigslice;
        sigslice.fromBytes(sig);

        var exponentLen = uint16(dnskey.uint8At(4));
        if(exponentLen != 0) {
            exponent.s(5, exponentLen + 5);
            modulus.s(exponentLen + 5, dnskey.len);
        } else {
            exponent.s(7, exponentLen + 7);
            modulus.s(exponentLen + 7, dnskey.len);
        }

        // Recover the message from the signature
        if(!RSAVerify.rsarecover(modulus, exponent, sigslice)) {
            return false;
        }
        // Verify it ends with the hash of our data
        return sha256(data) == sigslice.bytes32At(modulus.len - 32);
    }
}
