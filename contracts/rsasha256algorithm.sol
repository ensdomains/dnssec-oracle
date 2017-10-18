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

        bytes memory sigdata = new bytes(modulus.len);
        BytesUtils.slice memory sigdataslice;
        sigdataslice.fromBytes(sigdata);
        // Write 0x0001
        sigdataslice.writeBytes32(0, 0x0001 << 240);
        // Repeat 0xFF as many times as needed (2 byte 0x0001 + 20 byte prefix + 32 byte hash = 54)
        var padsize = modulus.len - 54;
        sigdataslice.fill(2, padsize, 0xff);
        // Write the prefix
        sigdataslice.writeBytes32(padsize + 2, 0x00003031300d060960864801650304020105000420 << 96);
        // Write the hash
        sigdataslice.writeBytes32(padsize + 22, sha256(data));

        // Verify the signature
        return RSAVerify.rsaverify(sigdataslice, modulus, exponent, sigslice);
    }
}
