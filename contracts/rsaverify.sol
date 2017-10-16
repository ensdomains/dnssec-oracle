pragma solidity ^0.4.17;

import "./modexp.sol";

library RSAVerify {
    function rsaverify(bytes rawmsg, bytes N, bytes E, bytes S) internal view returns (bool) {
        if (rawmsg.length != N.length) return false;
        // This would be modexp(S, e, N) == modexp(rawmsg, 1, N), but we simplify it a bit.
        var (retS, valS) = ModexpPrecompile.modexp(S, E, N);
        // NOTE: keccak256(valS) == keccak256(rawmsg) is the cheapest shortcut for equality comparison
        return retS == true && keccak256(valS) == keccak256(rawmsg);
        //Memory.equal(valS, 0, hash, 0, hash.length);
    }
}
