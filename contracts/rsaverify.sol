pragma solidity ^0.4.17;

import "./bytesutils.sol";
import "./modexp.sol";

library RSAVerify {
    using BytesUtils for *;

    /**
     * @dev Verifies an RSA signature.
     * @param rawmsg The raw (pre-padded) message to verify.
     * @param N The RSA public modulus.
     * @param E The RSA public exponent.
     * @param S The signature to verify.
     * @return True if the signature verifies.
     */
    function rsaverify(BytesUtils.slice memory rawmsg, BytesUtils.slice memory N, BytesUtils.slice memory E, BytesUtils.slice memory S) internal view returns (bool) {
        if (rawmsg.len != N.len) return false;
        // This would be modexp(S, e, N) == modexp(rawmsg, 1, N), but we simplify it a bit.
        var retS = ModexpPrecompile.modexp(S, E, N, S);
        return retS && S.equals(rawmsg);
    }
}
