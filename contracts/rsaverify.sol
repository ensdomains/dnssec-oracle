pragma solidity ^0.4.17;

import "./bytesutils.sol";
import "./modexp.sol";

library RSAVerify {
    using BytesUtils for *;

    /**
     * @dev Recovers the input data from an RSA signature, returning the result in S.
     * @param N The RSA public modulus.
     * @param E The RSA public exponent.
     * @param S The signature to recover.
     * @return True if the recovery succeeded.
     */
    function rsarecover(BytesUtils.slice memory N, BytesUtils.slice memory E, BytesUtils.slice memory S) internal view returns (bool) {
        return ModexpPrecompile.modexp(S, E, N, S);
    }
}
