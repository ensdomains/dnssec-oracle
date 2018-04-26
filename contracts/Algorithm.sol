pragma solidity ^0.4.17;

/**
 * @dev An interface for contracts implementing a DNSSEC (signing) algorithm.
 */
interface Algorithm {
    /**
     * @dev Verifies a signature.
     * @param key The public key to verify with.
     * @param data The signed data to verify.
     * @param signature The signature to verify.
     * @return True iff the signature is valid.
     */
    function verify(bytes key, bytes data, bytes signature) external view returns (bool);
}
