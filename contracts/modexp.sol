pragma solidity ^0.4.17;

import "./bytesutils.sol";

library ModexpPrecompile {
    using BytesUtils for *;

    /**
     * @dev Computes (base ^ exponent) % modulus over big numbers.
     */
    function modexp(BytesUtils.slice memory base, BytesUtils.slice memory exponent, BytesUtils.slice memory modulus) internal view returns (bool success, bytes output) {
        uint base_length = base.len;
        uint exponent_length = exponent.len;
        uint modulus_length = modulus.len;

        uint size = (32 * 3) + base_length + exponent_length + modulus_length;
        bytes memory input = new bytes(size);
        BytesUtils.slice memory inputslice;
        inputslice.fromBytes(input);

        inputslice.writeBytes32(0, bytes32(base_length));
        inputslice.writeBytes32(32, bytes32(exponent_length));
        inputslice.writeBytes32(64, bytes32(modulus_length));
        inputslice.memcpy(96, base, 0, base_length);
        inputslice.memcpy(96 + base_length, exponent, 0, exponent_length);
        inputslice.memcpy(96 + base_length + exponent_length, modulus, 0, modulus_length);

        output = new bytes(modulus_length);

        assembly {
            success := staticcall(gas(), 5, add(input, 32), size, add(output, 32), modulus_length)
        }
    }
}
