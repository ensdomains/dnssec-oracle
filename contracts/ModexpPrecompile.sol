pragma solidity ^0.4.17;

import "./BytesUtils.sol";

library ModexpPrecompile {
    using BytesUtils for *;

    /**
     * @dev Computes (base ^ exponent) % modulus over big numbers.
     */
    function modexp(BytesUtils.Slice memory base, BytesUtils.Slice memory exponent, BytesUtils.Slice memory modulus, BytesUtils.Slice memory output) internal view returns (bool success) {
        uint base_length = base.len;
        uint exponent_length = exponent.len;
        uint modulus_length = modulus.len;

        uint size = (32 * 3) + base_length + exponent_length + modulus_length;
        bytes memory input = new bytes(size);
        BytesUtils.Slice memory inputslice;
        inputslice.fromBytes(input);

        inputslice.writeBytes32(0, bytes32(base_length));
        inputslice.writeBytes32(32, bytes32(exponent_length));
        inputslice.writeBytes32(64, bytes32(modulus_length));
        inputslice.memcpy(96, base, 0, base_length);
        inputslice.memcpy(96 + base_length, exponent, 0, exponent_length);
        inputslice.memcpy(96 + base_length + exponent_length, modulus, 0, modulus_length);

        assembly {
            success := staticcall(gas(), 5, add(input, 32), size, mload(add(output, 32)), modulus_length)
        }
    }
}
