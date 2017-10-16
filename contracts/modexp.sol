pragma solidity ^0.4.13;

library BytesTool {
    function memcopy(bytes src, uint srcoffset, bytes dst, uint dstoffset, uint len) pure internal {
        assembly {
            src := add(src, add(32, srcoffset))
            dst := add(dst, add(32, dstoffset))

            // copy 32 bytes at once
            for
                {}
                iszero(lt(len, 32))
                {
                    dst := add(dst, 32)
                    src := add(src, 32)
                    len := sub(len, 32)
                }
                { mstore(dst, mload(src)) }

            // copy the remainder (0 < len < 32)
            let mask := sub(exp(256, sub(32, len)), 1)
            let srcpart := and(mload(src), not(mask))
            let dstpart := and(mload(dst), mask)
            mstore(dst, or(srcpart, dstpart))
        }
     }
}

library ModexpPrecompile {
    function modexp(bytes base, bytes exponent, bytes modulus) internal view returns (bool success, bytes output) {
        uint base_length = base.length;
        uint exponent_length = exponent.length;
        uint modulus_length = modulus.length;

        uint size = (32 * 3) + base_length + exponent_length + modulus_length;
        bytes memory input = new bytes(size);
        output = new bytes(modulus_length);

        assembly {
            mstore(add(input, 32), base_length)
            mstore(add(input, 64), exponent_length)
            mstore(add(input, 96), modulus_length)
        }

        BytesTool.memcopy(base, 0, input, 96, base_length);
        BytesTool.memcopy(exponent, 0, input, 96 + base_length, exponent_length);
        BytesTool.memcopy(modulus, 0, input, 96 + base_length + exponent_length, modulus_length);

        assembly {
            success := staticcall(gas(), 5, add(input, 32), size, add(output, 32), modulus_length)
        }
    }

    // Optimised for small exponent (such as RSA)
    function modexp(bytes base, uint exponent, bytes modulus) internal view returns (bool success, bytes output) {
        uint base_length = base.length;
        uint modulus_length = modulus.length;

        uint size = (32 * 3) + base_length + 32 + modulus_length;
        bytes memory input = new bytes(size);
        output = new bytes(modulus_length);

        assembly {
            mstore(add(input, 32), base_length)
            mstore(add(input, 64), 32)
            mstore(add(input, 96), modulus_length)

            mstore(add(input, add(128, base_length)), exponent)
        }

        BytesTool.memcopy(base, 0, input, 96, base_length);
        BytesTool.memcopy(modulus, 0, input, 96 + base_length + 32, modulus_length);

        assembly {
            success := staticcall(gas(), 5, add(input, 32), size, add(output, 32), modulus_length)
        }
    }
}
