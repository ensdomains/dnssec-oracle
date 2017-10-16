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

contract ModexpPrecompileTest {
    function test1() public returns (bytes) {
        var (, ret) = ModexpPrecompile.modexp(hex"03", hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
        return ret;
    }

    function test2() public returns (bytes) {
        bytes memory S = hex"77c6b0c53800d37b6b946df6d91a693c25b1ba97cac16879a10b3231a5cea0932a0bc16443b2e82b33ec155a61b29572a5faaf574152bd509a248fdb8ed9d7af";
        uint e = 65537;
        bytes memory N = hex"00890e68c2485f2c725116f259a7ac871e1de3618dfc41e1df8eacc0131b2d433de6ed6d1f36bbf5a401d5afa32eeb2d444cf02a920c81f8088ba0b99d47a0bfdf";

        var (, ret) = ModexpPrecompile.modexp(S, e, N);
        return ret;
    }
}
