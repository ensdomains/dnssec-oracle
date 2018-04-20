pragma solidity ^0.4.17;

library SHA1 {
    event Debug(bytes32 x);

    function sha1(bytes data) internal pure returns(bytes20 ret) {
        assembly {
            // Get a safe scratch location
            let scratch := mload(0x40)

            // Get the data length, and point data at the first byte
            let len := mload(data)
            data := add(data, 32)

            // Find the length after padding
            let totallen := add(and(add(len, 1), 0xFFFFFFFFFFFFFFC0), 64)
            switch lt(sub(totallen, len), 9)
            case 1 { totallen := add(totallen, 64) }

            let h := 0x6745230100EFCDAB890098BADCFE001032547600C3D2E1F0

            for { let i := 0 } lt(i, totallen) { i := add(i, 64) } {
                let word := 0
                if lt(i, len) { word := mload(add(data, i)) }
                mstore(scratch, word)

                word := 0
                if lt(add(i, 32), len) { word := mload(add(add(data, 32), i)) }
                mstore(add(scratch, 32), word)

                // If we loaded the last byte, store the terminator byte
                switch lt(sub(len, i), 64)
                case 1 { mstore8(add(scratch, sub(len, i)), 0x80) }

                // If this is the last block, store the length
                switch eq(i, sub(totallen, 64))
                case 1 { mstore(add(scratch, 32), or(mload(add(scratch, 32)), mul(len, 8))) }

                // Expand the 16 32-bit words into 80
                for { let j := 64 } lt(j, 128) { j := add(j, 12) } {
                    let temp := xor(xor(mload(add(scratch, sub(j, 12))), mload(add(scratch, sub(j, 32)))), xor(mload(add(scratch, sub(j, 56))), mload(add(scratch, sub(j, 64)))))
                    temp := or(and(mul(temp, 2), 0xFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFEFFFFFFFE), and(div(temp, exp(2, 31)), 0x0000000100000001000000010000000100000001000000010000000100000001))
                    mstore(add(scratch, j), temp)
                }
                for { let j := 128 } lt(j, 320) { j := add(j, 24) } {
                    let temp := xor(xor(mload(add(scratch, sub(j, 24))), mload(add(scratch, sub(j, 64)))), xor(mload(add(scratch, sub(j, 112))), mload(add(scratch, sub(j, 128)))))
                    temp := or(and(mul(temp, 4), 0xFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFCFFFFFFFC), and(div(temp, exp(2, 30)), 0x0000000300000003000000030000000300000003000000030000000300000003))
                    mstore(add(scratch, j), temp)
                }

                let x := h
                let f := 0
                let k := 0
                for { let j := 0 } lt(j, 80) { j := add(j, 1) } {
                    switch div(j, 20)
                    case 0 {
                        // f = d xor (b and (c xor d))
                        f := xor(div(x, exp(2, 80)), div(x, exp(2, 40)))
                        f := and(div(x, exp(2, 120)), f)
                        f := xor(div(x, exp(2, 40)), f)
                        k := 0x5A827999
                    }
                    case 1{
                        // f = b xor c xor d
                        f := xor(div(x, exp(2, 120)), div(x, exp(2, 80)))
                        f := xor(div(x, exp(2, 40)), f)
                        k := 0x6ED9EBA1
                    }
                    case 2 {
                        // f = (b and c) or (d and (b or c))
                        f := or(div(x, exp(2, 120)), div(x, exp(2, 80)))
                        f := and(div(x, exp(2, 40)), f)
                        f := or(and(div(x, exp(2, 120)), div(x, exp(2, 80))), f)
                        k := 0x8F1BBCDC
                    }
                    case 3 {
                        // f = b xor c xor d
                        f := xor(div(x, exp(2, 120)), div(x, exp(2, 80)))
                        f := xor(div(x, exp(2, 40)), f)
                        k := 0xCA62C1D6
                    }
                    // temp = (a leftrotate 5) + f + e + k + w[i]
                    let temp := and(div(x, exp(2, 187)), 0x1F)
                    temp := or(and(div(x, exp(2, 155)), 0xFFFFFFE0), temp)
                    temp := add(f, temp)
                    temp := add(and(x, 0xFFFFFFFF), temp)
                    temp := add(k, temp)
                    temp := add(div(mload(add(scratch, mul(j, 4))), exp(2, 224)), temp)
                    x := or(div(x, exp(2, 40)), mul(temp, exp(2, 160)))
                    x := or(and(x, 0xFFFFFFFF00FFFFFFFF000000000000FFFFFFFF00FFFFFFFF), mul(or(and(div(x, exp(2, 50)), 0xC0000000), and(div(x, exp(2, 82)), 0x3FFFFFFF)), exp(2, 80)))
                }

                h := and(add(h, x), 0xFFFFFFFF00FFFFFFFF00FFFFFFFF00FFFFFFFF00FFFFFFFF)
            }
            ret := mul(or(or(or(or(and(div(h, exp(2, 32)), 0xFFFFFFFF00000000000000000000000000000000), and(div(h, exp(2, 24)), 0xFFFFFFFF000000000000000000000000)), and(div(h, exp(2, 16)), 0xFFFFFFFF0000000000000000)), and(div(h, exp(2, 8)), 0xFFFFFFFF00000000)), and(h, 0xFFFFFFFF)), exp(256, 12))
        }
    }
}
