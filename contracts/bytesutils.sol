pragma solidity ^0.4.17;

library BytesUtils {
    struct slice {
        uint len;
        uint _ptr;
    }

    function memcpy(uint dest, uint src, uint len) private pure {
        // Copy word-length chunks while possible
        for(; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    /**
     * @dev Copies memory from one slice to another.
     *
     * Not safe to use if `src` and `dest` overlap.
     *
     * @param dest The destination slice.
     * @param destoff Offset into the destination slice.
     * @param src The source slice.
     * @param srcoff Offset into the source slice.
     * @param len Number of bytes to copy.
     */
    function memcpy(slice memory dest, uint destoff, slice memory src, uint srcoff, uint len) internal pure {
        require(destoff + len <= dest.len);
        require(srcoff + len <= src.len);
        memcpy(dest._ptr + destoff, src._ptr + srcoff, len);
    }

    /*
     * @dev Returns a slice containing the entire byte string.
     * @param self The byte string to make a slice from.
     * @return A newly allocated slice
     */
    function toSlice(bytes self) internal pure returns (slice) {
        uint ptr;
        assembly {
            ptr := add(self, 0x20)
        }
        return slice(ptr, self.length);
    }

    /*
     * @dev Initializes a slice from a byte string.
     * @param self The slice to iInitialize.
     * @param data The byte string to initialize from.
     * @return The initialized slice.
     */
    function fromBytes(slice self, bytes data) internal pure returns (slice) {
        uint ptr;
        assembly {
            ptr := add(data, 0x20)
        }
        self._ptr = ptr;
        self.len = data.length;
        return self;
    }

    /*
     * @dev Makes 'self' a duplicate of 'other'.
     * @param self The slice to copy to.
     * @param other The slice to copy from
     * @return self
     */
    function copyFrom(slice self, slice other) internal pure returns (slice) {
        self._ptr = other._ptr;
        self.len = other.len;
        return self;
    }

    /*
     * @dev Copies a slice to a new byte string.
     * @param self The slice to copy.
     * @return A newly allocated byte string containing the slice's text.
     */
    function toBytes(slice self) internal pure returns (bytes) {
        var ret = new bytes(self.len);
        uint retptr;
        assembly { retptr := add(ret, 32) }

        memcpy(retptr, self._ptr, self.len);
        return ret;
    }

    /*
     * @dev Copies a slice to a new byte string
     * @param self The slice to copy
     * @param start The start position to copy, inclusive
     * @param end The end position to copy, exclusive
     * @return A newly allocated byte string.
     */
    function toBytes(slice self, uint start, uint end) internal pure returns (bytes memory ret) {
        require(start <= end && end <= self.len);
        ret = new bytes(end - start);
        uint retptr;
        assembly { retptr := add(ret, 32) }
        memcpy(retptr, self._ptr + start, end - start);
    }


    /*
     * @dev Returns a positive number if `other` comes lexicographically after
     *      `self`, a negative number if it comes before, or zero if the
     *      contents of the two slices are equal. Comparison is done per-rune,
     *      on unicode codepoints.
     * @param self The first slice to compare.
     * @param other The second slice to compare.
     * @return The result of the comparison.
     */
    function compare(slice self, slice other) internal pure returns (int) {
        uint shortest = self.len;
        if (other.len < self.len)
            shortest = other.len;

        var selfptr = self._ptr;
        var otherptr = other._ptr;
        for (uint idx = 0; idx < shortest; idx += 32) {
            uint a;
            uint b;
            assembly {
                a := mload(selfptr)
                b := mload(otherptr)
            }
            if (a != b) {
                // Mask out irrelevant bytes and check again
                uint mask = ~(2 ** (8 * (32 - shortest + idx)) - 1);
                var diff = (a & mask) - (b & mask);
                if (diff != 0)
                    return int(diff);
            }
            selfptr += 32;
            otherptr += 32;
        }
        return int(self.len) - int(other.len);
    }

    /*
     * @dev Returns true if the two slices contain the same text.
     * @param self The first slice to compare.
     * @param self The second slice to compare.
     * @return True if the slices are equal, false otherwise.
     */
    function equals(slice self, slice other) internal pure returns (bool) {
        return keccak(self) == keccak(other);
    }

    /*
     * @dev Returns the keccak-256 hash of the slice.
     * @param self The slice to hash.
     * @return The hash of the slice.
     */
    function keccak(slice self) internal pure returns (bytes32 ret) {
        assembly {
            ret := sha3(mload(add(self, 32)), mload(self))
        }
    }

    /*
     * @dev Reslices the current slice
     * @param self The slice to reslice.
     * @param start The start index, inclusive.
     * @param end The end index, exclusive.
     * @return The modified slice.
     */
    function s(slice self, uint start, uint end) internal pure returns (slice) {
        assert(start >= 0 && end <= self.len && start <= end);

        self._ptr += uint(start);
        self.len = end - start;
        return self;
    }

    /*
     * @dev Returns true iff the slice is a suffix of the provided byte string.
     * @param self The slice to test.
     * @param data The byte string to test against.
     */
    function suffixOf(slice self, uint off, bytes data) internal pure returns (bool ret) {
        var suffixlen = self.len - off;
        require(suffixlen <= data.length);
        var suffixOffset = 32 + (data.length - suffixlen);
        assembly {
          let suffixhash := keccak256(add(data, suffixOffset), suffixlen)
          let ourhash := keccak256(add(mload(add(self, 32)), off), suffixlen)
          ret := eq(suffixhash, ourhash)
        }
    }

    /*
     * @dev Returns the specified byte from the slice.
     * @param self The slice.
     * @param idx The index into the slice.
     * @return The specified 8 bits of slice, interpreted as a byte.
     */
    function byteAt(slice self, uint idx) internal pure returns (byte ret) {
        var ptr = self._ptr;
        assembly {
            ret := and(mload(add(sub(ptr, 31), idx)), 0xFF)
        }
    }

    /*
     * @dev Returns the 8-bit number at the specified index of self.
     * @param self The slice.
     * @param idx The index into the slice
     * @return The specified 8 bits of slice, interpreted as an integer.
     */
    function uint8At(slice self, uint idx) internal pure returns (uint8 ret) {
        var ptr = self._ptr;
        assembly {
            ret := and(mload(add(sub(ptr, 31), idx)), 0xFF)
        }
    }

    /*
     * @dev Returns the 16-bit number at the specified index of self.
     * @param self The slice.
     * @param idx The index into the slice
     * @return The specified 16 bits of slice, interpreted as an integer.
     */
    function uint16At(slice self, uint idx) internal pure returns (uint16 ret) {
        var ptr = self._ptr;
        assembly {
            ret := and(mload(add(sub(ptr, 30), idx)), 0xFFFF)
        }
    }

    /*
     * @dev Returns the 32-bit number at the specified index of self.
     * @param self The slice.
     * @param idx The index into the slice
     * @return The specified 32 bits of slice, interpreted as an integer.
     */
    function uint32At(slice self, uint idx) internal pure returns (uint32 ret) {
        var ptr = self._ptr;
        assembly {
            ret := and(mload(add(sub(ptr, 28), idx)), 0xFFFFFFFF)
        }
    }

    /*
     * @dev Returns the bytes32 at the specified index of self.
     * @param self The slice.
     * @param idx The index into the slice
     * @return The specified 32 bytes of slice.
     */
    function bytes32At(slice self, uint idx) internal pure returns (bytes32 ret) {
        var ptr = self._ptr + idx;
        assembly { ret := mload(ptr) }
    }

    /*
     * @dev Writes a word to the specified index of self.
     * @param self The slice.
     * @param idx The index into the slice.
     * @param data The word to write.
     */
    function writeBytes32(slice self, uint idx, bytes32 data) internal pure {
        var ptr = self._ptr + idx;
        assembly { mstore(ptr, data) }
    }
}
