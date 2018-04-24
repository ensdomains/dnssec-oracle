pragma solidity ^0.4.19;

library Buffer {
    struct buffer {
        bytes buf;
        uint capacity;
    }

    function init(buffer memory buf, uint capacity) internal pure {
        if(capacity % 32 != 0) capacity += 32 - (capacity % 32);
        // Allocate space for the buffer data
        buf.capacity = capacity;
        assembly {
            let ptr := mload(0x40)
            mstore(buf, ptr)
            mstore(ptr, 0)
            mstore(0x40, add(ptr, capacity))
        }
    }

    function resize(buffer memory buf, uint capacity) private pure {
        bytes memory oldbuf = buf.buf;
        init(buf, capacity);
        append(buf, oldbuf);
    }

    function max(uint a, uint b) private pure returns(uint) {
        if(a > b) {
            return a;
        }
        return b;
    }

    /**
    * @dev Sets buffer length to 0.
    * @param buf The buffer to truncate.
    * @return The original buffer.
    */
    function truncate(buffer memory buf) internal pure returns (buffer memory) {
      assembly {
        let bufptr := mload(buf)
        mstore(bufptr, 0)
      }
      return buf;
    }

    /**
     * @dev Writes a byte string to a buffer. Resizes if doing so would exceed
     *      the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param off The start offset to write to.
     * @param data The data to append.
     * @return The original buffer.
     */
    function write(buffer memory buf, uint off, bytes data) internal pure returns(buffer memory) {
        if(off + data.length + buf.buf.length > buf.capacity) {
            resize(buf, max(buf.capacity, data.length + off) * 2);
        }

        uint dest;
        uint src;
        uint len = data.length;
        assembly {
            // Memory address of the buffer data
            let bufptr := mload(buf)
            // Length of existing buffer data
            let buflen := mload(bufptr)
            // Start address = buffer address + offset + sizeof(buffer length)
            dest := add(add(bufptr, 32), off)
            // Update buffer length if we're extending it
            if gt(add(len, off), buflen) {
              mstore(bufptr, add(len, off))
            }
            src := add(data, 32)
        }

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

        return buf;
    }

    /**
     * @dev Appends a byte string to a buffer. Resizes if doing so would exceed
     *      the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param data The data to append.
     * @return The original buffer.
     */
    function append(buffer memory buf, bytes data) internal pure returns (buffer memory) {
      return write(buf, buf.buf.length, data);
    }

    /**
     * @dev Writes a byte to the buffer. Resizes if doing so would exceed the
     *      capacity of the buffer.
     * @param buf The buffer to append to.
     * @param off The offset to write the byte at.
     * @param data The data to append.
     * @return The original buffer.
     */
    function write(buffer memory buf, uint off, uint8 data) internal pure returns(buffer memory) {
        if(off > buf.capacity) {
            resize(buf, buf.capacity * 2);
        }

        assembly {
            // Memory address of the buffer data
            let bufptr := mload(buf)
            // Length of existing buffer data
            let buflen := mload(bufptr)
            // Address = buffer address + sizeof(buffer length) + off
            let dest := add(add(bufptr, off), 32)
            mstore8(dest, data)
            // Update buffer length if we extended it
            if eq(off, buflen) {
                mstore(bufptr, add(buflen, 1))
            }
        }
        return buf;
    }

    /**
     * @dev Appends a byte to the buffer. Resizes if doing so would exceed the
     *      capacity of the buffer.
     * @param buf The buffer to append to.
     * @param data The data to append.
     * @return The original buffer.
     */
    function append(buffer memory buf, uint8 data) internal pure returns(buffer memory) {
      return write(buf, buf.buf.length, data);
    }

    /**
     * @dev Writes up to 32 bytes to the buffer. Resizes if doing so would
     *      exceed the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param off The offset to write at.
     * @param data The data to append.
     * @param len The number of bytes to write (left-aligned).
     * @return The original buffer.
     */
    function write(buffer memory buf, uint off, bytes32 data, uint len) private pure returns(buffer memory) {
      if(len + off > buf.capacity) {
          resize(buf, max(buf.capacity, len) * 2);
      }

      uint mask = 256 ** len - 1;
      // Right-align data
      data = data >> (8 * (32 - len));
      assembly {
          // Memory address of the buffer data
          let bufptr := mload(buf)
          // Address = buffer address + sizeof(buffer length) + off + len
          let dest := add(add(bufptr, off), len)
          mstore(dest, or(and(mload(dest), not(mask)), data))
          // Update buffer length if we extended it
          if gt(add(off, len), mload(bufptr)) {
            mstore(bufptr, add(off, len))
          }
      }
      return buf;
    }

    /**
     * @dev Writes a bytes20 to the buffer. Resizes if doing so would
     *      exceed the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param off The offset to write at.
     * @param data The data to append.
     * @return The original buffer.
     */
    function write(buffer memory buf, uint off, bytes20 data) internal pure returns (buffer memory) {
      return write(buf, off, bytes32(data), 20);
    }

    /**
     * @dev Appends a bytes20 to the buffer. Resizes if doing so would
     *      exceed the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param data The data to append.
     * @return The original buffer.
     */
    function append(buffer memory buf, bytes20 data) internal pure returns (buffer memory) {
      return write(buf, buf.buf.length, bytes32(data), 20);
    }

    /**
     * @dev Writes an integer to the buffer. Resizes if doing so
     * would exceed the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param off The offset to write at.
     * @param data The data to append.
     * @param len The number of bytes to write (right-aligned).
     * @return The original buffer.
     */
    function writeInt(buffer memory buf, uint off, uint data, uint len) private pure returns(buffer memory) {
        if(len + off > buf.capacity) {
            resize(buf, max(buf.capacity, len + off) * 2);
        }

        uint mask = 256 ** len - 1;
        assembly {
            // Memory address of the buffer data
            let bufptr := mload(buf)
            // Address = buffer address + off + sizeof(buffer length) + len
            let dest := add(add(bufptr, off), len)
            mstore(dest, or(and(mload(dest), not(mask)), data))
            // Update buffer length if we extended it
            if gt(add(off, len), mload(bufptr)) {
              mstore(bufptr, add(off, len))
            }
        }
        return buf;
    }
}
