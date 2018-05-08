pragma solidity ^0.4.17;

import "./BytesUtils.sol";
import "./Buffer.sol";

/**
 * @dev RRUtils is a library that provides utilities for parsing DNS resource records.
 */
library RRUtils {
    using BytesUtils for *;
    using Buffer for *;

    /**
     * @dev Returns the number of bytes in the DNS name at 'offset' in 'self'.
     * @param self The byte array to read a name from.
     * @param offset The offset to start reading at.
     * @return The length of the DNS name at 'offset', in bytes.
     */
    function nameLength(bytes memory self, uint offset) internal pure returns(uint) {
        uint idx = offset;
        while (true) {
            assert(idx < self.length);
            uint labelLen = self.readUint8(idx);
            idx += labelLen + 1;
            if (labelLen == 0) break;
        }
        return idx - offset;
    }

    /**
     * @dev Returns the number of labels in the DNS name at 'offset' in 'self'.
     * @param self The byte array to read a name from.
     * @param offset The offset to start reading at.
     * @return The number of labels in the DNS name at 'offset', in bytes.
     */
    function labelCount(bytes memory self, uint offset) internal pure returns(uint) {
        uint count = 0;
        while (true) {
            assert(offset < self.length);
            uint labelLen = self.readUint8(offset);
            offset += labelLen + 1;
            if (labelLen == 0) break;
            count += 1;
        }
        return count;
    }

    /**
     * @dev An iterator over resource records.
     */
    struct RRIterator {
        bytes data;
        uint offset;
        uint16 dnstype;
        uint16 class;
        uint32 ttl;
        uint rdataOffset;
        uint nextOffset;
    }

    /**
     * @dev Begins iterating over resource records.
     * @param self The byte string to read from.
     * @param offset The offset to start reading at.
     * @return An iterator object.
     */
    function iterateRRs(bytes memory self, uint offset) internal pure returns (RRIterator memory ret) {
      ret.data = self;
      ret.nextOffset = offset;
      next(ret);
    }

    /**
     * @dev Returns true iff there are more RRs to iterate.
     * @param iter The iterator to check.
     * @return True iff the iterator has finished.
     */
    function done(RRIterator memory iter) internal pure returns(bool) {
      return iter.offset >= iter.data.length;
    }

    /**
     * @dev Moves the iterator to the next resource record.
     * @param iter The iterator to advance.
     */
    function next(RRIterator memory iter) internal pure {
        iter.offset = iter.nextOffset;
        if(iter.offset >= iter.data.length) return;

        // Skip the name
        uint off = iter.offset + nameLength(iter.data, iter.offset);

        // Read type, class, and ttl
        iter.dnstype = iter.data.readUint16(off); off += 2;
        iter.class = iter.data.readUint16(off); off += 2;
        iter.ttl = iter.data.readUint32(off); off += 4;

        // Read the rdata
        uint rdataLength = iter.data.readUint16(off); off += 2;
        iter.rdataOffset = off;
        iter.nextOffset = off + rdataLength;
    }

    /**
     * @dev Returns the name of the current record.
     * @param iter The iterator.
     * @return A new bytes object containing the owner name from the RR.
     */
    function name(RRIterator memory iter) internal pure returns(bytes memory) {
        return iter.data.substring(iter.offset, nameLength(iter.data, iter.offset));
    }

    /**
     * @dev Returns the rdata portion of the current record.
     * @param iter The iterator.
     * @return A new bytes object containing the RR's RDATA.
     */
    function rdata(RRIterator memory iter) internal pure returns(bytes memory) {
        return iter.data.substring(iter.rdataOffset, iter.nextOffset - iter.rdataOffset);
    }

    /**
     * @dev Checks if a given RR type exists in a type bitmap.
     * @param self The byte string to read the type bitmap from.
     * @param offset The offset to start reading at.
     * @param rrtype The RR type to check for.
     * @return True if the type is found in the bitmap, false otherwise.
     */
    function checkTypeBitmap(bytes memory self, uint offset, uint16 rrtype) internal pure returns (bool) {
        uint8 typeWindow = uint8(rrtype >> 8);
        uint8 windowByte = uint8((rrtype & 0xff) / 8);
        uint8 windowBitmask = uint8(uint8(1) << (uint8(7) - uint8(rrtype & 0x7)));
        for(uint off = offset; off < self.length;) {
            uint8 window = self.readUint8(off);
            uint8 len = self.readUint8(off + 1);
            if(typeWindow < window) {
                // We've gone past our window; it's not here.
                return false;
            } else if(typeWindow == window) {
                // Check this type bitmap
                if(len * 8 <= windowByte) {
                    // Our type is past the end of the bitmap
                    return false;
                }
                return (self.readUint8(off + windowByte + 2) & windowBitmask) != 0;
            } else {
                // Skip this type bitmap
                off += len + 2;
            }
        }

        return false;
    }

    function compareNames(bytes memory self, bytes memory other) internal  returns (int){
        bool equal = self.equals(other);
        if(equal){ return 0; }

        uint off = 0;
        uint otheroff = 0;
        uint head;
        uint otherhead;
        uint counts = labelCount(self, 0);
        uint othercounts = labelCount(other, 0);

        // Keep removing labels from the front of the name until both names are equal,
        // then compare the last nonequal labels to each other
        while (!equal) {
            if(counts >= othercounts){
                head = off + 1;
                off = progress(self, off);
            }
            if(counts <= othercounts){
                otherhead = otheroff + 1;
                otheroff = progress(other, otheroff);
            }
            if(counts != 0 )
                counts = labelCount(self, off);
            if(othercounts != 0 )
                othercounts = labelCount(other, otheroff);
            if(counts == 0 && othercounts ==0)
                break;

            equal = self.equals(off, other, otheroff);
        }
        return self.compare(head, self.readUint8(head), other, otherhead, other.readUint8(otherhead));
    }

    function progress(bytes memory body, uint off) internal  returns(uint){
        return  off + 1 + body.readUint8(off);
    }
}
