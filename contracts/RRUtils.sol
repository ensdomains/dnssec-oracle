pragma solidity ^0.4.17;

import "./BytesUtils.sol";
import "./Buffer.sol";

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
     */
    function done(RRIterator memory iter) internal pure returns(bool) {
      return iter.offset >= iter.data.length;
    }

    /**
     * @dev Moves the iterator to the next resource record.
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
     */
    function name(RRIterator memory iter) internal pure returns(bytes memory) {
        return iter.data.substring(iter.offset, nameLength(iter.data, iter.offset));
    }

    /**
     * @dev Returns the rdata portion of the current record.
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
        uint8 windowBitmask = uint8(1 << (7 - (rrtype & 0x7)));
        for(uint off = 0; off < self.length;) {
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

    event Logger(string name);
    event LoggerBytes(bytes name);
    event LoggerInt(int label);

    function compareLabel(bytes a, bytes b) internal returns (int){
         BytesUtils.Slice memory aSlice = a.toSlice();
         BytesUtils.Slice memory bSlice = b.toSlice();
         BytesUtils.Slice memory aHead;
         BytesUtils.Slice memory bHead;
         uint aLength = countLabels(aSlice, 0);
         uint bLength = countLabels(bSlice, 0);
         uint length;
         if (aLength < bLength){
            length = aLength;
         }else{
            length = bLength;
         }
         emit LoggerInt(int(length));

        uint aTailStart = aLength - length;
        uint bTailStart = bLength - length;
        BytesUtils.Slice memory aTail;
        BytesUtils.Slice memory bTail;
        if(aLength == length){
            aTail = aSlice;
        }else{
            (aHead, aTail) = headAndTail(aSlice);
        }
        if(bLength == length){
            bTail = bSlice;
        }else{
            (bHead, bTail) = headAndTail(bSlice);
        }
        int result = compareTail(aTail.toBytes(), bTail.toBytes());
        if(result != 0){
            return result;   
        }else{
            if(aLength < bLength){
                return -1;
            }else if (aLength > bLength){
                return 1;
            }else(aLength == bLength){
                // a and b are identical
                return 0;
            }
        }
    }

    function compareTail(bytes a, bytes b) internal returns (int) {
        // when both are '.'
        if (keccak256(a) == keccak256(hex'00') && keccak256(b) == keccak256(hex'00')){
            return 0;
        }
        BytesUtils.Slice memory aSlice = a.toSlice();
        BytesUtils.Slice memory bSlice = b.toSlice();
        // getting head
        BytesUtils.Slice memory aHead;
        BytesUtils.Slice memory bHead;
        BytesUtils.Slice memory aTail;
        BytesUtils.Slice memory bTail;
        (aHead, aTail) = headAndTail(aSlice);
        (bHead, bTail) = headAndTail(bSlice);
        int result = compareTail(aTail.toBytes(), bTail.toBytes());
        if(result == 0){
            return aHead.compare(bHead);
        }else{
            return result;
        }
    }

    function headAndTail(BytesUtils.Slice aSlice) internal returns(BytesUtils.Slice head, BytesUtils.Slice tail){
        uint aHeadLength =  aSlice.uint8At(0);
        BytesUtils.Slice memory aHead;
        aHead.copyFrom(aSlice).s(1,aHeadLength);
        // getting tail
        BytesUtils.Slice memory aTail;
        aTail.copyFrom(aSlice).s(1 + aHeadLength, aSlice.len);
        return (aHead, aTail);
    }
}
