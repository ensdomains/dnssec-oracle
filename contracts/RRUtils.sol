pragma solidity ^0.4.17;

import "./BytesUtils.sol";

library RRUtils {
    using BytesUtils for *;

    function dnsNameAt(BytesUtils.Slice self, uint startIdx, BytesUtils.Slice memory target) internal pure returns (BytesUtils.Slice) {
        target._ptr = self._ptr + startIdx;

        uint idx = startIdx;
        while (true) {
            assert(idx < self.len);
            uint labelLen = self.uint8At(idx);
            idx += labelLen + 1;
            if (labelLen == 0) break;
        }
        target.len = idx - startIdx;
        return target;
    }

    function nextRR(BytesUtils.Slice memory self, BytesUtils.Slice memory name, BytesUtils.Slice memory rdata) internal pure returns (uint16 dnstype, uint16 class, uint32 ttl) {
        // Compute the offset from self to the start of the next record
        uint off;
        if (rdata._ptr < self._ptr || rdata._ptr > self._ptr + self.len) {
            off = 0;
        } else {
            off = (rdata._ptr + rdata.len) - self._ptr;
        }

        if (off >= self.len) {
            return (0, 0, 0);
        }

        // Parse the name
        dnsNameAt(self, off, name); off += name.len;

        // Read type, class, and ttl
        dnstype = self.uint16At(off); off += 2;
        class = self.uint16At(off); off += 2;
        ttl = self.uint32At(off); off += 4;

        // Read the rdata
        rdata.len = self.uint16At(off); off += 2;
        rdata._ptr = self._ptr + off;
    }

    function countLabels(BytesUtils.Slice memory self, uint off) internal pure returns (uint ret) {
        while (true) {
            assert(off < self.len);
            uint8 labelLen = self.uint8At(off);
            if (labelLen == 0) return;
            off += labelLen + 1;
            ret += 1;
        }
    }
    function checkTypeBitmap(BytesUtils.Slice memory self, uint16 rrtype) internal pure returns (bool) {
        uint8 typeWindow = uint8(rrtype >> 8);
        uint8 windowByte = uint8((rrtype & 0xff) / 8);
        uint8 windowBitmask = uint8(1 << (7 - (rrtype & 0x7)));
        for(uint off = 0; off < self.len;) {
            uint8 window = self.uint8At(off);
            uint8 len = self.uint8At(off + 1);
            if(typeWindow < window) {
                // We've gone past our window; it's not here.
                return false;
            } else if(typeWindow == window) {
                // Check this type bitmap
                if(len * 8 <= windowByte) {
                    // Our type is past the end of the bitmap
                    return false;
                }

                return (self.uint8At(off + windowByte + 2) & windowBitmask) != 0;
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
