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
}
