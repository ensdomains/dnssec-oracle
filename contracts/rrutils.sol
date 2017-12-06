pragma solidity ^0.4.17;

import "./bytesutils.sol";

library RRUtils {
    using BytesUtils for *;

    function dnsNameAt(BytesUtils.Slice self, uint startIdx, BytesUtils.Slice memory target) internal pure returns (BytesUtils.Slice) {
        target._ptr = self._ptr + startIdx;

        var idx = startIdx;
        while (true) {
            assert(idx < self.len);
            var labelLen = self.uint8At(idx);
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
            var labelLen = self.uint8At(off);
            if (labelLen == 0) return;
            off += labelLen + 1;
            ret += 1;
        }
    }
}
