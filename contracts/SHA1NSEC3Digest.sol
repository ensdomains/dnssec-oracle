pragma solidity ^0.4.17;

import "./NSEC3Digest.sol";
import "./sha1/contracts/SHA1.sol";
import "./Buffer.sol";

contract SHA1NSEC3Digest is NSEC3Digest {
  using Buffer for Buffer.buffer;

  function hash(bytes salt, bytes data, uint iterations) public pure returns (bytes) {
    Buffer.buffer memory buf;
    buf.init(salt.length + data.length + 16);

    buf.append(data);
    buf.append(salt);
    bytes20 h = SHA1.sha1(buf.buf);

    for(uint i = 0; i < iterations; i++) {
      buf.truncate();
      buf.append(h);
      buf.append(salt);
      h = SHA1.sha1(buf.buf);
    }

    buf.truncate();
    buf.append(h);
    return buf.buf;
  }
}
