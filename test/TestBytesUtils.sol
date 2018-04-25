import "truffle/Assert.sol";
import "../contracts/RRUtils.sol";
import "../contracts/BytesUtils.sol";

contract TestBytesUtils {
  using BytesUtils for *;

  function testKeccak() {
    Assert.equal("".keccak(0, 0), bytes32(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470), "Incorrect hash of empty string");
    Assert.equal("foo".keccak(0, 3), bytes32(0x41b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d), "Incorrect hash of 'foo'");
    Assert.equal("foo".keccak(0, 0), bytes32(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470), "Incorrect hash of empty string");
  }

  function testEquals() {
    Assert.equal("hello".equals("hello"), true, "String equality");
    Assert.equal("hello".equals("goodbye"), false, "String inequality");
    Assert.equal("hello".equals(1, "ello"), true, "Substring to string equality");
    Assert.equal("hello".equals(1, "jello", 1, 4), true, "Substring to substring equality");
  }

  function testSubstring() {
    Assert.equal(string("hello".substring(0, 0)), "", "Copy 0 bytes");
    Assert.equal(string("hello".substring(0, 4)), "hell", "Copy substring");
    Assert.equal(string("hello".substring(1, 4)), "ello", "Copy substring");
    Assert.equal(string("hello".substring(0, 5)), "hello", "Copy whole string");
  }
}
