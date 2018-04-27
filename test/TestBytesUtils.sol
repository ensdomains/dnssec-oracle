pragma solidity ^0.4.23;

import "truffle/Assert.sol";
import "../contracts/RRUtils.sol";
import "../contracts/BytesUtils.sol";

contract TestBytesUtils {
  using BytesUtils for *;

  function testKeccak() public {
    Assert.equal("".keccak(0, 0), bytes32(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470), "Incorrect hash of empty string");
    Assert.equal("foo".keccak(0, 3), bytes32(0x41b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d), "Incorrect hash of 'foo'");
    Assert.equal("foo".keccak(0, 0), bytes32(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470), "Incorrect hash of empty string");
  }

  function testEquals() public {
    Assert.equal("hello".equals("hello"), true, "String equality");
    Assert.equal("hello".equals("goodbye"), false, "String inequality");
    Assert.equal("hello".equals(1, "ello"), true, "Substring to string equality");
    Assert.equal("hello".equals(1, "jello", 1, 4), true, "Substring to substring equality");
  }

  function testCompare() public {
    Assert.equal("a".compare("a")  == 0, true,  "Compare equal");
    Assert.equal("a".compare("b")   < 0, true,   "Compare different value with same length");
    Assert.equal("b".compare("a")   > 0, true,   "Compare different value with same length");
    Assert.equal("aa".compare("ab") < 0, true,   "Compare different value with multiple length");
    Assert.equal("a".compare("aa")  < 0, true,   "Compare different value with different length");
    Assert.equal("aa".compare("a")  > 0, true,   "Compare different value with different length");
    bytes memory longChar = "1234567890123456789012345678901234";
    Assert.equal(longChar.compare(longChar) == 0, true,   "Compares more than 32 bytes char");
    bytes memory otherLongChar = "2234567890123456789012345678901234";
    Assert.equal(longChar.compare(otherLongChar) < 0, true,   "Compare long char with difference at start");
  }

  function testSubstring() public {
    Assert.equal(string("hello".substring(0, 0)), "", "Copy 0 bytes");
    Assert.equal(string("hello".substring(0, 4)), "hell", "Copy substring");
    Assert.equal(string("hello".substring(1, 4)), "ello", "Copy substring");
    Assert.equal(string("hello".substring(0, 5)), "hello", "Copy whole string");
  }

  function testReadUint8() public {
    Assert.equal(uint("a".readUint8(0)), 0x61, "a == 0x61");
    Assert.equal(uint("ba".readUint8(1)), 0x61, "a == 0x61");
  }

  function testReadUint16() public {
    Assert.equal(uint("abc".readUint16(1)), 0x6263, "Read uint 16");
  }

  function testReadUint32() public {
    Assert.equal(uint("abcde".readUint32(1)), 0x62636465, "Read uint 32");
  }

  function testReadBytes20() public {
    Assert.equal(bytes32("abcdefghijklmnopqrstuv".readBytes20(1)), bytes32(bytes20(0x0062636465666768696A6B6C6D6E6F707172737475)), "readBytes20");
  }

  function testReadBytes32() public {
    Assert.equal("0123456789abcdef0123456789abcdef".readBytes32(0), bytes32(0x3031323334353637383961626364656630313233343536373839616263646566), "readBytes32");
  }
}
