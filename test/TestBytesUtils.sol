pragma solidity ^0.7.4;

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
    Assert.equal("zhello".equals(1, "abchello", 3), true,   "Compare different value with multiple length");
  }

  function testComparePartial() public {
    Assert.equal("xax".compare(1, 1, "xxbxx", 2, 1)   < 0, true,  "Compare same length");
    Assert.equal("xax".compare(1, 1, "xxabxx", 2, 2)  < 0, true,  "Compare different length");
    Assert.equal("xax".compare(1, 1, "xxaxx", 2, 1)  == 0, true,  "Compare same with different offset");
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
    Assert.equal(bytes32("abcdefghijklmnopqrstuv".readBytes20(1)), bytes32(0x62636465666768696a6b6c6d6e6f707172737475000000000000000000000000), "readBytes20");
  }

  function testReadBytes32() public {
    Assert.equal("0123456789abcdef0123456789abcdef".readBytes32(0), bytes32(0x3031323334353637383961626364656630313233343536373839616263646566), "readBytes32");
  }

  function testBase32HexDecodeWord() public {
    Assert.equal("C4".base32HexDecodeWord(0, 2), bytes32(bytes1("a")), "Decode 'a'");
    Assert.equal("C5GG".base32HexDecodeWord(0, 4), bytes32(bytes2("aa")), "Decode 'aa'");
    Assert.equal("C5GM2".base32HexDecodeWord(0, 5), bytes32(bytes3("aaa")), "Decode 'aaa'");
    Assert.equal("C5GM2O8".base32HexDecodeWord(0, 7), bytes32(bytes4("aaaa")), "Decode 'aaaa'");
    Assert.equal("C5GM2OB1".base32HexDecodeWord(0, 8), bytes32(bytes5("aaaaa")), "Decode 'aaaaa'");
    Assert.equal("c5gm2Ob1".base32HexDecodeWord(0, 8), bytes32(bytes5("aaaaa")), "Decode 'aaaaa' lowercase");
    Assert.equal("C5H66P35CPJMGQBADDM6QRJFE1ON4SRKELR7EU3PF8".base32HexDecodeWord(0, 42), bytes32(bytes26("abcdefghijklmnopqrstuvwxyz")), "Decode alphabet");
    Assert.equal("c5h66p35cpjmgqbaddm6qrjfe1on4srkelr7eu3pf8".base32HexDecodeWord(0, 42), bytes32(bytes26("abcdefghijklmnopqrstuvwxyz")), "Decode alphabet lowercase");
    Assert.equal("C5GM2OB1C5GM2OB1C5GM2OB1C5GM2OB1C5GM2OB1C5GM2OB1C5GG".base32HexDecodeWord(0, 52), bytes32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "Decode 32*'a'");
    Assert.equal(" bst4hlje7r0o8c8p4o8q582lm0ejmiqt\x07matoken\x03xyz\x00".base32HexDecodeWord(1, 32), bytes32(hex"5f3a48d66e3ec18431192611a2a055b01d3b4b5d"), "Decode real bytes32hex");
  }
}
