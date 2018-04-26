import "truffle/Assert.sol";
import "../contracts/RRUtils.sol";
import "../contracts/BytesUtils.sol";

contract TestRRUtils {
  using BytesUtils for *;
  using RRUtils for *;

  uint16 constant DNSTYPE_A = 1;
  uint16 constant DNSTYPE_CNAME = 5;
  uint16 constant DNSTYPE_MX = 15;
  uint16 constant DNSTYPE_RRSIG = 46;
  uint16 constant DNSTYPE_NSEC = 47;
  uint16 constant DNSTYPE_TYPE1234 = 1234;

  function testNameLength() {
    Assert.equal(hex'00'.nameLength(0), 1, "nameLength('.') == 1");
    Assert.equal(hex'0361626300'.nameLength(4), 1, "nameLength('.') == 1");
    Assert.equal(hex'0361626300'.nameLength(0), 5, "nameLength('abc.') == 5");
  }

  function testLabelCount() {
    Assert.equal(hex'00'.labelCount(0), 0, "labelCount('.') == 0");
    Assert.equal(hex'016100'.labelCount(0), 1, "labelCount('a.') == 1");
    Assert.equal(hex'0162016100'.labelCount(0), 2, "labelCount('b.a.') == 2");
  }

  function testIterateRRs() {
    // a. IN A 3600 127.0.0.1
    // b.a. IN A 3600 192.168.1.1
    bytes memory rrs = hex'0161000001000100000e1000047400000101620161000001000100000e100004c0a80101';
    string[2] memory names = [hex'016100', hex'0162016100'];
    string[2] memory rdatas = [hex'74000001', hex'c0a80101'];
    uint i = 0;
    for(RRUtils.RRIterator memory iter = rrs.iterateRRs(0); !iter.done(); iter.next()) {
      Assert.equal(uint(iter.dnstype), 1, "Type matches");
      Assert.equal(uint(iter.class), 1, "Class matches");
      Assert.equal(uint(iter.ttl), 3600, "TTL matches");
      Assert.equal(string(iter.name()), names[i], "Name matches");
      Assert.equal(string(iter.rdata()), rdatas[i], "Rdata matches");
      i++;
    }
    Assert.equal(i, 2, "Expected 2 records");
  }

  function testCheckTypeBitmap() public {
    // From https://tools.ietf.org/html/rfc4034#section-4.3
    //    alfa.example.com. 86400 IN NSEC host.example.com. (
    //                               A MX RRSIG NSEC TYPE1234
    bytes memory tb = hex'0006400100000003041b000000000000000000000000000000000000000000000000000020';

    // Exists in bitmap
    Assert.equal(tb.checkTypeBitmap(0, DNSTYPE_A), true, "A record should exist in type bitmap");
    // Does not exist, but in a window that is included
    Assert.equal(tb.checkTypeBitmap(0, DNSTYPE_CNAME), false, "CNAME record should not exist in type bitmap");
    // Does not exist, past the end of a window that is included
    Assert.equal(tb.checkTypeBitmap(0, 64), false, "Type 64 should not exist in type bitmap");
    // Does not exist, in a window that does not exist
    Assert.equal(tb.checkTypeBitmap(0, 769), false, "Type 769 should not exist in type bitmap");
    // Exists in a subsequent window
    Assert.equal(tb.checkTypeBitmap(0, DNSTYPE_TYPE1234), true, "Type 1234 should exist in type bitmap");
    // Does not exist, past the end of the bitmap windows
    Assert.equal(tb.checkTypeBitmap(0, 1281), false, "Type 1281 should not exist in type bitmap");
  }
}
