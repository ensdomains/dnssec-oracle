import "truffle/Assert.sol";
import "../contracts/RRUtils.sol";
import "../contracts/BytesUtils.sol";

contract TestRRUtils {
  using BytesUtils for *;
  using RRUtils for bytes;
  using RRUtils for BytesUtils.Slice;

  uint16 constant DNSTYPE_A = 1;
  uint16 constant DNSTYPE_CNAME = 5;
  uint16 constant DNSTYPE_MX = 15;
  uint16 constant DNSTYPE_RRSIG = 46;
  uint16 constant DNSTYPE_NSEC = 47;
  uint16 constant DNSTYPE_TYPE1234 = 1234;

  function testCheckTypeBitmap() public {
    // From https://tools.ietf.org/html/rfc4034#section-4.3
    //    alfa.example.com. 86400 IN NSEC host.example.com. (
    //                               A MX RRSIG NSEC TYPE1234
    bytes memory typebitmap = hex'0006400100000003041b000000000000000000000000000000000000000000000000000020';
    BytesUtils.Slice memory s;
    s.fromBytes(typebitmap);

    // Exists in bitmap
    Assert.equal(s.checkTypeBitmap(DNSTYPE_A), true, "A record should exist in type bitmap");
    // Does not exist, but in a window that is included
    Assert.equal(s.checkTypeBitmap(DNSTYPE_CNAME), false, "CNAME record should not exist in type bitmap");
    // Does not exist, past the end of a window that is included
    Assert.equal(s.checkTypeBitmap(64), false, "Type 64 should not exist in type bitmap");
    // Does not exist, in a window that does not exist
    Assert.equal(s.checkTypeBitmap(769), false, "Type 769 should not exist in type bitmap");
    // Exists in a subsequent window
    Assert.equal(s.checkTypeBitmap(DNSTYPE_TYPE1234), true, "Type 1234 should exist in type bitmap");
    // Does not exist, past the end of the bitmap windows
    Assert.equal(s.checkTypeBitmap(1281), false, "Type 1281 should not exist in type bitmap");
  }

  function testCompareLabel() public {
    bytes memory bthLabXyz = hex'066274686c61620378797a00';
    bytes memory ethLabXyz = hex'066574686c61620378797a00';
    bytes memory xyz = hex'0378797a00';
    // Exists in bitmap
    Assert.equal(xyz.compareLabel(ethLabXyz)       <  0, true, "xyz comes before ethLab.xyz");
    Assert.equal(bthLabXyz.compareLabel(ethLabXyz) <  0, true, "bthLab.xyz comes before ethLab.xyz");
    Assert.equal(bthLabXyz.compareLabel(bthLabXyz) == 0, true, "bthLab.xyz and bthLab.xyz are the same");
    Assert.equal(ethLabXyz.compareLabel(bthLabXyz) >  0, true, "ethLab.xyz comes after bethLab.xyz");
    Assert.equal(bthLabXyz.compareLabel(xyz)       >  0, true, "bthLab.xyz comes after xyz");
  }
}
