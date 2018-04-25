var sha256 = artifacts.require("./SHA256Digest.sol");
var sha1 = artifacts.require("./SHA1Digest.sol");

contract("SHA256Digest", function(accounts) {
  it('should return true for valid hashes', async function() {
    var instance = await sha256.deployed();
    assert.equal(await instance.verify("", "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), true);
    assert.equal(await instance.verify("foo", "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"), true);
  });

  it('should return false for invalid hashes', async function() {
    var instance = await sha256.deployed();
    assert.equal(await instance.verify("", "0x1111111111111111111111111111111111111111111111111111111111111111"), false);
  });
})

contract("SHA1Digest", function(accounts) {
  it('should return true for valid hashes', async function() {
    var instance = await sha1.deployed();
    assert.equal(await instance.verify("", "0xda39a3ee5e6b4b0d3255bfef95601890afd80709"), true);
    assert.equal(await instance.verify("foo", "0x0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"), true);
  });

  it('should return false for invalid hashes', async function() {
    var instance = await sha1.deployed();
    assert.equal(await instance.verify("", "0x1111111111111111111111111111111111111111"), false);
  });
})
