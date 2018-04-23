var sha1 = artifacts.require("./SHA1NSEC3Digest.sol");

vectors = [
  ["", "", 0, "0xda39a3ee5e6b4b0d3255bfef95601890afd80709"],
  ["nacl", "test", 0, "0x68b36a28941caebfc2af818c99a8e34478d77fec"],
  ["nacl", "test", 1, "0x16574cbb9312cf064794482fdd1148289027db73"],
  ["nacl", "test", 10, "0x455370ef51d39be8efa646b807a818c7649a505e"],
];

contract("SHA1NSEC3Digest", function(accounts) {
  for(var i = 0; i < vectors.length; i++) {
    (function(i, vector) {
      it('calculates test vector ' + i, async function() {
        var instance = await sha1.deployed();
        assert.equal(await instance.hash(vector[0], vector[1], vector[2]), vector[3])
      });
    })(i, vectors[i]);
  }
})
