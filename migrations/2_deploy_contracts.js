var rsasha256 = artifacts.require("./rsasha256algorithm.sol");
var sha256 = artifacts.require("./sha256digest.sol");
var dnssec = artifacts.require("./dnssec.sol");

module.exports = function(deployer) {
  deployer.deploy(dnssec).then(function() {
    return deployer.deploy(rsasha256);
  }).then(function() {
    return deployer.deploy(sha256);
  }).then(function() {
    return dnssec.deployed().then(function(instance) {
      return rsasha256.deployed().then(function(algorithm) {
        return instance.setAlgorithm(8, algorithm.address);
      }).then(function() {
        return sha256.deployed();
      }).then(function(digest) {
        return instance.setDigest(2, digest.address);
      });
    });
  });
};
