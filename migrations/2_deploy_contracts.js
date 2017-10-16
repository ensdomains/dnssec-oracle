var rsasha256 = artifacts.require("./rsasha256algorithm.sol");
var sha256 = artifacts.require("./sha256digest.sol");
var dnssec = artifacts.require("./dnssec.sol");
var dummyalgorithm = artifacts.require("./dummyalgorithm.sol");
var dummydigest = artifacts.require("./dummydigest.sol");

module.exports = function(deployer, network) {
  var dev = network == "development";
  return deployer.deploy(dnssec)
    .then(() => deployer.deploy(rsasha256))
    .then(() => deployer.deploy(sha256))
    .then(() => dev?deployer.deploy(dummyalgorithm):null)
    .then(() => dev?deployer.deploy(dummydigest):null)
    .then(() => dnssec.deployed().then(function(instance) {
      tasks = [];
      tasks.push(rsasha256.deployed().then((algorithm) => instance.setAlgorithm(8, algorithm.address)));
      tasks.push(sha256.deployed().then((digest) => instance.setDigest(2, digest.address)));
      if(dev) {
        tasks.push(dummyalgorithm.deployed().then((algorithm) => instance.setAlgorithm(253, algorithm.address)));
        tasks.push(dummydigest.deployed().then((digest) => instance.setDigest(253, digest.address)));
      }
      return Promise.all(tasks);
    }));
};
