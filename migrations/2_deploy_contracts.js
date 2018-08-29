var rsasha1 = artifacts.require("./algorithms/RSASHA1Algorithm");
var rsasha256 = artifacts.require("./algorithms/RSASHA256Algorithm");
var sha1 = artifacts.require("./digests/SHA1Digest");
var sha256 = artifacts.require("./digests/SHA256Digest");
var nsec3sha1 = artifacts.require("./nsec3digests/SHA1NSEC3Digest");
var dnssec = artifacts.require("./DNSSECImpl");
var dummyalgorithm = artifacts.require("./algorithms/DummyAlgorithm");
var dummydigest = artifacts.require("./digests/DummyDigest");

var dns = require("../lib/dns.js");

module.exports = function(deployer, network) {
  var dev = (network == "test" || network == "local");
  // From http://data.iana.org/root-anchors/root-anchors.xml
  var anchors = dns.anchors;

  if(dev) {
    anchors.push(dns.dummyAnchor);
  }
  return deployer.deploy(dnssec, dns.encodeAnchors(anchors))
    .then(() => deployer.deploy([[rsasha256], [rsasha1], [sha256], [sha1], [nsec3sha1]]))
    .then(() => dev?deployer.deploy([[dummyalgorithm], [dummydigest]]):null)
    .then(() => dnssec.deployed().then(function(instance) {
      tasks = [];
      tasks.push(rsasha1.deployed().then(async function(algorithm) {
        await instance.setAlgorithm(5, algorithm.address);
        await instance.setAlgorithm(7, algorithm.address);
      }));
      tasks.push(rsasha256.deployed().then((algorithm) => instance.setAlgorithm(8, algorithm.address)));
      tasks.push(sha1.deployed().then((digest) => instance.setDigest(1, digest.address)));
      tasks.push(sha256.deployed().then((digest) => instance.setDigest(2, digest.address)));
      tasks.push(nsec3sha1.deployed().then((digest) => instance.setNSEC3Digest(1, digest.address)));
      if(dev) {
        tasks.push(dummyalgorithm.deployed().then((algorithm) => instance.setAlgorithm(253, algorithm.address)));
        tasks.push(dummyalgorithm.deployed().then((algorithm) => instance.setAlgorithm(254, algorithm.address)));
        tasks.push(dummydigest.deployed().then((digest) => instance.setDigest(253, digest.address)));
      }
      return Promise.all(tasks);
    }));
};
