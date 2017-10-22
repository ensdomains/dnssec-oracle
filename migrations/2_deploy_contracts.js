var rsasha256 = artifacts.require("./RSASHA256Algorithm.sol");
var sha256 = artifacts.require("./SHA256Digest.sol");
var dnssec = artifacts.require("./DNSSEC.sol");
var dummyalgorithm = artifacts.require("./DummyAlgorithm.sol");
var dummydigest = artifacts.require("./DummyDigest.sol");

var dns = require("../lib/dns.js");

function encodeAnchors(anchors) {
  var buf = new Buffer(4096);
  var off = 0;
  for(var anchor of anchors) {
    off = dns.encodeDS(buf, off, anchor);
  }
  return "0x" + buf.toString("hex", 0, off);
}

module.exports = function(deployer, network) {
  var dev = network == "development";
  // From http://data.iana.org/root-anchors/root-anchors.xml
  var anchors = [
    {
      name: ".",
      type: dns.TYPE_DS,
      klass: dns.CLASS_INET,
      ttl: 3600,
      keytag: 19036,
      algorithm: 8,
      digestType: 2,
      digest: new Buffer("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5", "hex")
    },
    {
      name: ".",
      type: dns.TYPE_DS,
      klass: dns.CLASS_INET,
      ttl: 3600,
      keytag: 20326,
      algorithm: 8,
      digestType: 2,
      digest: new Buffer("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", "hex")
    },
  ];
  if(dev) {
    anchors.push({
      name: ".",
      type: dns.TYPE_DS,
      klass: dns.CLASS_INET,
      ttl: 3600,
      keytag: 5647, // Empty body, flags == 0x0101, algorithm = 253, body = 0x1111
      algorithm: 253,
      digestType: 253,
      digest: new Buffer("", "hex")
    });
  }
  return deployer.deploy(dnssec, encodeAnchors(anchors))
    .then(() => deployer.deploy([[rsasha256], [sha256]]))
    .then(() => dev?deployer.deploy([[dummyalgorithm], [dummydigest]]):null)
    .then(() => dnssec.deployed().then(function(instance) {
      tasks = [];
      tasks.push(rsasha256.deployed().then((algorithm) => instance.setAlgorithm(8, algorithm.address)));
      tasks.push(sha256.deployed().then((digest) => instance.setDigest(2, digest.address)));
      if(dev) {
        tasks.push(dummyalgorithm.deployed().then((algorithm) => instance.setAlgorithm(253, algorithm.address)));
        tasks.push(dummyalgorithm.deployed().then((algorithm) => instance.setAlgorithm(254, algorithm.address)));
        tasks.push(dummydigest.deployed().then((digest) => instance.setDigest(253, digest.address)));
      }
      return Promise.all(tasks);
    }));
};
