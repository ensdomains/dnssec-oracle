const RSASHA1Algorithm = artifacts.require("./algorithms/RSASHA1Algorithm");
const RSASHA256Algorithm = artifacts.require("./algorithms/RSASHA256Algorithm");
const SHA1Digest = artifacts.require("./digests/SHA1Digest");
const SHA256Digest = artifacts.require("./digests/SHA256Digest");
const SHA1NSEC3Digest = artifacts.require("./nsec3digests/SHA1NSEC3Digest");
const DNSSEC = artifacts.require("./DNSSECImpl");
const DummyAlgorithm = artifacts.require("./algorithms/DummyAlgorithm");
const DummyDigest = artifacts.require("./digests/DummyDigest");

const dns = require("../lib/dns.js");

module.exports = function(deployer, network) {
    return deployer.then(async () => {
        let dev = (network == "test" || network == "local");
        // From http://data.iana.org/root-anchors/root-anchors.xml
        let anchors = dns.anchors;

        if (dev) {
            anchors.push(dns.dummyAnchor);
        }

        await deployer.deploy(DNSSEC, dns.encodeAnchors(anchors));

        await deployer.deploy([[RSASHA256Algorithm], [RSASHA1Algorithm], [SHA256Digest], [SHA1Digest], [SHA1NSEC3Digest]]);

        if (dev) {
            await deployer.deploy([[DummyAlgorithm], [DummyDigest]])
        }

        let tasks = [];

        const dnssec = await DNSSEC.deployed();

        const rsasha1 = await RSASHA1Algorithm.deployed();
        tasks.push(dnssec.setAlgorithm(5, rsasha1.address));
        tasks.push(dnssec.setAlgorithm(7, rsasha1.address));

        const rsasha256 = await RSASHA256Algorithm.deployed();
        tasks.push(dnssec.setAlgorithm(8, rsasha256.address));

        const sha1 = await SHA1Digest.deployed();
        tasks.push(dnssec.setDigest(1, sha1.address));

        const sha256 = await SHA256Digest.deployed();
        tasks.push(dnssec.setDigest(2, sha256.address));

        const nsec3sha1 = await SHA1NSEC3Digest.deployed();
        tasks.push(dnssec.setNSEC3Digest(1, nsec3sha1.address));

        if (dev) {
            const dummyalgorithm = await DummyAlgorithm.deployed();
            tasks.push(dnssec.setAlgorithm(253, dummyalgorithm.address));
            tasks.push(dnssec.setAlgorithm(254, dummyalgorithm.address));

            const dummydigest = await DummyDigest.deployed();
            tasks.push(dnssec.setDigest(253, dummydigest.address));
        }

        await Promise.all(tasks)
    });
};
