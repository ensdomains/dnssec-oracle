const RSASHA1Algorithm = artifacts.require("./algorithms/RSASHA1Algorithm");
const RSASHA256Algorithm = artifacts.require("./algorithms/RSASHA256Algorithm");
const ECCAlgorithm = artifacts.require("./algorithms/ECCAlgorithm");
const SHA1Digest = artifacts.require("./digests/SHA1Digest");
const SHA256Digest = artifacts.require("./digests/SHA256Digest");
const SHA1NSEC3Digest = artifacts.require("./nsec3digests/SHA1NSEC3Digest");
const DNSSEC = artifacts.require("./DNSSECImpl");
const DummyAlgorithm = artifacts.require("./algorithms/DummyAlgorithm");
const DummyDigest = artifacts.require("./digests/DummyDigest");
const Curve = artifacts.require("@ensdomains/curvearithmetics/contracts/Curve");

const dns = require("../lib/dns.js");
const BN = require("bn.js");

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

        await deployer.deploy(
            Curve,
            [new BN("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)],
            [new BN("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)],
            [new BN("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16)],
            [new BN(1)],
            [new BN("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16), new BN("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)],
            [new BN("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)],
            [new BN("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)],
        );

        const curve = await Curve.deployed();
        await deployer.deploy(ECCAlgorithm, curve.address);
        const ecc = await ECCAlgorithm.deployed();

        tasks.push(dnssec.setAlgorithm(13, ecc.address));

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
