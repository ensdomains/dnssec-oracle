pragma solidity ^0.4.17;

import "./owned.sol";
import "./bytesutils.sol";
import "./rrutils.sol";
import "./algorithm.sol";
import "./digest.sol";

/*
 * TODO: Support for wildcards
 * TODO: Support for NSEC records
 * NOTE: Doesn't enforce expiration for records, to allow 'playing forward'
 * TODO: Enforce expiration for non-DNSKEY records
 */
contract DNSSEC is Owned {
    using BytesUtils for *;
    using RRUtils for *;

    uint16 constant DNSCLASS_IN = 1;

    uint16 constant DNSTYPE_DS = 43;
    uint16 constant DNSTYPE_RRSIG = 46;
    uint16 constant DNSTYPE_DNSKEY = 48;

    uint constant DS_KEY_TAG = 0;
    uint constant DS_ALGORITHM = 2;
    uint constant DS_DIGEST_TYPE = 3;
    uint constant DS_DIGEST = 4;

    uint constant RRSIG_TYPE = 0;
    uint constant RRSIG_ALGORITHM = 2;
    uint constant RRSIG_LABELS = 3;
    uint constant RRSIG_TTL = 4;
    uint constant RRSIG_EXPIRATION = 8;
    uint constant RRSIG_INCEPTION = 12;
    uint constant RRSIG_KEY_TAG = 16;
    uint constant RRSIG_SIGNER_NAME = 18;

    uint constant DNSKEY_FLAGS = 0;
    uint constant DNSKEY_PROTOCOL = 2;
    uint constant DNSKEY_ALGORITHM = 3;
    uint constant DNSKEY_PUBKEY = 4;

    uint constant DNSKEY_FLAG_ZONEKEY = 0x100;

    uint8 constant ALGORITHM_RSASHA256 = 8;

    uint8 constant DIGEST_ALGORITHM_SHA256 = 2;

    struct RRSet {
        uint32 inception;
        uint32 expiration;
        uint64 inserted;
        bytes rrs;
    }

    // (name, type, class) => RRSet
    mapping(bytes32=>mapping(uint16=>mapping(uint16=>RRSet))) rrsets;

    mapping(uint8=>Algorithm) public algorithms;
    mapping(uint8=>Digest) public digests;

    event AlgorithmUpdated(uint8 id, address addr);
    event DigestUpdated(uint8 id, address addr);
    event RRSetUpdated(bytes name);

    function DNSSEC(bytes anchors) public {
        rrsets[keccak256(hex"00")][DNSTYPE_DS][DNSCLASS_IN] = RRSet(
            // Inception
            0,
            // Expiration
            0xFFFFFFFF,
            // Inserted
            uint64(now),
            // RRs
            anchors
            //hex"0000430001FFFFFFFF00244A5C080249AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB50000430001FFFFFFFF00244F660802E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        );
    }

    function setAlgorithm(uint8 id, Algorithm algo) public owner_only {
        algorithms[id] = algo;
        AlgorithmUpdated(id, algo);
    }

    function setDigest(uint8 id, Digest digest) public owner_only {
        digests[id] = digest;
        DigestUpdated(id, digest);
    }

    function rrset(uint16 class, uint16 dnstype, bytes name) public constant returns(uint32 inception, uint32 expiration, uint64 inserted, bytes rrs) {
        var result = rrsets[keccak256(name)][dnstype][class];
        return (result.inception, result.expiration, result.inserted, result.rrs);
    }

    function submitRRSet(uint16 class, bytes name, bytes input, bytes sig) public {
        BytesUtils.slice memory data;
        data.fromBytes(input);

        var inception = data.uint32At(RRSIG_INCEPTION);
        var expiration = data.uint32At(RRSIG_EXPIRATION);
        var typecovered = data.uint16At(RRSIG_TYPE);

        // Validate the signature
        verifySignature(class, data, input, sig);

        var set = rrsets[keccak256(name)][typecovered][class];
        set.inception = inception;
        set.expiration = expiration;
        set.inserted = uint64(now);

        // o  The validator's notion of the current time MUST be less than or
        //    equal to the time listed in the RRSIG RR's Expiration field.
        // We permit submitting expired DNSKEYs in order to 'play forward' the
        // signatures.
        assert(expiration > now || typecovered == DNSTYPE_DNSKEY);

        // o  The validator's notion of the current time MUST be greater than or
        //    equal to the time listed in the RRSIG RR's Inception field.
        assert(inception < now);

        if(set.rrs.length > 0) {
            // To replace an existing rrset, the signature must be newer
            assert(inception > set.inception);
        }

        insertRRs(set, data, name, class, typecovered);
        RRSetUpdated(name);
    }

    function insertRRs(RRSet storage set, BytesUtils.slice memory data, bytes rrsigname, uint16 rrsetclass, uint16 typecovered) internal {
        // Iterate over all the RRs
        BytesUtils.slice memory name;
        BytesUtils.slice memory rdata;
        for(var (dnstype, class, ttl) = data.nextRR(name, rdata); dnstype != 0; (dnstype, class, ttl) = data.nextRR(name, rdata)) {
            // o  The RRSIG RR and the RRset MUST have the same owner name and the
            //    same class.
            require(class == rrsetclass && name.keccak() == keccak256(rrsigname));

            // o  The RRSIG RR's Type Covered field MUST equal the RRset's type.
            require(dnstype == typecovered);

            // o  The RRSIG RR's Signer's Name field MUST be the name of the zone
            //    that contains the RRset.

            // o  The number of labels in the RRset owner name MUST be greater than
            //    or equal to the value in the RRSIG RR's Labels field.
        }

        set.rrs = data.toBytes();
    }

    function verifySignature(uint16 class, BytesUtils.slice memory rdata, bytes data, bytes sig) internal constant {
        // Extract signer name, algorithm, and key tag
        BytesUtils.slice memory signerName;
        rdata.dnsNameAt(RRSIG_SIGNER_NAME, signerName);
        var algorithm = rdata.uint8At(RRSIG_ALGORITHM);
        var keytag = rdata.uint16At(RRSIG_KEY_TAG);

        // Update rdata to point at the first RR
        rdata.s(18 + signerName.len, rdata.len);

        // Look for a matching key and verify the signature with it
        var keys = rrsets[signerName.keccak()][DNSTYPE_DNSKEY][class];
        BytesUtils.slice memory keydata;
        keydata.fromBytes(keys.rrs);

        BytesUtils.slice memory keyname;
        BytesUtils.slice memory keyrdata;
        for(var (dnstype,,) = keydata.nextRR(keyname, keyrdata); dnstype != 0; (dnstype,,) = keydata.nextRR(keyname, keyrdata)) {
            if(verifySignatureWithKey(keyrdata, algorithm, keytag, data, sig)) return;
        }

        // Perhaps it's self-signed and verified by a DS record?
        for((dnstype,,) = rdata.nextRR(keyname, keyrdata); dnstype != 0; (dnstype,,) = rdata.nextRR(keyname, keyrdata)) {
            if(dnstype != DNSTYPE_DNSKEY) break;
            if(verifySignatureWithKey(keyrdata, algorithm, keytag, data, sig)) {
                // It's self-signed - look for a DS record to verify it.
                if(verifyKeyWithDS(class, keyname, keyrdata, keytag, algorithm)) return;
                // If we found a valid signature but no valid DS, no use checking other records too.
                break;
            }
        }

        // No valid keys found
        revert();
    }

    function verifySignatureWithKey(BytesUtils.slice memory keyrdata, uint8 algorithm, uint16 keytag, bytes data, bytes sig) internal view returns(bool) {
        require(algorithms[algorithm] != address(0));
        // TODO: Check key isn't expired, unless updating key itself

        // o The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
        //   match the owner name, algorithm, and key tag for some DNSKEY RR in
        //   the zone's apex DNSKEY RRset.
        if(keyrdata.uint8At(DNSKEY_PROTOCOL) != 3) return false;
        if(keyrdata.uint8At(DNSKEY_ALGORITHM) != algorithm) return false;
        var computedkeytag = computeKeytag(keyrdata);        if(computedkeytag != keytag) return false;

        // o The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
        //   RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
        //   set.
        if(keyrdata.uint16At(DNSKEY_FLAGS) & DNSKEY_FLAG_ZONEKEY == 0) return false;

        return algorithms[algorithm].verify(keyrdata.toBytes(), data, sig);
    }

    function computeKeytag(BytesUtils.slice memory data) internal pure returns(uint16) {
        uint ac;
        for(uint i = 0; i < data.len; i += 2) {
            ac += data.uint16At(i);
        }
        ac += (ac >> 16) & 0xFFFF;
        return uint16(ac & 0xFFFF);
    }

    function verifyKeyWithDS(uint16 class, BytesUtils.slice memory keyname, BytesUtils.slice memory keyrdata, uint16 keytag, uint8 algorithm) internal constant returns (bool) {
        var dss = rrsets[keyname.keccak()][DNSTYPE_DS][class];

        BytesUtils.slice memory data;
        data.fromBytes(dss.rrs);

        BytesUtils.slice memory dsname;
        BytesUtils.slice memory dsrdata;
        for(var (dnstype,,) = data.nextRR(dsname, dsrdata); dnstype != 0; (dnstype,,) = data.nextRR(dsname, dsrdata)) {
            if(dsrdata.uint16At(DS_KEY_TAG) != keytag) continue;
            if(dsrdata.uint8At(DS_ALGORITHM) != algorithm) continue;

            var digesttype = dsrdata.uint8At(DS_DIGEST_TYPE);
            if(verifyDSHash(digesttype, keyname, keyrdata, dsrdata)) return true;
        }
        return false;
    }

    function verifyDSHash(uint8 digesttype, BytesUtils.slice memory keyname, BytesUtils.slice memory keyrdata, BytesUtils.slice memory digest) internal view returns (bool) {
        require(digests[digesttype] != address(0));

        bytes memory data = new bytes(keyname.len + keyrdata.len);
        BytesUtils.slice memory dataslice;
        dataslice.fromBytes(data);
        dataslice.memcpy(0, keyname, 0, keyname.len);
        dataslice.memcpy(keyname.len, keyrdata, 0, keyrdata.len);
        return digests[digesttype].verify(dataslice.toBytes(), digest.toBytes(4, 36));
    }
}
