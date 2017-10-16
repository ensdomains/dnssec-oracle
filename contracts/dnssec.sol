pragma solidity ^0.4.13;

import "./rsaverify.sol";
import "./bytesutils.sol";
import "./rrutils.sol";

/*
 * TODO: Support for wildcards
 * TODO: Support for NSEC records
 * NOTE: Doesn't enforce expiration for records, to allow 'playing forward'
 * TODO: Enforce expiration for non-DNSKEY records
 */
contract DNSSEC {
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

    event RRSetUpdated(bytes name);

    function DNSSEC() public {
        // From http://data.iana.org/root-anchors/root-anchors.xml
        rrsets[keccak256(hex"00")][DNSTYPE_DS][DNSCLASS_IN] = RRSet(
            // Inception
            0,
            // Expiration
            0xFFFFFFFF,
            // Inserted
            uint64(now),
            // RRs
            hex"0000430001FFFFFFFF00244A5C080249AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB50000430001FFFFFFFF00244F660802E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        );
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

        var rrset = rrsets[keccak256(name)][typecovered][class];
        rrset.inception = inception;
        rrset.expiration = expiration;
        rrset.inserted = uint64(now);

        // o  The validator's notion of the current time MUST be less than or
        //    equal to the time listed in the RRSIG RR's Expiration field.
        // We permit submitting expired DNSKEYs in order to 'play forward' the
        // signatures.
        assert(expiration > now || typecovered == DNSTYPE_DNSKEY);

        // o  The validator's notion of the current time MUST be greater than or
        //    equal to the time listed in the RRSIG RR's Inception field.
        assert(inception < now);

        if(rrset.rrs.length > 0) {
            // To replace an existing rrset, the signature must be newer
            assert(inception > rrset.inception);
        }

        insertRRs(rrset, data, name, class, typecovered);
        RRSetUpdated(name);
    }

    function insertRRs(RRSet storage rrset, BytesUtils.slice memory data, bytes rrsigname, uint16 rrsetclass, uint16 typecovered) internal {
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

        rrset.rrs = data.toBytes();
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

        if(algorithm == ALGORITHM_RSASHA256) {
            if(verifyRSASHA256(keyrdata, data, sig)) return true;
        }
        return false;
    }

    function computeKeytag(BytesUtils.slice memory data) internal pure returns(uint16) {
        uint ac;
        for(uint i = 0; i < data.len; i += 2) {
            ac += data.uint16At(i);
        }
        ac += (ac >> 16) & 0xFFFF;
        return uint16(ac & 0xFFFF);
    }

    function verifyRSASHA256(BytesUtils.slice memory dnskey, bytes data, bytes sig) internal view returns (bool) {
        bytes memory exponent;
        bytes memory modulus;

        var exponentLen = uint16(dnskey.uint8At(4));
        if(exponentLen != 0) {
            exponent = dnskey.toBytes(5, exponentLen + 5);
            modulus = dnskey.toBytes(exponentLen + 5, dnskey.len);
        } else {
            exponentLen = dnskey.uint16At(5);
            exponent = dnskey.toBytes(7, exponentLen + 7);
            modulus = dnskey.toBytes(exponentLen + 7, dnskey.len);
        }

        bytes memory sigdata = new bytes(modulus.length);
        BytesUtils.slice memory sigdataslice;
        sigdataslice.fromBytes(sigdata);
        // Write 0x0001
        sigdataslice.writeBytes32(0, 0x0001 << 240);
        // Repeat 0xFF as many times as needed (2 byte 0x0001 + 20 byte prefix + 32 byte hash = 54)
        var padsize = modulus.length - 54;
        sigdataslice.fill(2, padsize, 0xff);
        // Write the prefix
        sigdataslice.writeBytes32(padsize + 2, 0x003031300d060960864801650304020105000420 << 96);
        // Write the hash
        sigdataslice.writeBytes32(padsize + 22, sha256(data));

        // Verify the signature
        return RSAVerify.rsaverify(sigdata, modulus, exponent, sig);
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
            if(digesttype == DIGEST_ALGORITHM_SHA256) {
                if(verifySHA256(keyname, keyrdata, dsrdata)) return true;
            }
        }
        return false;
    }

    function verifySHA256(BytesUtils.slice memory keyname, BytesUtils.slice memory keyrdata, BytesUtils.slice memory digest) internal view returns (bool) {
        bytes memory data = new bytes(keyname.len + keyrdata.len);
        BytesUtils.slice memory dataslice;
        dataslice.fromBytes(data);
        dataslice.memcpy(0, keyname, 0, keyname.len);
        dataslice.memcpy(keyname.len, keyrdata, 0, keyrdata.len);
        var hash = sha256(data);
        return hash == digest.bytes32At(4);
    }
}
