pragma solidity ^0.4.23;

import "./Owned.sol";
import "./Buffer.sol";
import "./BytesUtils.sol";
import "./RRUtils.sol";
import "./Algorithm.sol";
import "./Digest.sol";
import "./NSEC3Digest.sol";

/*
 * @dev An oracle contract that verifies and stores DNSSEC-validated DNS records.
 *
 * TODO: Support for NSEC records
 * TODO: Support for NSEC3 records
 */
contract DNSSEC is Owned {
    using Buffer for Buffer.buffer;
    using BytesUtils for bytes;
    using RRUtils for *;

    uint16 constant DNSCLASS_IN = 1;

    uint16 constant DNSTYPE_DS = 43;
    uint16 constant DNSTYPE_RRSIG = 46;
    uint16 constant DNSTYPE_NSEC = 47;
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
        uint64 inserted;
        bytes20 hash;
    }

    // (name, type) => RRSet
    mapping (bytes32 => mapping(uint16 => RRSet)) rrsets;

    bytes public anchors;

    mapping (uint8 => Algorithm) public algorithms;
    mapping (uint8 => Digest) public digests;
    mapping (uint8 => NSEC3Digest) public nsec3Digests;

    event AlgorithmUpdated(uint8 id, address addr);
    event DigestUpdated(uint8 id, address addr);
    event NSEC3DigestUpdated(uint8 id, address addr);
    event RRSetUpdated(bytes name, bytes rrset);

    /**
     * @dev Constructor.
     * @param _anchors The binary format RR entries for the root DS records.
     */
    constructor(bytes _anchors) public {
        // Insert the 'trust anchors' - the key hashes that start the chain
        // of trust for all other records.
        anchors = _anchors;
        rrsets[keccak256(hex"00")][DNSTYPE_DS] = RRSet({
            inception: uint32(0),
            inserted: uint64(now),
            hash: bytes20(keccak256(anchors))
        });
        emit RRSetUpdated(hex"00", anchors);
    }

    /**
     * @dev Sets the contract address for a signature verification algorithm.
     *      Callable only by the owner.
     * @param id The algorithm ID
     * @param algo The address of the algorithm contract.
     */
    function setAlgorithm(uint8 id, Algorithm algo) public owner_only {
        algorithms[id] = algo;
        emit AlgorithmUpdated(id, algo);
    }

    /**
     * @dev Sets the contract address for a digest verification algorithm.
     *      Callable only by the owner.
     * @param id The digest ID
     * @param digest The address of the digest contract.
     */
    function setDigest(uint8 id, Digest digest) public owner_only {
        digests[id] = digest;
        emit DigestUpdated(id, digest);
    }

    /**
     * @dev Sets the contract address for an NSEC3 digest algorithm.
     *      Callable only by the owner.
     * @param id The digest ID
     * @param digest The address of the digest contract.
     */
    function setNSEC3Digest(uint8 id, NSEC3Digest digest) public owner_only {
        nsec3Digests[id] = digest;
        emit NSEC3DigestUpdated(id, digest);
    }

    /**
     * @dev Submits a signed set of RRs to the oracle.
     *
     * RRSETs are only accepted if they are signed with a key that is already
     * trusted, or if they are self-signed, and the signing key is identified by
     * a DS record that is already trusted.
     *
     * @param name The name of the RRSET, in DNS label-sequence format.
     * @param input The signed RR set. This is in the format described in section
     *        5.3.2 of RFC4035: The RRDATA section from the RRSIG without the signature
     *        data, followed by a series of canonicalised RR records that the signature
     *        applies to.
     * @param sig The signature data from the RRSIG record.
     */
    function submitRRSet(bytes memory name, bytes memory input, bytes memory sig, bytes memory proof) public {
        uint32 inception = input.readUint32(RRSIG_INCEPTION);
        uint32 expiration = input.readUint32(RRSIG_EXPIRATION);
        uint16 typecovered = input.readUint16(RRSIG_TYPE);
        uint8 labels = input.readUint8(RRSIG_LABELS);

        // Validate the signature
        uint offset = verifySignature(name, input, sig, proof);

        bytes memory rrs = input.substring(offset, input.length - offset);

        RRSet storage set = rrsets[keccak256(name)][typecovered];
        if (set.inserted > 0) {
            // To replace an existing rrset, the signature must be at least as new
            require(inception >= set.inception);
        }
        if(set.hash == keccak256(rrs)) {
          // Already inserted!
          return;
        }

        // TODO: Check inception and expiration using mod2^32 math

        // o  The validator's notion of the current time MUST be less than or
        //    equal to the time listed in the RRSIG RR's Expiration field.
        require(expiration > now);

        // o  The validator's notion of the current time MUST be greater than or
        //    equal to the time listed in the RRSIG RR's Inception field.
        require(inception < now);

        validateRRs(rrs, name, typecovered, labels);
        rrsets[keccak256(name)][typecovered] = RRSet({
            inception: inception,
            inserted: uint64(now),
            hash: bytes20(keccak256(rrs))
        });
        emit RRSetUpdated(name, rrs);
    }

    /**
     * @dev Deletes an RR from the oracle.
     *
     * @param nsecname which contains the next authorative record
     * @param deletetype The DNS record type to delete.
     * @param deletename which you want to delete
     *
     */
    function deleteRRSet(uint16 deletetype, bytes deletename, bytes nsecname, bytes proof) public {
        require(rrsets[keccak256(nsecname)][DNSTYPE_NSEC].hash == bytes20(keccak256(proof)));

        int compareResult = deletename.compareNames(nsecname);

        for(RRUtils.RRIterator memory iter = proof.iterateRRs(0); !iter.done(); iter.next()) {
            uint rdataOffset = iter.rdataOffset;
            uint nextNameLength = iter.data.nameLength(rdataOffset);
            uint rDataLength = iter.nextOffset - iter.rdataOffset;

            // We assume that there is always typed bitmap after the next domain name
            require(rDataLength > nextNameLength);
            assert(iter.dnstype == DNSTYPE_NSEC);
            if(compareResult == 0){
                require(!iter.data.checkTypeBitmap(rdataOffset + nextNameLength, deletetype));
            }else if(compareResult > 0){
                bytes memory nextName = iter.data.substring(rdataOffset,nextNameLength);
                require(deletename.compareNames(nextName) < 0);
            }else{
                // This happens only when the name to delete come before the NSEC record
                revert();
            }
            delete rrsets[keccak256(deletename)][deletetype];
            return;
        }
        // This should never reach.
        revert();
    }

    /**
     * @dev Returns the RRs (if any) associated with the provided type and name.
     * @param dnstype The DNS record type to query.
     * @param name The name to query, in DNS label-sequence format.
     * @return inception The unix timestamp at which the signature for this RRSET was created.
     * @return inserted The unix timestamp at which this RRSET was inserted into the oracle.
     * @return rrs The wire-format RR records.
     */
    function rrdata(uint16 dnstype, bytes memory name) public view returns (uint32, uint64, bytes20) {
        RRSet storage result = rrsets[keccak256(name)][dnstype];
        return (result.inception, result.inserted, result.hash);
    }

    /**
     * @dev Validates a set of RRs.
     * @param data The RR data.
     * @param rrsigname The name assigned to the RRSIG record verifying this RRSET.
     * @param typecovered The type covered by the RRSIG record.
     * @param labels The number of labels specified by the RRSIG record.
     */
    function validateRRs(bytes memory data, bytes memory rrsigname, uint16 typecovered, uint8 labels) internal pure {
        // Iterate over all the RRs
        for(RRUtils.RRIterator memory iter = data.iterateRRs(0); !iter.done(); iter.next()) {
            // o  The RRSIG RR and the RRset MUST have the same owner name and the
            //    same class.
            // o  The number of labels in the RRset owner name MUST be greater than
            //    or equal to the value in the RRSIG RR's Labels field.
            require(iter.class == DNSCLASS_IN);
            checkName(rrsigname, data, iter.offset, labels);

            // o  The RRSIG RR's Type Covered field MUST equal the RRset's type.
            require(iter.dnstype == typecovered);
        }
    }

    function checkName(bytes memory rrsigname, bytes memory data, uint offset, uint8 labels) internal pure {
        uint nameLabels = data.labelCount(offset);
        uint nameLength = data.nameLength(offset);
        if (nameLabels == labels) {
            require(nameLength == rrsigname.length);
            require(data.equals(0, rrsigname));
        } else if (nameLabels == labels + 1) {
            // It's a wildcard domain; make sure it ends with rrsigname and starts with *.
            require(data.readUint16(0) == 0x012A);
            require(data.equals(2, rrsigname, rrsigname.length - nameLength + 2, nameLength - 2));
        } else {
            // Anything else is invalid
            revert();
        }
    }

    /**
     * @dev Performs signature verification.
     *
     * Throws or reverts if unable to verify the record.
     *
     * @param name The name of the RRSIG record, in DNS label-sequence format.
     * @param data The original data to verify.
     * @param sig The signature data.
     */
    function verifySignature(bytes name, bytes memory data, bytes memory sig, bytes memory proof) internal constant returns(uint offset) {
        uint signerNameLength = data.nameLength(RRSIG_SIGNER_NAME);

        // o  The RRSIG RR's Signer's Name field MUST be the name of the zone
        //    that contains the RRset.
        require(signerNameLength <= name.length);
        require(data.equals(RRSIG_SIGNER_NAME, name, name.length - signerNameLength, signerNameLength));

        // Set the return offset to point at the first RR
        offset = 18 + signerNameLength;

        // Check the proof
        RRUtils.RRIterator memory iter = proof.iterateRRs(0);
        require(rrsets[data.keccak(RRSIG_SIGNER_NAME, signerNameLength)][iter.dnstype].hash == bytes20(keccak256(proof)));
        if(iter.dnstype == DNSTYPE_DS) {
            require(verifyWithDS(data, sig, offset, proof));
        } else if(iter.dnstype == DNSTYPE_DNSKEY) {
            require(verifyWithKnownKey(data, sig, proof));
        } else {
            revert("Unsupported proof record type");
        }
    }

    /**
     * @dev Attempts to verify a signed RRSET against an already known public key.
     * @param data The original data to verify.
     * @param sig The signature data.
     * @return True if the RRSET could be verified, false otherwise.
     */
    function verifyWithKnownKey(bytes memory data, bytes memory sig, bytes memory proof) internal constant returns(bool) {
        uint signerNameLength = data.nameLength(RRSIG_SIGNER_NAME);

        // Extract algorithm and keytag
        uint8 algorithm = data.readUint8(RRSIG_ALGORITHM);
        uint16 keytag = data.readUint16(RRSIG_KEY_TAG);

        for(RRUtils.RRIterator memory iter = proof.iterateRRs(0); !iter.done(); iter.next()) {
          // Check the DNSKEY's owner name matches the signer name on the RRSIG
          require(proof.nameLength(0) == signerNameLength);
          require(proof.equals(0, data, RRSIG_SIGNER_NAME, signerNameLength));
          if (verifySignatureWithKey(iter.rdata(), algorithm, keytag, data, sig)) return true;
        }

        return false;
    }

    /**
     * @dev Attempts to verify a signed RRSET against an already known public key.
     * @param data The original data to verify.
     * @param sig The signature data.
     * @param offset The offset from the start of the data to the first RR.
     * @return True if the RRSET could be verified, false otherwise.
     */
    function verifyWithDS(bytes memory data, bytes memory sig, uint offset, bytes memory proof) internal constant returns(bool) {
        // Extract algorithm and keytag
        uint8 algorithm = data.readUint8(RRSIG_ALGORITHM);
        uint16 keytag = data.readUint16(RRSIG_KEY_TAG);

        // Perhaps it's self-signed and verified by a DS record?
        for(RRUtils.RRIterator memory iter = data.iterateRRs(offset); !iter.done(); iter.next()) {
          if (iter.dnstype != DNSTYPE_DNSKEY) return false;

          bytes memory keyrdata = iter.rdata();
          if (verifySignatureWithKey(keyrdata, algorithm, keytag, data, sig)) {
              // It's self-signed - look for a DS record to verify it.
              if (verifyKeyWithDS(iter.name(), keyrdata, keytag, algorithm, proof)) return true;
              // If we found a valid signature but no valid DS, no use checking other records too.
              return false;
          }
        }

        return false;
    }

    /**
     * @dev Attempts to verify some data using a provided key and a signature.
     * @param keyrdata The RDATA section of the key to use.
     * @param algorithm The algorithm ID of the key and signature.
     * @param keytag The keytag from the signature.
     * @param data The data to verify.
     * @param sig The signature to use.
     * @return True iff the key verifies the signature.
     */
    function verifySignatureWithKey(bytes memory keyrdata, uint8 algorithm, uint16 keytag, bytes data, bytes sig) internal view returns (bool) {
        if (algorithms[algorithm] == address(0)) return false;
        // TODO: Check key isn't expired, unless updating key itself

        // o The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
        //   match the owner name, algorithm, and key tag for some DNSKEY RR in
        //   the zone's apex DNSKEY RRset.
        if (keyrdata.readUint8(DNSKEY_PROTOCOL) != 3) return false;
        if (keyrdata.readUint8(DNSKEY_ALGORITHM) != algorithm) return false;
        uint16 computedkeytag = computeKeytag(keyrdata);
        if (computedkeytag != keytag) return false;

        // o The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
        //   RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
        //   set.
        if (keyrdata.readUint16(DNSKEY_FLAGS) & DNSKEY_FLAG_ZONEKEY == 0) return false;

        return algorithms[algorithm].verify(keyrdata, data, sig);
    }

    /**
     * @dev Attempts to verify a key using DS records.
     * @param keyname The DNS name of the key, in DNS label-sequence format.
     * @param keyrdata The RDATA section of the key.
     * @param keytag The keytag of the key.
     * @param algorithm The algorithm ID of the key.
     * @return True if a DS record verifies this key.
     */
    function verifyKeyWithDS(bytes memory keyname, bytes memory keyrdata, uint16 keytag, uint8 algorithm, bytes memory data) internal view returns (bool) {
        for(RRUtils.RRIterator memory iter = data.iterateRRs(0); !iter.done(); iter.next()) {
            if(data.readUint16(iter.rdataOffset + DS_KEY_TAG) != keytag) continue;
            if(data.readUint8(iter.rdataOffset + DS_ALGORITHM) != algorithm) continue;

            uint8 digesttype = data.readUint8(iter.rdataOffset + DS_DIGEST_TYPE);
            Buffer.buffer memory buf;
            buf.init(keyname.length + keyrdata.length);
            buf.append(keyname);
            buf.append(keyrdata);
            if (verifyDSHash(digesttype, buf.buf, data.substring(iter.rdataOffset, iter.nextOffset - iter.rdataOffset))) return true;
        }
        return false;
    }

    /**
     * @dev Attempts to verify a DS record's hash value against some data.
     * @param digesttype The digest ID from the DS record.
     * @param data The data to digest.
     * @param digest The digest data to check against.
     * @return True iff the digest matches.
     */
    function verifyDSHash(uint8 digesttype, bytes data, bytes digest) internal view returns (bool) {
        if (digests[digesttype] == address(0)) return false;
        return digests[digesttype].verify(data, digest.substring(4, digest.length - 4));
    }

    /**
     * @dev Computes the keytag for a chunk of data.
     * @param data The data to compute a keytag for.
     * @return The computed key tag.
     */
    function computeKeytag(bytes memory data) internal pure returns (uint16) {
        uint ac;
        for (uint i = 0; i < data.length; i += 2) {
            ac += data.readUint16(i);
        }
        ac += (ac >> 16) & 0xFFFF;
        return uint16(ac & 0xFFFF);
    }
}
