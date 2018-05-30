var exports = module.exports = {};

const TYPE_TXT = exports.TYPE_TXT = 16;
const TYPE_NSEC = exports.TYPE_NSEC = 47;
const TYPE_DNSKEY = exports.TYPE_DNSKEY = 48;
const TYPE_DS = exports.TYPE_DS = 43;
const TYPE_NSEC3 = exports.TYPE_NSEC3 = 50;
const CLASS_INET = exports.CLASS_INET = 1;

var encodeName = exports.encodeName = function(buf, off, name) {
  if(!name.endsWith(".")) name = name + ".";
  if(name == ".") {
    buf.writeUInt8(0, off++);
    return off;
  }

  for(var part of name.split(".")) {
    buf.writeUInt8(part.length, off++);
    buf.write(part, off)
    off += part.length;
  }
  return off;
}

var hexEncodeName = exports.hexEncodeName = function(name) {
  var buf = new Buffer(name.length + 1);
  var off = encodeName(buf, 0, name);
  return "0x" + buf.toString("hex", 0, off);
}

var encodeRRHeader = exports.encodeRRHeader = function(buf, off, header) {
  off = encodeName(buf, off, header.name);
  buf.writeUInt16BE(header.type, off); off += 2;
  buf.writeUInt16BE(header.klass, off); off += 2;
  buf.writeUInt32BE(header.ttl, off); off += 4;
  return off;
}

var encodeTXT = exports.encodeTXT = function(buf, off, rec) {
  rec.type = TYPE_TXT;
  off = encodeRRHeader(buf, off, rec);
  var totalLen = rec.text.map((x) => x.length + 1).reduce((a, b) => a + b);
  buf.writeUInt16BE(totalLen, off); off += 2;
  for(var part of rec.text) {
    buf.writeUInt8(part.length, off); off += 1;
    buf.write(part, off); off += part.length;
  }
  return off;
}

var encodeNSEC = exports.encodeNSEC = function(buf, off, rec) {
  rec.type = TYPE_NSEC;
  off = encodeRRHeader(buf, off, rec);
  var lengthPointer = off;
  off += 2;
  off = encodeName(buf, off, rec.next);
  off += encodeTypeBitMap(buf, off, rec.rrtypes);
  var rd_length = off - lengthPointer - 2;
  buf.writeUInt16BE(rd_length, lengthPointer);
  return off;
}

var encodeNSEC3 = exports.encodeNSEC3 = function(buf, off, rec) {
  rec.type = TYPE_NSEC3;
  off = encodeRRHeader(buf, off, rec);
  var lengthPointer = off;
  off += 2;
  buf.writeUInt8(rec.algorithm, off); off += 1;
  buf.writeUInt8(rec.flags, off); off += 1;
  buf.writeUInt16BE(rec.iterations, off); off += 2;
  buf.writeUInt8(rec.salt.length, off); off += 1;
  rec.salt.copy(buf, off); off += rec.salt.length;
  buf.writeUInt8(rec.nextDomain.length, off); off += 1;
  rec.nextDomain.copy(buf, off); off += rec.nextDomain.length;
  off += encodeTypeBitMap(buf, off, rec.rrtypes);
  var rd_length = off - lengthPointer - 2;
  buf.writeUInt16BE(rd_length, lengthPointer);
  return off;
}

// https://tools.ietf.org/html/rfc4034#section-4.1.2
var encodeTypeBitMap = exports.encodeTypeBitMap = function(buffer, off, types){
  let result = getTypeBitMap(types);
  result.copy(buffer, off);
  return result.length;
}

var getTypeBitMap = function(types){
  var window_size = 256;
  var byte_size = 8;
  var bitmap = {};
  var bitmap_length = 32;
  types.forEach(function(type){
    var window_number = parseInt(type / window_size);
    var window_type = type % window_size;
    var byte_position = parseInt(window_type / byte_size) + 1;
    if(!bitmap[window_number]){
      bitmap[window_number] = {
        buffer:new Buffer(bitmap_length),
        watermark: 1,
        window_number: window_number
      }
    }
    if(bitmap[window_number].watermark < byte_position){
      bitmap[window_number].watermark = byte_position;
    }
    set_bit(bitmap[window_number].buffer, window_type);
  })
  var array = Object.entries(bitmap).map(([key, w])=>{
    var numbers = Buffer.from([w.window_number, w.watermark]);
    return Buffer.concat([numbers, w.buffer.slice(0,w.watermark) ]);
  });
  return Buffer.concat(array);
}

var set_bit = function(bitmap, offset){
  return bitmap[parseInt(offset / 8)] |= 256 >> (offset % 8) + 1
}

var encodeDNSKEY = exports.encodeDNSKEY = function(buf, off, rec) {
  rec.type = TYPE_DNSKEY;
  off = encodeRRHeader(buf, off, rec);
  buf.writeUInt16BE(rec.pubkey.length + 4, off); off += 2;
  buf.writeUInt16BE(rec.flags, off); off += 2;
  buf.writeUInt8(rec.protocol, off); off += 1;
  buf.writeUInt8(rec.algorithm, off); off += 1;
  rec.pubkey.copy(buf, off); off += rec.pubkey.length;
  return off;
}

var encodeDS = exports.encodeDS = function(buf, off, rec) {
  rec.type = TYPE_DS;
  off = encodeRRHeader(buf, off, rec);
  buf.writeUInt16BE(rec.digest.length + 4, off); off += 2;
  buf.writeUInt16BE(rec.keytag, off); off += 2;
  buf.writeUInt8(rec.algorithm, off); off += 1;
  buf.writeUInt8(rec.digestType, off); off += 1;
  rec.digest.copy(buf, off); off += rec.digest.length;
  return off;
}

const RR_TYPES = {}
RR_TYPES[TYPE_TXT] = encodeTXT;
RR_TYPES[TYPE_DS] = encodeDS;
RR_TYPES[TYPE_DNSKEY] = encodeDNSKEY;
RR_TYPES[TYPE_NSEC] = encodeNSEC;
RR_TYPES[TYPE_NSEC3] = encodeNSEC3;

var encodeRRs = exports.encodeRRs = function(buf, off, rrs) {
  for(var rr of rrs) {
    off = RR_TYPES[rr.type](buf, off, rr);
  }
  return off;
}

var hexEncodeRRs = exports.hexEncodeRRs = function(rrs) {
  var buf = new Buffer(4096);
  var off = encodeRRs(buf, 0, rrs);
  return "0x" + buf.toString("hex", 0, off);
}

var encodeSignedSet = exports.encodeSignedSet = function(buf, off, rec) {
  buf.writeUInt16BE(rec.typeCovered, off); off += 2;
  buf.writeUInt8(rec.algorithm, off); off += 1;
  buf.writeUInt8(rec.labels, off); off += 1;
  buf.writeUInt32BE(rec.originalTTL, off); off += 4;
  buf.writeUInt32BE(rec.expiration, off); off += 4;
  buf.writeUInt32BE(rec.inception, off); off += 4;
  buf.writeUInt16BE(rec.keytag, off); off += 2;
  off = encodeName(buf, off, rec.signerName);
  off = encodeRRs(buf, off, rec.rrs);
  return off;
}

var hexEncodeSignedSet = exports.hexEncodeSignedSet = function(rec) {
  var buf = new Buffer(4096);
  var off = encodeSignedSet(buf, 0, rec);
  return "0x" + buf.toString("hex", 0, off);
}
