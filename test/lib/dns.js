var dns = require("../../lib/dns.js");
contract('DNSSEC', function(accounts) {
    describe('encodeTypeBitMap', function(){
        let buffer, off, result;

        beforeEach(async function(){
            buffer = new Buffer(10);
            off = 0;
        })

        it('encodes single type', function(){
            result = dns.encodeTypeBitMap(buffer, off, [16]);
            assert.equal(result, 5);
            assert.equal(buffer.toString('hex'), '00030000800000000000');
        });

        it('encodes with offset', function(){
            off = 1;
            result = dns.encodeTypeBitMap(buffer, off, [16]);
            assert.equal(result, 5);
            assert.equal(buffer.toString('hex'), '00000300008000000000');
        });

        it('adds up types in the same bigmap segment', function(){
            result = dns.encodeTypeBitMap(buffer, off, [16, 17]);
            assert.equal(result, 5);
            assert.equal(buffer.toString('hex'), '00030000c00000000000');
        });

        it('encodes across multiple windows', function(){
            result = dns.encodeTypeBitMap(buffer, off, [256 + 16, 256 + 17]);
            assert.equal(result, 5);
            assert.equal(buffer.toString('hex'), '01030000c00000000000');
        });
    })
})
