var dns = require("../../lib/dns.js");
contract('DNSSEC', function(accounts) {
    describe('encodeTypeBitMap', function(){
        it('encodes single type', function(){
            assert.equal(
                dns.encodeTypeBitMap([16]).toString('hex'), '0003000001'
            );
        });

        it('adds up types in the same bigmap segment', function(){
            assert.equal(
                dns.encodeTypeBitMap([16, 48]).toString('hex'), '000700000100000001'
            );
        });

        it('encodes across multiple windows', function(){
            assert.equal(
                dns.encodeTypeBitMap([256 + 16, 256 + 48]).toString('hex'), '010700000100000001'
            );
        });
    })
})