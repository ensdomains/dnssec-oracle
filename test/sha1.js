var SHA1Test = artifacts.require("./SHA1Test");

var vectors = require('hash-test-vectors')

contract('SHA1', function(accounts) {
    var totalGas = 0;
    var instance = SHA1Test.new();
    vectors.forEach(function(v, i) {
        if(v.input.length > 4096) return; // Really long test vectors make us OOM
        it("sha1.sol against test vector " + i, async function() {
            var input = "0x" + new Buffer(v.input, 'base64').toString('hex');
            assert.equal(await (await instance).sha1(input), "0x" + v.sha1, "input " + input + " should hash to 0x" + v.sha1);
            /*var gas = await (await instance).sha1.estimateGas(input);
            totalGas += gas;
            console.log("Cumulative gas: " + totalGas);*/
        });
    });
});
