var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./dnssec.sol");

const test_rrsets = [
  // .	160065	IN	RRSIG	DNSKEY 8 0 172800 20171111000000 20171021000000 19036 . ItR1tbAbqjpJ6phdY2Wfoz7Ny56aOtXnU1lRRZuIzC2qWrzge8MEJYfRn+1kSuUZ7x2T74la12RYbBkUld79Ul7vS/Chs6w76WszUENQ9G+ImGhpyCqzUfaq/8wTGMmMF6MWlioHRHOhEnSebWq/ErxFhUOkwnuYZAeMKrTqppR/WygEBzlIFCXJTmyt4Pm7WuDTTC97DO/ope7ABJyN/YSU/tvenL4qI7jPCJlSjOo1lg3yF6VQk2DjMjBWo5yZFI/twoNZsTzMEzvbthjnKymwmZcxlFIiJayKMBVTihpWZxc8d2s4svFyT1UPu80r5mQEd5aKvZ4l88XzWVzwQw==
  // .	160065	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  // .	160065	IN	DNSKEY	256 3 8 AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+bP7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPyG6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1ylsr4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjveD1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2/PFENcoFERc=
  // .	160065	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  [".", "003008000002a3005a063d8059ea8e004a5c0000003000010002a30001080100030803010001c44865fc6c91d12530a823c2f5903b66d07bb10602f5face021aaa66ec68caa632b229775f9b3fb9f250b2ee2fc8d69ca02a71a55f6a5db2243e74820e73165e725bf17d74a3575c4148ed511c1ab3f21bafceac0f51054f291969b4ab1a6c366e542204d4e485fba5bff4ac18faedcfd1eea967f2c8c7d7296caf87f563747aa7f76bba211a94a6ac12318a03d2f6c3d8f3510bac5b133b7d0c7f4fc73fdf1ddbb23bde0f5765790e8c25a0b1e1ba4f5d8669a97992bc69fe4f6bf9df9d1c055005a952a119b8f11325c0c1e7a6f1c4d4e0bd69f8357b51ad756b5b4c7f44e5bbca64a4bc21ecd408820204849c0484f7971371380ba436fcf14435ca05111700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "22d475b5b01baa3a49ea985d63659fa33ecdcb9e9a3ad5e7535951459b88cc2daa5abce07bc3042587d19fed644ae519ef1d93ef895ad764586c191495defd525eef4bf0a1b3ac3be96b33504350f46f88986869c82ab351f6aaffcc1318c98c17a316962a074473a112749e6d6abf12bc458543a4c27b9864078c2ab4eaa6947f5b28040739481425c94e6cade0f9bb5ae0d34c2f7b0cefe8a5eec0049c8dfd8494fedbde9cbe2a23b8cf0899528cea35960df217a5509360e3323056a39c99148fedc28359b13ccc133bdbb618e72b29b099973194522225ac8a3015538a1a5667173c776b38b2f1724f550fbbcd2be6640477968abd9e25f3c5f3595cf043"],

  // xyz.	73758	IN	RRSIG	DS 8 1 86400 20171103180000 20171021170000 46809 . gZthgqDQUAVERPzCFsjrseci26fO+n825sAKzsPKnxTR6BnieSTUwENaMFYJlrxqu7nxq6lLHkvhbhqUDRzRBvHLLwQqI24PX8Ps/PaqNxgKYcFPBlQQ4TA9R59z0mqSbCWE/df92uaWF9rVhIhMxXyN//vUX/hXTQb0OoIHudZmbovt4SPWTNOnuy+tl2DLPnVEvEYlHtDQHK+gjvnuuGJIWcDELweMeeGjAcZMv9eG7l8BT78BSUrczuDP4WjtcCQLjQbMzalQrXpa+gzdthAnSKTtIr+d8fAmxLH9ovpcN61Smku9Br0AxLhyJzVZZLLZXHF71uVU7tMQqtGzuA==
  // xyz.	73758	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
  // xyz.	73758	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
  ["xyz.", "002b08010001518059fcaea059eb7d10b6d9000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "819b6182a0d050054444fcc216c8ebb1e722dba7cefa7f36e6c00acec3ca9f14d1e819e27924d4c0435a30560996bc6abbb9f1aba94b1e4be16e1a940d1cd106f1cb2f042a236e0f5fc3ecfcf6aa37180a61c14f065410e1303d479f73d26a926c2584fdd7fddae69617dad584884cc57c8dfffbd45ff8574d06f43a8207b9d6666e8bede123d64cd3a7bb2fad9760cb3e7544bc46251ed0d01cafa08ef9eeb8624859c0c42f078c79e1a301c64cbfd786ee5f014fbf01494adccee0cfe168ed70240b8d06cccda950ad7a5afa0cddb6102748a4ed22bf9df1f026c4b1fda2fa5c37ad529a4bbd06bd00c4b87227355964b2d95c717bd6e554eed310aad1b3b8"],

  // xyz.	1799	IN	RRSIG	DNSKEY 8 1 3600 20171115134239 20171016161557 3599 xyz. PvdrKEn3apGXBbiHSZprqgifM3pkjKNZuXKkZXCJ44pdJa8z8/ilRdxbT+WH+GRU+YNY2XpzY+N/k6Cqj0EuXXQyViF85ZZluo/yO8gZAk40AUVr+lLjfSUBYF8xRzJqa+YTCsFRxfKWPzCWZwbHfkXr9zY3U2ZibKg1QId97V652lH2Jo3cHybd5tYRfMW4AqdrUjvvjh2wLsWMCU343OeuQwRq7AkMKlaUY8zoscOpi4GGjny5dmfClOWvPmy6wAa6LTxRb1Y5tfviFNjnj7885r0oP8O7UiJCAfFfVn3s0Qsw49BhclQ3ufSp2YdFg97l77YOqGvqU3Va8r+Qtg==
  // xyz.	1799	IN	DNSKEY	256 3 8 AwEAAZ92VSgD71ay++8GbqtLF58yu5xuZEKwruVWjA1sZuf6fG68Ahkd/AnTcCs4PITlliSk4466CXSdcUnQm17SnrWOPHEf3gd+GVuMwwTwduGr8a8ZAYbO2/kr2ey9zaP36m2ssxlm0iRkDsLp9ThnLWG6ku2AkJuXS3du/KhcDt4h
  // xyz.	1799	IN	DNSKEY	256 3 8 AwEAAbVuIatF/tAzZhe2NFItxkYd7fstkOavgZV7PBRgYynKSS6aijV7Xv2cOsFGX0/cIZJy0Owh0b6/d+GaJ7ocmO990xVslrhCKf5cdprVw68ntHkudLkUMA4zZmYLST/CzW3o1C9rKSvetuKM8Ru0Tsbz8gOUt6YrggIw3IKntUDb
  // xyz.	1799	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  ["xyz.", "0030080100000e105a0c444f59e4db3d0e0f0378797a000378797a000030000100000e10008801000308030100019f76552803ef56b2fbef066eab4b179f32bb9c6e6442b0aee5568c0d6c66e7fa7c6ebc02191dfc09d3702b383c84e59624a4e38eba09749d7149d09b5ed29eb58e3c711fde077e195b8cc304f076e1abf1af190186cedbf92bd9ecbdcda3f7ea6dacb31966d224640ec2e9f538672d61ba92ed80909b974b776efca85c0ede210378797a000030000100000e1000880100030803010001b56e21ab45fed0336617b634522dc6461dedfb2d90e6af81957b3c14606329ca492e9a8a357b5efd9c3ac1465f4fdc219272d0ec21d1bebf77e19a27ba1c98ef7dd3156c96b84229fe5c769ad5c3af27b4792e74b914300e3366660b493fc2cd6de8d42f6b292bdeb6e28cf11bb44ec6f3f20394b7a62b820230dc82a7b540db0378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "3ef76b2849f76a919705b887499a6baa089f337a648ca359b972a4657089e38a5d25af33f3f8a545dc5b4fe587f86454f98358d97a7363e37f93a0aa8f412e5d743256217ce59665ba8ff23bc819024e3401456bfa52e37d2501605f3147326a6be6130ac151c5f2963f30966706c77e45ebf736375366626ca83540877ded5eb9da51f6268ddc1f26dde6d6117cc5b802a76b523bef8e1db02ec58c094df8dce7ae43046aec090c2a569463cce8b1c3a98b81868e7cb97667c294e5af3e6cbac006ba2d3c516f5639b5fbe214d8e78fbf3ce6bd283fc3bb52224201f15f567decd10b30e3d061725437b9f4a9d9874583dee5efb60ea86bea53755af2bf90b6"],

  // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20171117013437 20171017192030 51879 xyz. EA2jsO/Jl/w28fgishmhdW5s6oRSd+W28d17ojw5z2gmC6PydGb4v17IjuzXs78iC9ZSNuk9UoMrkS20bFSBOnvQKIAi8yMaNsuKBx3xlzxUC+vUUhusqw4GzNHaBgWMtR/ioJLjOwoEz0qJGTIvmU4dnCLYAu4s8uhA/sI7zNs=
  // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
  // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
  ["ethlab.xyz.", "002b080200000e105a0e3cad59e657fecaa70378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "100da3b0efc997fc36f1f822b219a1756e6cea845277e5b6f1dd7ba23c39cf68260ba3f27466f8bf5ec88eecd7b3bf220bd65236e93d52832b912db46c54813a7bd0288022f3231a36cb8a071df1973c540bebd4521bacab0e06ccd1da06058cb51fe2a092e33b0a04cf4a8919322f994e1d9c22d802ee2cf2e840fec23bccdb"],

  // ethlab.xyz.	300	IN	RRSIG	DNSKEY 8 2 300 20320927145531 20171016135531 42999 ethlab.xyz. kCWUTbG6licygmytAdeH9dKc5EsNmGwUImTQlqjIlKJLt9nwPO2ncIW5AllRRU2hpKKFDuZdUC5z6uV0Jsr74g==
  // ethlab.xyz.	300	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
  // ethlab.xyz.	300	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
  ["ethlab.xyz.", "003008020000012c7603066359e4ba53a7f7066574686c61620378797a00066574686c61620378797a00003000010000012c00480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a00003000010000012c01080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "9025944db1ba962732826cad01d787f5d29ce44b0d986c142264d096a8c894a24bb7d9f03ceda77085b9025951454da1a4a2850ee65d502e73eae57426cafbe2"],

  // _ens.ethlab.xyz.	86400	IN	RRSIG	TXT 8 3 86400 20320926152530 20171015142530 42999 ethlab.xyz. FhBZI7LarPHOX/1cjiWpX0IFisWAgIao4VEPeqgoYJVkqF6lv7KlaZcAp2n9AEHk1ynffrxoVbijdCUoDn6q8A==
  // _ens.ethlab.xyz.	86400	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
  ["_ens.ethlab.xyz.", "00100803000151807601bbea59e36fdaa7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262", "16105923b2daacf1ce5ffd5c8e25a95f42058ac5808086a8e1510f7aa828609564a85ea5bfb2a5699700a769fd0041e4d729df7ebc6855b8a37425280e7eaaf0"]
];

async function verifySubmission(instance, name, data, sig) {
  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(1, name, data, sig);
  assert.equal(tx.receipt.status, "0x1");
  assert.equal(tx.logs.length, 1);
  assert.equal(tx.logs[0].args.name, name);
  return tx;
}

async function verifyFailedSubmission(instance, name, data, sig) {
  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(1, name, data, sig);
  assert.equal(tx.receipt.status, "0x0");
  return tx;
}

contract('DNSSEC', function(accounts) {
  it('should have a default algorithm and digest set', async function() {
    var instance = await dnssec.deployed();
    assert.notEqual(await instance.algorithms(8), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.algorithms(253), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.digests(2), "0x0000000000000000000000000000000000000000");
    assert.notEqual(await instance.digests(253), "0x0000000000000000000000000000000000000000");
  });

  function rootKeys() {
    return {
      typeCovered: dns.TYPE_DNSKEY,
      algorithm: 253,
      labels: 0,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [],
    };
  };

  it("should reject signatures with non-matching algorithms", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.push({name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: new Buffer("1111", "HEX")});
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.push({name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")})
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.push({name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: new Buffer("1211", "HEX")})
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should accept a root DNSKEY', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 4, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
    ];
    await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should reject signatures with non-matching classes', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_TXT, klass: 2, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  })

  it('should reject signatures with non-matching names', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "foo.net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should reject signatures with the wrong type covered', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_DS,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should reject signatures with too many labels', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 2,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should support wildcard subdomains', async function() {
    var instance = await dnssec.deployed();
    await verifySubmission(instance, "foo.net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 1,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "*.net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should reject signatures with invalid signer names', async function() {
    var instance = await dnssec.deployed();

    await verifySubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_DNSKEY,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")}
      ]
    }), "0x");

    await verifyFailedSubmission(instance, "com.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: "net.",
      rrs: [
        {name: "com.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it("should reject entries with expirations in the past", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    keys.expiration = 123;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries with inceptions in the future", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 0xFFFFFFFF;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should accept updates with newer signatures", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries that aren't newer", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should reject invalid RSA signatures', async function() {
    var instance = await dnssec.deployed();
    var sig = test_rrsets[0][2];
    await verifyFailedSubmission(instance, test_rrsets[0][0], "0x" + test_rrsets[0][1], "0x" + sig.slice(0, sig.length - 2) + "FF");
  });

  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var totalGas = 0;
    for(var rrset of test_rrsets) {
      var tx = await verifySubmission(instance, rrset[0], "0x" + rrset[1], "0x" + rrset[2]);
      totalGas += tx.receipt.gasUsed;
    }
    console.log("Gas used: " + totalGas);
  });
});
