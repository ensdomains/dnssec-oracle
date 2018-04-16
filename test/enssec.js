var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
  // .	2988	IN	RRSIG	DNSKEY 8 0 172800 20171221000000 20171130000000 19036 . Chxx0nFLbwEzx3efCT1k6J1JhX9Cuk9r8IXLKfbeAyEbzuEUovXFokmbZckYvu9cD+DhL+nm33OYTqBLS6VhalEPij95bezRovI5RfAeOlgfc+faHOUe6et553Rk2/3EghtNqutc67tAFpDYAjfKD2CleuyYFIt7vxs5IXRdOUxMOiwWYXwcrMstp6FMZw2Jx/r8eYzulXSCXUq+brqugxx49RlXbnpY5tDNJV5rRBKWUhg56+WOonWg0TxdWdZ1pRfmQ9o+nneuknkCnB5eKbQiA+EvbuLscbWYlvuaHcRynqnW/0nqWx5UDIHxCgkw9XkN03bM4PxQ6J0yjqwVJQ==
  // .	2988	IN	DNSKEY	256 3 8 AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+bP7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPyG6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1ylsr4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjveD1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2/PFENcoFERc=
  // .	2988	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  // .	2988	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  [".", "003008000002a3005a3af9805a1f4a004a5c0000003000010002a30001080100030803010001c44865fc6c91d12530a823c2f5903b66d07bb10602f5face021aaa66ec68caa632b229775f9b3fb9f250b2ee2fc8d69ca02a71a55f6a5db2243e74820e73165e725bf17d74a3575c4148ed511c1ab3f21bafceac0f51054f291969b4ab1a6c366e542204d4e485fba5bff4ac18faedcfd1eea967f2c8c7d7296caf87f563747aa7f76bba211a94a6ac12318a03d2f6c3d8f3510bac5b133b7d0c7f4fc73fdf1ddbb23bde0f5765790e8c25a0b1e1ba4f5d8669a97992bc69fe4f6bf9df9d1c055005a952a119b8f11325c0c1e7a6f1c4d4e0bd69f8357b51ad756b5b4c7f44e5bbca64a4bc21ecd408820204849c0484f7971371380ba436fcf14435ca05111700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "0a1c71d2714b6f0133c7779f093d64e89d49857f42ba4f6bf085cb29f6de03211bcee114a2f5c5a2499b65c918beef5c0fe0e12fe9e6df73984ea04b4ba5616a510f8a3f796decd1a2f23945f01e3a581f73e7da1ce51ee9eb79e77464dbfdc4821b4daaeb5cebbb401690d80237ca0f60a57aec98148b7bbf1b3921745d394c4c3a2c16617c1caccb2da7a14c670d89c7fafc798cee9574825d4abe6ebaae831c78f519576e7a58e6d0cd255e6b441296521839ebe58ea275a0d13c5d59d675a517e643da3e9e77ae9279029c1e5e29b42203e12f6ee2ec71b59896fb9a1dc4729ea9d6ff49ea5b1e540c81f10a0930f5790dd376cce0fc50e89d328eac1525"],

  // xyz.	78203	IN	RRSIG	DS 8 1 86400 20171224050000 20171211040000 46809 . IPR+56x0Xl2/P/oNnJ00dl73OMO2QeCekHK+6CV8HsiTAWYbRVICSha7wPm0uDABPKzzXCfncH+/WujnzhXQkE2twiVlE8OMUBg6eUlXSHMCuiDzLUS3AiK8hMKY9VemfDdVQvIu7JBL6k6+GNavFW9j2yHWw2H+ZVscverfGZju+9eU1ml6YnhXYHrkRn+nL+Bu9bKAzn88elkS97C3rDxq/7uuyfq+RPdmDIag3JhY+tSWovzKlwCIIbsPlm3zFUNtODdpLEhr3iKKAXkUsxppq5K5K2NQkAYIy4H/9aSxSvvHNAASl1eTLCp8GvmbqOjs4THiDLHQ8xIDRzkv0A==
  // xyz.	78203	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
  // xyz.	78203	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
  ["xyz.", "002b0801000151805a3f34505a2e02c0b6d9000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "20f47ee7ac745e5dbf3ffa0d9c9d34765ef738c3b641e09e9072bee8257c1ec89301661b4552024a16bbc0f9b4b830013cacf35c27e7707fbf5ae8e7ce15d0904dadc2256513c38c50183a794957487302ba20f32d44b70222bc84c298f557a67c375542f22eec904bea4ebe18d6af156f63db21d6c361fe655b1cbdeadf1998eefbd794d6697a627857607ae4467fa72fe06ef5b280ce7f3c7a5912f7b0b7ac3c6affbbaec9fabe44f7660c86a0dc9858fad496a2fcca97008821bb0f966df315436d3837692c486bde228a017914b31a69ab92b92b6350900608cb81fff5a4b14afbc73400129757932c2a7c1af99ba8e8ece131e20cb1d0f3120347392fd0"],

  // xyz.	1935	IN	RRSIG	DNSKEY 8 1 3600 20171215122201 20171115165924 3599 xyz. R97j06oJBxyWwNbcTGtM8NNX0m8ctsMzm7xaAmeR2KKQa6OWETCbqZAbzKPNo12fzR++sMt+FAmxT/1qthc9CAXFG9UVzd15f0XuZ1YAwbplSTdbRW6aQKifCXlN05NYm2lZQvpt3B4Y/Zoc0b5jRLnz7cVR/TYUSQ8pWMu/jDLAJF3OpCCttKbVD9gxPylFdk+lKA9XdZ96YQRpawjfEaJ466WIuhxuqR22368TGi9+0QvtnW03Oyu919L4lkyKaLGxwD0fxA9I2Uo4CvIvVVjNKF5HosIcQMB8VCTkh/QfaZG/Nhjr+R1ilu3ynsy1OkVgvxvQIm4QGnpstJevFg==
  // xyz.	1935	IN	DNSKEY	256 3 8 AwEAAZ92VSgD71ay++8GbqtLF58yu5xuZEKwruVWjA1sZuf6fG68Ahkd/AnTcCs4PITlliSk4466CXSdcUnQm17SnrWOPHEf3gd+GVuMwwTwduGr8a8ZAYbO2/kr2ey9zaP36m2ssxlm0iRkDsLp9ThnLWG6ku2AkJuXS3du/KhcDt4h
  // xyz.	1935	IN	DNSKEY	256 3 8 AwEAAcNtcabd7RfM090DJQb5dvd5E4+EBdCVEA5sPIfOw8GM7AztT2AkzFHAP/3e3IZ35qGj6FfWyra/UeD7pblcerkwsmgRq0yeFbRkWN33G8nfkP7UnIcp35MeN+0ADb9zaBVPQLk7ctEsozjWVSeYhLazFOYqn2PFt5O8vwLHJLyh
  // xyz.	1935	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  ["xyz.", "0030080100000e105a33be695a0c726c0e0f0378797a000378797a000030000100000e10008801000308030100019f76552803ef56b2fbef066eab4b179f32bb9c6e6442b0aee5568c0d6c66e7fa7c6ebc02191dfc09d3702b383c84e59624a4e38eba09749d7149d09b5ed29eb58e3c711fde077e195b8cc304f076e1abf1af190186cedbf92bd9ecbdcda3f7ea6dacb31966d224640ec2e9f538672d61ba92ed80909b974b776efca85c0ede210378797a000030000100000e1000880100030803010001c36d71a6dded17ccd3dd032506f976f779138f8405d095100e6c3c87cec3c18cec0ced4f6024cc51c03ffddedc8677e6a1a3e857d6cab6bf51e0fba5b95c7ab930b26811ab4c9e15b46458ddf71bc9df90fed49c8729df931e37ed000dbf7368154f40b93b72d12ca338d655279884b6b314e62a9f63c5b793bcbf02c724bca10378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "47dee3d3aa09071c96c0d6dc4c6b4cf0d357d26f1cb6c3339bbc5a026791d8a2906ba39611309ba9901bcca3cda35d9fcd1fbeb0cb7e1409b14ffd6ab6173d0805c51bd515cddd797f45ee675600c1ba6549375b456e9a40a89f09794dd393589b695942fa6ddc1e18fd9a1cd1be6344b9f3edc551fd3614490f2958cbbf8c32c0245dcea420adb4a6d50fd8313f2945764fa5280f57759f7a6104696b08df11a278eba588ba1c6ea91db6dfaf131a2f7ed10bed9d6d373b2bbdd7d2f8964c8a68b1b1c03d1fc40f48d94a380af22f5558cd285e47a2c21c40c07c5424e487f41f6991bf3618ebf91d6296edf29eccb53a4560bf1bd0226e101a7a6cb497af16"],

  // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180110024731 20171211110343 7563 xyz. ms5y+4DGayYb2FBmmf4mgKaUbGsbpiFy82YT2JfubA1AN9Rw0X1SF4yCudZWAH0cOPyKO0Lh3hh4hZWdsYxOuW6IT7uN+T0qGRzwJSvdkiTVaellvcfSmNvij4ls8JlFvvtK5COgt04Kn2E5JatrlNZ/N0ejsFS3gStNCiTwXA0=
  // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
  // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
  ["ethlab.xyz.", "002b080200000e105a557ec35a2e660f1d8b0378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "9ace72fb80c66b261bd8506699fe2680a6946c6b1ba62172f36613d897ee6c0d4037d470d17d52178c82b9d656007d1c38fc8a3b42e1de187885959db18c4eb96e884fbb8df93d2a191cf0252bdd9224d569e965bdc7d298dbe28f896cf09945befb4ae423a0b74e0a9f613925ab6b94d67f3747a3b054b7812b4d0a24f05c0d"],

  // ethlab.xyz.	299	IN	RRSIG	DNSKEY 8 2 300 20320927145531 20171016135531 42999 ethlab.xyz. kCWUTbG6licygmytAdeH9dKc5EsNmGwUImTQlqjIlKJLt9nwPO2ncIW5AllRRU2hpKKFDuZdUC5z6uV0Jsr74g==
  // ethlab.xyz.	299	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
  // ethlab.xyz.	299	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
  ["ethlab.xyz.", "003008020000012c7603066359e4ba53a7f7066574686c61620378797a00066574686c61620378797a00003000010000012c00480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a00003000010000012c01080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "9025944db1ba962732826cad01d787f5d29ce44b0d986c142264d096a8c894a24bb7d9f03ceda77085b9025951454da1a4a2850ee65d502e73eae57426cafbe2"],

  // _ens.ethlab.xyz.	21599	IN	RRSIG	TXT 8 3 86400 20320926152530 20171015142530 42999 ethlab.xyz. FhBZI7LarPHOX/1cjiWpX0IFisWAgIao4VEPeqgoYJVkqF6lv7KlaZcAp2n9AEHk1ynffrxoVbijdCUoDn6q8A==
  // _ens.ethlab.xyz.	21599	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
  ["_ens.ethlab.xyz.", "00100803000151807601bbea59e36fdaa7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262", "16105923b2daacf1ce5ffd5c8e25a95f42058ac5808086a8e1510f7aa828609564a85ea5bfb2a5699700a769fd0041e4d729df7ebc6855b8a37425280e7eaaf0"]
];

async function verifySubmission(instance, name, data, sig) {
  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(1, name, data, sig);
  assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
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
      console.log(rrset[0]);
      var tx = await verifySubmission(instance, rrset[0], "0x" + rrset[1], "0x" + rrset[2]);
      totalGas += tx.receipt.gasUsed;
    }
    console.log("Gas used: " + totalGas);
  });
});
