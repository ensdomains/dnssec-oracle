var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
  // .	108336	IN	RRSIG	DNSKEY 8 0 172800 20180502000000 20180411000000 19036 . RuGJ2bWAFVvwMNLFlekfwzrGZ9F/osGnJroRl01gG/XC5/vvUjl5pP6wKNJiRMhuXCOfE/b860yD4InvzExUeYJc1P5Y1VCNazABaXulVQQ/4CogjTaFfxl9gZWZfbz2catntlJ88rD06kgWjW6YgtNqBWKSfJ+EmpyWbsh8PDgcO4LfQkhDemWugY4Huhy6MF1RGzCynD4SuU2TtMLNXWFXbt/ngap68ktFR60R2u4VCx6p8GTLtYpe2auQZrJqnwAgpO/0zBV6AcHz0KZV0tnKwQ+HTIee1LlAR18TKjnDlkpSTLpImNbE4Uc0rJsi73jcUr9sjtP0N1+Nk/tDGQ==
  // .	108336	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  // .	108336	IN	DNSKEY	256 3 8 AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZRrPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aRZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aCIK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtjwG0I78sfMZc=
  // .	108336	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  [".", "003008000002a3005ae8ff805acd50004a5c0000003000010002a30001080100030803010001d53868a943804a57596a47e5a5c7259235566f429b8da6180b2a933dda90572d4bacec6470b7a4d34cba0f7d7ca6bb396fad44723064473ffe65fc26de9b730e5b3e04471babb6793f2f5296d70cf56cd4808647a16197015610ecb16c82220df77b12ae9e00b93944d71abb213efd93fe55dae15990de116651acf04b8c1c815931e5faffdffb1bd32774ad72adad12a9f34b60823abe914c97a9a6b621bbee5897a69166611504adbb5825b566b9352de909bc95df7322922a4d7d0b93392565f9f29c7a9c1d484b4a4cb3a68220adb2690415354120f57c90cc14affeb33154d372dd502a3a3be1f8e012a4b326e061026d249ef23b63c06d08efcb1f319700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "46e189d9b580155bf030d2c595e91fc33ac667d17fa2c1a726ba11974d601bf5c2e7fbef523979a4feb028d26244c86e5c239f13f6fceb4c83e089efcc4c5479825cd4fe58d5508d6b3001697ba555043fe02a208d36857f197d8195997dbcf671ab67b6527cf2b0f4ea48168d6e9882d36a0562927c9f849a9c966ec87c3c381c3b82df4248437a65ae818e07ba1cba305d511b30b29c3e12b94d93b4c2cd5d61576edfe781aa7af24b4547ad11daee150b1ea9f064cbb58a5ed9ab9066b26a9f0020a4eff4cc157a01c1f3d0a655d2d9cac10f874c879ed4b940475f132a39c3964a524cba4898d6c4e14734ac9b22ef78dc52bf6c8ed3f4375f8d93fb4319"],

  // xyz.	55477	IN	RRSIG	DS 8 1 86400 20180429050000 20180416040000 39570 . kXUSo/3+KtIrAaenpKtwMncd9TUsIk34eHTtvT728m1v31KBUp94+xIwTlgOEzWtkuA54U5bYWIuLOcTpmanqJPoTu4LbM0zaRFDhDPZkGDIcBjusEJJK6BhXgjy9STmm4b0shojTYxL24Q4jR1ntxlc/LnDDkYV8Ht6blcAcCYVInnP18X2qQrX/+SQoIW34NyMegCP04PVjr1pmtQRY1pQqikYPIuu5IrYHPiSynyeK2dl3g5T17c4CJJ+txzFl/w6fTNq2yzyt6MIoULvP1xMuYTmfE2VLqmZLFqPPbNq85gzvTAdyM/lRDx10cfqS22e+sEPOirdStI5GeVMyg==
  // xyz.	55477	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
  // xyz.	55477	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
  ["xyz.", "002b0801000151805ae551505ad41fc09a92000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "917512a3fdfe2ad22b01a7a7a4ab7032771df5352c224df87874edbd3ef6f26d6fdf5281529f78fb12304e580e1335ad92e039e14e5b61622e2ce713a666a7a893e84eee0b6ccd336911438433d99060c87018eeb042492ba0615e08f2f524e69b86f4b21a234d8c4bdb84388d1d67b7195cfcb9c30e4615f07b7a6e57007026152279cfd7c5f6a90ad7ffe490a085b7e0dc8c7a008fd383d58ebd699ad411635a50aa29183c8baee48ad81cf892ca7c9e2b6765de0e53d7b73808927eb71cc597fc3a7d336adb2cf2b7a308a142ef3f5c4cb984e67c4d952ea9992c5a8f3db36af39833bd301dc8cfe5443c75d1c7ea4b6d9efac10f3a2add4ad23919e54cca"],

  // xyz.	1952	IN	RRSIG	DNSKEY 8 1 3600 20180515021130 20180414183948 3599 xyz. OrJosbGfgTU8PMWJHzx89lh5f8eMLTQGjU6GT/oFF1VHf1P4pdD0NbVs6mCyJ3dsD38llNL1eF7/H3Eayo2Fjbiq2n+vvz8/1FKhCM21hvSUVu9Q3DnrDWEbFKeg73j1QK4OOlJU5RKOu/akVGIEt84syc7T6t4ISVoZUIHGQlEsO8ZRI6Z9YmWkf+7oFoiQopSGr3VeOFuVNBsGHyNdl7/hAcrUEMhXaqCoHagNwBDycxhbuSYxwn5FaODXlwIgx7QinNRGrEBjpKC5RxVTZ3IgTTTWUzolc1rFbJincNaDkf3ng6oSpn0nRSyf32cSyl/kPlyt+11cayDvAoKGQA==
  // xyz.	1952	IN	DNSKEY	256 3 8 AwEAAYNktvUuoOalRZ7fB2EGfUkqOqIVNZcx9YaU3i8CubvOetVo8n+oUvvivq8+Vs2XithtiMzExJPGtJOjk38hibkBfCFcjNdiMQpce+ZfpJtRcmB30R+hxpHXiRwS7y6pPT3g2/dyeQJckH7R1qR6TQgqqVi/Mgbs6FmvpxgI9Dy7
  // xyz.	1952	IN	DNSKEY	256 3 8 AwEAAa6CLBIa4fmw7gt9YTsutscEOLeGjGnu+w2C+yLpQqvuZNu9O2BdVNjv0VwoP0fc33eYUh3OLgwki8O3ZjfneQPKmYJLkbLmWvRrX+mV8zUGGF3qOgOYk34ewK8fhHZO07UY7xk4jKjiCa+52OSdyof6tR3My+QOjQZH3mn9b/GX
  // xyz.	1952	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  ["xyz.", "0030080100000e105afa41d25ad24af40e0f0378797a000378797a000030000100000e10008801000308030100018364b6f52ea0e6a5459edf0761067d492a3aa215359731f58694de2f02b9bbce7ad568f27fa852fbe2beaf3e56cd978ad86d88ccc4c493c6b493a3937f2189b9017c215c8cd762310a5c7be65fa49b51726077d11fa1c691d7891c12ef2ea93d3de0dbf77279025c907ed1d6a47a4d082aa958bf3206ece859afa71808f43cbb0378797a000030000100000e1000880100030803010001ae822c121ae1f9b0ee0b7d613b2eb6c70438b7868c69eefb0d82fb22e942abee64dbbd3b605d54d8efd15c283f47dcdf7798521dce2e0c248bc3b76637e77903ca99824b91b2e65af46b5fe995f33506185dea3a0398937e1ec0af1f84764ed3b518ef19388ca8e209afb9d8e49dca87fab51dcccbe40e8d0647de69fd6ff1970378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "3ab268b1b19f81353c3cc5891f3c7cf658797fc78c2d34068d4e864ffa051755477f53f8a5d0f435b56cea60b227776c0f7f2594d2f5785eff1f711aca8d858db8aada7fafbf3f3fd452a108cdb586f49456ef50dc39eb0d611b14a7a0ef78f540ae0e3a5254e5128ebbf6a4546204b7ce2cc9ced3eade08495a195081c642512c3bc65123a67d6265a47feee8168890a29486af755e385b95341b061f235d97bfe101cad410c8576aa0a81da80dc010f273185bb92631c27e4568e0d7970220c7b4229cd446ac4063a4a0b94715536772204d34d6533a25735ac56c98a770d68391fde783aa12a67d27452c9fdf6712ca5fe43e5cadfb5d5c6b20ef02828640"],

  // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180507073833 20180407085930 56880 xyz. JA5rC3pDdK5i9Z85qMo6lWiO86UZWbJIy56hDBPSQy9Ffjr7dGnf7voPuD1k0BmUUAknYw6ArcN2JrXlJGMpdFxheytu0m7CCFgkkA7+zEpHVb+BOsVcsGi3oODOQMl3NPdtaIvG/o9LaWmNTkAQU48gfjG3ofC+hv4HV5/9Gs4=
  // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
  // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
  ["ethlab.xyz.", "002b080200000e105af002795ac88872de300378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "240e6b0b7a4374ae62f59f39a8ca3a95688ef3a51959b248cb9ea10c13d2432f457e3afb7469dfeefa0fb83d64d01994500927630e80adc37626b5e5246329745c617b2b6ed26ec2085824900efecc4a4755bf813ac55cb068b7a0e0ce40c97734f76d688bc6fe8f4b69698d4e4010538f207e31b7a1f0be86fe07579ffd1ace"],

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
  try{
    var tx = await instance.submitRRSet(1, name, data, sig);
  }
  catch(error){
    // Assert ganache revert exception
    assert.equal(error.message, 'VM Exception while processing transaction: revert');
  }
  // Assert geth failed transaction
  if(tx !== undefined) {
    assert.equal(parseInt(tx.receipt.status), parseInt('0x0'));
  }
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
      rrs: [
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 4, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
      ],
    };
  };

  it("should reject signatures with non-matching algorithms", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: new Buffer("1111", "HEX")}
    ];
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
    ];
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: new Buffer("1211", "HEX")}
    ];
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

  it('should check if root DNSKEY exist', async function(){
    var instance = await dnssec.deployed();
    var [_, _, rrs] = await instance.rrset.call(1, dns.TYPE_DNSKEY, dns.hexEncodeName('nonexisting.'));
    assert.equal(rrs, '0x');
    [_, _, rrs] = await instance.rrset.call(1, dns.TYPE_DNSKEY, dns.hexEncodeName('.'));
    assert.notEqual(rrs, '0x');
  })

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

  // Test delete RRsec
  async function verifyPresence(instance, bool, type, name){
    var result = (await instance.rrset.call(1, type, dns.hexEncodeName(name)))[2];
    if(bool){
      assert.notEqual(result,'0x');  
    }else{
      assert.equal(result,'0x');  
    }
  }

  async function submitEntry(instance, type, name, option){
    var rrs = {name: name, type: type, klass: 1, ttl: 3600};
    Object.assign(rrs, option)
    var keys = {
      typeCovered: type,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 1,
      keytag: 5647,
      signerName: ".",
      rrs: [rrs],
    };
    await verifySubmission(instance, name, dns.hexEncodeSignedSet(keys), "0x");
    var [_, _, rrs] = await instance.rrset.call(1, type, dns.hexEncodeName(name));
    assert.notEqual(rrs, '0x');  
  }

  it('rejects if NSEC record is not found', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]});
    await verifyPresence(instance, true, dns.TYPE_TXT, 'b.')
    await instance.deleteRRSet(1, dns.hexEncodeName('a.'), dns.TYPE_TXT, dns.hexEncodeName('b.'));
    await verifyPresence(instance, true, dns.TYPE_TXT, 'b.')
  })

  it('rejects if NSEC record does not match deleting record type', async function(){
    var instance = await dnssec.deployed();
    // proving record is not NSEC
    var option = {klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")}
    await submitEntry(instance, dns.TYPE_DNSKEY, 'a.',  option);
    await verifyPresence(instance, true, dns.TYPE_DNSKEY, 'a.')
    await instance.deleteRRSet(1, dns.hexEncodeName('a.'), dns.TYPE_TXT, dns.hexEncodeName('b.'));
    await verifyPresence(instance, true, dns.TYPE_TXT, 'b.')
  })

  it('deletes RRset if NSEC entry is found', async function(){
    var instance = await dnssec.deployed();
    // proving record is NSEC
    await submitEntry(instance, dns.TYPE_NSEC, 'a.', {next:'d.', rrtypes:[dns.TYPE_TXT]});
    await verifyPresence(instance, true, dns.TYPE_NSEC, 'a.')
    var tx = await instance.deleteRRSet(1, dns.hexEncodeName('a.'), dns.TYPE_TXT, dns.hexEncodeName('b.'));
    tx.logs.forEach(function(l){
      console.log('tx', l.event, l.args)
    })
    await verifyPresence(instance, false, dns.TYPE_TXT, 'b.')
  })

  // Test against real record
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
