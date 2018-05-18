var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
    // .	99538	IN	RRSIG	DNSKEY 8 0 172800 20180601000000 20180511000000 19036 . k0XCRTsOetHy2ybnDwZx1Lq0wSc80YksHYTEs+PgpMsR3lYcp+QX7p5zX1pf/78Mhh1m2pW6M6onpWZCIeM+OPyqDNjKpRV9siF/Aw7idpNKSraqs4ceOtJlrKi6chRlfgDhXliNy8lpfj8PnPaGNaihL9Tvmv4bIlHZiFRJMpdz43UFb9vkpQOCdZu7sfK9lZGYU+cpjVT4OqfC0JfmpTA3H3lcpOy2o7VDKB0dEuldy07hBigh6toAYWTD1Qk6WPMRVn+YQBe40hgFLItHHwYdpOLH3uSBJb2R3fzOTh6+hx3rUDJvoEajbou4pUP8Y7dhNXc3zPiI6tG8A5dNoA==
    // .	99538	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
    // .	99538	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
    // .	99538	IN	DNSKEY	256 3 8 AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZRrPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aRZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aCIK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtjwG0I78sfMZc=
    [".", "003008000002a3005b108c805af4dd004a5c0000003000010002a30001080100030803010001d53868a943804a57596a47e5a5c7259235566f429b8da6180b2a933dda90572d4bacec6470b7a4d34cba0f7d7ca6bb396fad44723064473ffe65fc26de9b730e5b3e04471babb6793f2f5296d70cf56cd4808647a16197015610ecb16c82220df77b12ae9e00b93944d71abb213efd93fe55dae15990de116651acf04b8c1c815931e5faffdffb1bd32774ad72adad12a9f34b60823abe914c97a9a6b621bbee5897a69166611504adbb5825b566b9352de909bc95df7322922a4d7d0b93392565f9f29c7a9c1d484b4a4cb3a68220adb2690415354120f57c90cc14affeb33154d372dd502a3a3be1f8e012a4b326e061026d249ef23b63c06d08efcb1f319700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "9345c2453b0e7ad1f2db26e70f0671d4bab4c1273cd1892c1d84c4b3e3e0a4cb11de561ca7e417ee9e735f5a5fffbf0c861d66da95ba33aa27a5664221e33e38fcaa0cd8caa5157db2217f030ee276934a4ab6aab3871e3ad265aca8ba7214657e00e15e588dcbc9697e3f0f9cf68635a8a12fd4ef9afe1b2251d9885449329773e375056fdbe4a50382759bbbb1f2bd95919853e7298d54f83aa7c2d097e6a530371f795ca4ecb6a3b543281d1d12e95dcb4ee1062821eada006164c3d5093a58f311567f984017b8d218052c8b471f061da4e2c7dee48125bd91ddfcce4e1ebe871deb50326fa046a36e8bb8a543fc63b761357737ccf888ead1bc03974da0"],

    // xyz.	51512	IN	RRSIG	DS 8 1 86400 20180527170000 20180514160000 39570 . bIF+BmGJ7g1RKsqi7uCJ01R++EHCGjpHE+ddsBmn/eMpCcrpGvF2N51LugK4Pa0YbeCxuQb4soS+ysXYX5L19ZCe1RiJVWO8vZ5KfVAbvBfq02Bgv3DPtkXnauGNq4DvJftIm6xHiQDLHp77+7W4jzs63+4jhyaBqH1Dy/4oB8JaWsiRMPo/Jb2jbksAVBVmKp2WENRiYERVOKFVh8qNcEVfBrg9BmYCO/aUwOwu9CsYuFgoWbaBrDYTB6mGQ/imE/8PHXZNE3fCH5FJWoYm8HRJmNNQ7FEqe7IOQ5N2/GluYMp06zkYk4fN+rQGO+3eMjObqB8i4dyvI324eJh3gA==
    // xyz.	51512	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
    // xyz.	51512	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
    ["xyz.", "002b0801000151805b0ae4105af9b2809a92000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "6c817e066189ee0d512acaa2eee089d3547ef841c21a3a4713e75db019a7fde32909cae91af176379d4bba02b83dad186de0b1b906f8b284becac5d85f92f5f5909ed518895563bcbd9e4a7d501bbc17ead36060bf70cfb645e76ae18dab80ef25fb489bac478900cb1e9efbfbb5b88f3b3adfee23872681a87d43cbfe2807c25a5ac89130fa3f25bda36e4b005415662a9d9610d46260445538a15587ca8d70455f06b83d0666023bf694c0ec2ef42b18b8582859b681ac361307a98643f8a613ff0f1d764d1377c21f91495a8626f0744998d350ec512a7bb20e439376fc696e60ca74eb39189387cdfab4063bedde32339ba81f22e1dcaf237db878987780"],

    // xyz.	3361	IN	RRSIG	DNSKEY 8 1 3600 20180613130918 20180514192031 3599 xyz. FLzhcG4KLcYx6837aEZ3xWCYA2SNIMjv7sBVJG2TLkl7pq+9wWwZHfCpUaRr/Q/Mnfuu77ljkEx3ZFAmut7/AKXvoC12BHfNUiOxjARQUpiFDWzF+AAKIGqweimjj/0fv/L0E0Vvu9wbKopUnw58f3RGc+4RUtvl4cvPhZUNc6s1k9csjfvZcTWvx5caso9hGU/4f5H0GzBOnv6LL96rzW+UAuk543ndkbqPd+niC61ZF80h3s0b9JnhJ06D7BAIf4AhJWf6DA+jzspaa5J8qZh/EWbPFYNCgewK020zQfCzxFxlUPUZ8ix47Lbfx++KOHUKvOHV2JNNYjT/xFdS/g==
    // xyz.	3361	IN	DNSKEY	256 3 8 AwEAAYNktvUuoOalRZ7fB2EGfUkqOqIVNZcx9YaU3i8CubvOetVo8n+oUvvivq8+Vs2XithtiMzExJPGtJOjk38hibkBfCFcjNdiMQpce+ZfpJtRcmB30R+hxpHXiRwS7y6pPT3g2/dyeQJckH7R1qR6TQgqqVi/Mgbs6FmvpxgI9Dy7
    // xyz.	3361	IN	DNSKEY	256 3 8 AwEAAbi90iT9b2z/i2CJyxKwJk7wVxTBizJhqB7Uabh55DwvDiBRUP3GMw1Qsng01aC4Ve92SUVBc3LIBTJ1FerN2OnByWBAnjizWuOn9RSGFlehJSbtHNdMlUktiyRxM+6j9/DUR1UYZCCChwuzkaQtNH5e4EKX5PhjwMeT2GfOg69v
    // xyz.	3361	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
    ["xyz.", "0030080100000e105b21177e5af9e17f0e0f0378797a000378797a000030000100000e10008801000308030100018364b6f52ea0e6a5459edf0761067d492a3aa215359731f58694de2f02b9bbce7ad568f27fa852fbe2beaf3e56cd978ad86d88ccc4c493c6b493a3937f2189b9017c215c8cd762310a5c7be65fa49b51726077d11fa1c691d7891c12ef2ea93d3de0dbf77279025c907ed1d6a47a4d082aa958bf3206ece859afa71808f43cbb0378797a000030000100000e1000880100030803010001b8bdd224fd6f6cff8b6089cb12b0264ef05714c18b3261a81ed469b879e43c2f0e205150fdc6330d50b27834d5a0b855ef764945417372c805327515eacdd8e9c1c960409e38b35ae3a7f514861657a12526ed1cd74c95492d8b247133eea3f7f0d4475518642082870bb391a42d347e5ee04297e4f863c0c793d867ce83af6f0378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "14bce1706e0a2dc631ebcdfb684677c5609803648d20c8efeec055246d932e497ba6afbdc16c191df0a951a46bfd0fcc9dfbaeefb963904c77645026badeff00a5efa02d760477cd5223b18c04505298850d6cc5f8000a206ab07a29a38ffd1fbff2f413456fbbdc1b2a8a549f0e7c7f744673ee1152dbe5e1cbcf85950d73ab3593d72c8dfbd97135afc7971ab28f61194ff87f91f41b304e9efe8b2fdeabcd6f9402e939e379dd91ba8f77e9e20bad5917cd21decd1bf499e1274e83ec10087f80212567fa0c0fa3ceca5a6b927ca9987f1166cf15834281ec0ad36d3341f0b3c45c6550f519f22c78ecb6dfc7ef8a38750abce1d5d8934d6234ffc45752fe"],

    // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180603040300 20180504054358 48429 xyz. XCf5FksrqPEwuRJT/mSQutDUCrxycTw6tMvEDHfgcRAS2IGP74HjSpb4zOiyHeA8Wly3PXX+/5OYcdrhNZMXfk06ZzDdJ8nB/vCZDdx9Q9f1N3UYjGiqXRmzHiTbOjdpSmiQcnW3OW1hqVmZJCKp9lzHHuyglwLBXx/RWeJKaN8=
    // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
    // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
    ["ethlab.xyz.", "002b080200000e105b1368745aebf31ebd2d0378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "5c27f9164b2ba8f130b91253fe6490bad0d40abc72713c3ab4cbc40c77e0711012d8818fef81e34a96f8cce8b21de03c5a5cb73d75feff939871dae13593177e4d3a6730dd27c9c1fef0990ddc7d43d7f53775188c68aa5d19b31e24db3a37694a68907275b7396d61a959992422a9f65cc71eeca09702c15f1fd159e24a68df"],

    // ethlab.xyz.	168	IN	RRSIG	DNSKEY 8 2 3600 20330425112105 20180514102105 42999 ethlab.xyz. NR9mB8JdE5uoaKYsHha4NtHdVhyhKkrVfnwTo0EOzziYjGSBZNVV6QR4Fk3g9zjdVk3G0gwdYGlwDldXIdIaiw==
    // ethlab.xyz.	168	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
    // ethlab.xyz.	168	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
    ["ethlab.xyz.", "0030080200000e107717af215af96311a7f7066574686c61620378797a00066574686c61620378797a000030000100000e1000480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a000030000100000e1001080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "351f6607c25d139ba868a62c1e16b836d1dd561ca12a4ad57e7c13a3410ecf38988c648164d555e90478164de0f738dd564dc6d20c1d6069700e575721d21a8b"],

    // _ens.ethlab.xyz.	15412	IN	RRSIG	TXT 8 3 86400 20330425112105 20180514102105 42999 ethlab.xyz. UPpW0TxdA/aXTtOdzZZrsnzYoTZqb/AKLJroyw8zJq8ZuBP5UaJbvYWGSoV92+osozXTb53IbRBc57qstaKz8A==
    // _ens.ethlab.xyz.	15412	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
    ["_ens.ethlab.xyz.", "00100803000151807717af215af96311a7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262", "50fa56d13c5d03f6974ed39dcd966bb27cd8a1366a6ff00a2c9ae8cb0f3326af19b813f951a25bbd85864a857ddbea2ca335d36f9dc86d105ce7baacb5a2b3f0"]
];

async function verifySubmission(instance, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  var tx = await instance.submitRRSet(data, sig, proof);
  assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
  assert.equal(tx.logs.length, 1);
  return tx;
}

async function verifyFailedSubmission(instance, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  try{
    var tx = await instance.submitRRSet(data, sig, proof);
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
      {name: "foo.bar.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: new Buffer("1111", "HEX")}
    ];
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
    ];
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: new Buffer("1211", "HEX")}
    ];
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  var rootKeyProof = undefined;
  it('should accept a root DNSKEY', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    var tx = await verifySubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
    rootKeyProof = tx.logs[0].args.rrset;
  });

  it('should check if root DNSKEY exist', async function(){
    var instance = await dnssec.deployed();
    var [_, _, rrs] = await instance.rrdata.call(dns.TYPE_DNSKEY, dns.hexEncodeName('nonexisting.'));
    assert.equal(rrs, '0x0000000000000000000000000000000000000000');
    [_, _, rrs] = await instance.rrdata.call(dns.TYPE_DNSKEY, dns.hexEncodeName('.'));
    assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
  })

  it('should accept a signed RRSET', async function() {
    var instance = await dnssec.deployed();
    var proof = dns.hexEncodeRRs(rootKeys().rrs);
    await verifySubmission(instance, dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 1,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "test.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["test"]}
      ],
    }), "0x", proof);
  });

  it('should reject signatures with non-matching classes', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet({
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
    var proof = dns.hexEncodeRRs(rootKeys().rrs);
    await verifySubmission(instance, dns.hexEncodeSignedSet({
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
    }), "0x", proof);
  });

  it('should reject signatures with invalid signer names', async function() {
    var instance = await dnssec.deployed();

    await verifySubmission(instance, dns.hexEncodeSignedSet({
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

    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries with inceptions in the future", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 0xFFFFFFFF;
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should accept updates with newer signatures", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    await verifySubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries that are older", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 0;
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should reject invalid RSA signatures', async function() {
    var instance = await dnssec.deployed();
    var sig = test_rrsets[0][2];
    await verifyFailedSubmission(instance, "0x" + test_rrsets[0][1], "0x" + sig.slice(0, sig.length - 2) + "FF");
  });

  // Test delete RRSET
  async function checkPresence(instance, type, name){
    var result = (await instance.rrdata.call(type, dns.hexEncodeName(name)))[2];
    return result != '0x0000000000000000000000000000000000000000';
  }

  function buildEntry(type, name, option, sig) {
      var rrs = {name: name, type: type, klass: 1, ttl: 3600};
      Object.assign(rrs, option);
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
      if(sig !== undefined) {
          Object.assign(keys, sig);
      }
      return keys;
  }

  async function submitEntry(instance, type, name, option, proof, sig){
    var keys = buildEntry(type, name, option, sig);
    var [inception, _, rrs] = await instance.rrdata.call(type, dns.hexEncodeName(name));
    if(inception >= keys.inception) {
        keys.inception = inception + 1;
    }
    tx = await verifySubmission(instance, dns.hexEncodeSignedSet(keys), "0x", proof);
    [_, _, rrs] = await instance.rrdata.call(type, dns.hexEncodeName(name));
    assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
    return tx;
  }

  async function deleteEntry(instance, deletetype, deletename, nsec, proof) {
    var tx, result;
    try{
      tx = await instance.deleteRRSet(deletetype, dns.hexEncodeName(deletename), nsec, "0x", proof);
    }
    catch(error){
      // Assert ganache revert exception
      assert.equal(error.message, 'VM Exception while processing transaction: revert');
      result = false;
    }
    // Assert geth failed transaction
    if(tx !== undefined) {
      result = (parseInt(tx.receipt.status) == parseInt('0x1'));
    }
    return result;
  }

  it('rejects if a proof with the wrong type is supplied', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]}, rootKeyProof);
    // Submit with a proof for an irrelevant record.
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.', dns.hexEncodeSignedSet(rootKeys()), rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.')), true);
  })

  it('rejects if next record does not come before the deleting name', async function(){
    var instance = await dnssec.deployed();
    // text z. comes after next d.
    await submitEntry(instance, dns.TYPE_TXT, 'z.', {text: ["foo"]}, rootKeyProof);
    var nsec = buildEntry(dns.TYPE_NSEC, 'a.', {next: 'd.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'z.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'z.')), true);
  })

  it('rejects if nsec record starts after the deleting name', async function(){
    var instance = await dnssec.deployed();
    // text a. comes after nsec b.
    await submitEntry(instance, dns.TYPE_TXT, 'a.', {text: ["foo"]}, rootKeyProof);
    var nsec = buildEntry(dns.TYPE_NSEC, 'b.', {next:'d.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  })

  it('rejects RRset if trying to delete rrset that is in the type bitmap', async function(){
    var instance = await dnssec.deployed();
    // text a. has same nsec a. with type bitmap
    await submitEntry(instance, dns.TYPE_TXT, 'a.', { text:['foo']}, rootKeyProof);
    var nsec = buildEntry(dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  })

  it('deletes RRset if nsec name and delete name are the same but with different rrtypes', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT,  'a.', { text: ["foo"] }, rootKeyProof);
    // This test fails if rrtypes is empty ([]), but would that case every happen?
    var nsec = buildEntry(dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_NSEC]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), false);
  })

  it('rejects if the proof hash does not match', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT,  'a.', { text: ["foo"] }, rootKeyProof);
    // This test fails if rrtypes is empty ([]), but would that case every happen?
    var nsec = buildEntry(dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_NSEC]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', dns.hexEncodeSignedSet(nsec) + '00', rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  })

  it('deletes RRset if NSEC next comes after delete name', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]}, rootKeyProof);
    var nsec = buildEntry(dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.')), false);
  })

  it('will not delete a record if it is more recent than the NSEC record', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'y.', {text: ["foo"]}, rootKeyProof, {inception: 2000});
    var nsec = buildEntry(dns.TYPE_NSEC, 'x.', { next:'z.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'y.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'y.')), true);
  })

  // Test against real record
  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var proof = await instance.anchors();
    for(var rrset of test_rrsets) {
      console.log(rrset[0]);
      var tx = await verifySubmission(instance, "0x" + rrset[1], "0x" + rrset[2], proof);
      assert.equal(tx.logs.length, 1);
      assert.equal(tx.logs[0].event, 'RRSetUpdated');
      proof = tx.logs[0].args.rrset;
    }
  });
});
