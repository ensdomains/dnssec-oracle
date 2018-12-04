var base32hex = require('rfc4648').base32hex;
var dns = require("../lib/dns.js");
const anchors = require("../lib/anchors.js");
const packet = require('dns-packet');
const types = require('dns-packet/types');

var dnssec = artifacts.require("./DNSSECImpl");
const Result = require('@ensdomains/dnsprovejs/dist/dns/result')

const test_rrsets = [
    // .	125194	IN	RRSIG	DNSKEY 8 0 172800 20180910000000 20180820000000 19036 . R5LO5NN4JIYfd2dUeqGoVSuJVhYgkaPpmZCdOP5c9fyhD8mSjVFt38GW8HuY4slXE0uXCYdix5KfPIdS4np+pAYjNcrbO4zm73XdKBAKhwP0L5OyRn5t9ceuk9E7OxjgEv45AhLJ0pMYQQ4UVyUNfBf+RYMEGV6jK9HJqfmGkRQKIp+RiH9Ql2vLmOYehmAxQ3y0HMQfDyu++MBRNQN8ES/BFTRi+UcKiAep9fQ1qkmrPa1FCgVej6WT0yHCW1hCsl1mOHQNQ2kGDAq3+SIWl5Moec+l88f4Cargio/PiIsVPaK3yet1sXiLG++5T572C2NYY8sQlEQozzqcrHJdZA==
    // .	125194	IN	DNSKEY	256 3 8 AwEAAfaifSqh+9ItxYRCwuiY0FY2NkaEwd/zmyVvakixDgTOkgG/PUzlEauAiKzlxGwezjqbKFPSwrY3qHmbbsSTY6G8hZtna8k26eCwy59Chh573cu8qtBkmUIXMYG3fSdlUReP+uhBWBfKI2aGwhRmQYR0zSmg7PGOde34c/rOItK1ebJhjTAJ6TmnON7qMfk/lKvH4qOvYtzstLhr7Pn9ZOVLx/WUKQpU/nEyFyTduRbz1nZqkp6yMuHwWVsABK8lUYXSaUrDAsuMSldhafmR/A15BxNhv9M7mzJj7UH2RVME9JbYinBEzWwW9GpnY+ZmBWgZiRVTaDuemCTJ5ZJWLRs=
    // .	125194	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
    // .	125194	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
    [".", "003008000002a3005b95b4005b7a04804a5c0000003000010002a30001080100030803010001f6a27d2aa1fbd22dc58442c2e898d05636364684c1dff39b256f6a48b10e04ce9201bf3d4ce511ab8088ace5c46c1ece3a9b2853d2c2b637a8799b6ec49363a1bc859b676bc936e9e0b0cb9f42861e7bddcbbcaad0649942173181b77d276551178ffae8415817ca236686c21466418474cd29a0ecf18e75edf873face22d2b579b2618d3009e939a738deea31f93f94abc7e2a3af62dcecb4b86becf9fd64e54bc7f594290a54fe71321724ddb916f3d6766a929eb232e1f0595b0004af255185d2694ac302cb8c4a576169f991fc0d79071361bfd33b9b3263ed41f6455304f496d88a7044cd6c16f46a6763e666056819891553683b9e9824c9e592562d1b00003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "4792cee4d37824861f7767547aa1a8552b8956162091a3e999909d38fe5cf5fca10fc9928d516ddfc196f07b98e2c957134b97098762c7929f3c8752e27a7ea4062335cadb3b8ce6ef75dd28100a8703f42f93b2467e6df5c7ae93d13b3b18e012fe390212c9d29318410e1457250d7c17fe458304195ea32bd1c9a9f98691140a229f91887f50976bcb98e61e866031437cb41cc41f0f2bbef8c05135037c112fc1153462f9470a8807a9f5f435aa49ab3dad450a055e8fa593d321c25b5842b25d6638740d4369060c0ab7f9221697932879cfa5f3c7f809aae08a8fcf888b153da2b7c9eb75b1788b1befb94f9ef60b635863cb10944428cf3a9cac725d64"],

    // xyz.	84109	IN	RRSIG	DS 8 1 86400 20180906050000 20180824040000 41656 . SpxwxdhBLQhHVsjaOoLiJ+t9l62x5/18gHE/DrUk5Kf3DqdQBlqASb5MFsLiLQLkS8Nz2MM0NKcsRvE3H8V2zycQmKFWaZ5E7kP3f9JKBLhAiqf80JzbbZNiD0FUBpAMyIQwtZoxxX2rkaXBrHhI7GYn1n7FkX964obM7Rx2+IaZWYsFV70wpaLyqaZUSvzf2jaZQ+NmEqb207vxer1lASPuTU7s+4eRFkK1lLoWKFA1nD0VfcZ+ypwifl8907Ha3rdMn0WQYtBjNCB91057+mSSArw6JgvqBqnJn6ABpypiimAOmHjXqM4hQvi0BCkLxO7OGjedyHSRoagMFSjSjA==
    // xyz.	84109	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
    // xyz.	84109	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
    ["xyz.", "002b0801000151805b90b4505b7f82c0a2b8000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "4a9c70c5d8412d084756c8da3a82e227eb7d97adb1e7fd7c80713f0eb524e4a7f70ea750065a8049be4c16c2e22d02e44bc373d8c33434a72c46f1371fc576cf271098a156699e44ee43f77fd24a04b8408aa7fcd09cdb6d93620f415406900cc88430b59a31c57dab91a5c1ac7848ec6627d67ec5917f7ae286cced1c76f88699598b0557bd30a5a2f2a9a6544afcdfda369943e36612a6f6d3bbf17abd650123ee4d4eecfb87911642b594ba162850359c3d157dc67eca9c227e5f3dd3b1dadeb74c9f459062d06334207dd74e7bfa649202bc3a260bea06a9c99fa001a72a628a600e9878d7a8ce2142f8b404290bc4eece1a379dc87491a1a80c1528d28c"],

    // xyz.	3545	IN	RRSIG	DNSKEY 8 1 3600 20180912090853 20180812194519 3599 xyz. dpIwGsySlIOJmUqVt6yo5KmLDWgQztWrCoa4cc9ZJpMcNiddLRxYQjWVXHFl/4tv2FoClU34I1XNvpzNWADdCY1s7AUFBNA3BzC8qpQ847Prp1pAwvdH/SUf5AGonbV6JxuOJ7lvD4fGclSzDZdsE69sKscmo486iQ8ZZ8ohcybsqtGuiTNWxjUpa3gtmb5sbSBAj8Q4yPIYKQBwz6la9Wn4tPC+KV+nSuKD6GQHluHWcG39BQp2ka1HrvTUP2pDQEIGwAHnPuX8Vi1SJGSM1y7YomkYeW9ulh6pImAmZXyb17BwA3BTC5ZpWKNbh1jsYHkt6B2g6X2lcOc/s7yCyQ==
    // xyz.	3545	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
    // xyz.	3545	IN	DNSKEY	256 3 8 AwEAAaPjZXskXBdJP8Vc1dtptECSfbGI0uf8448cxCKTqWN1DVbbtcHWltCveGVM5WJEIHe34kar8bjdJTqxXratPGE2Bfze6CrODUBreX+NziT0taI+z0oT+/sXmkpDWj8Fch1+afaWxaA9MaCK0pSBf4eajIp1Xm3dqvPITEVJWS/f
    // xyz.	3545	IN	DNSKEY	256 3 8 AwEAAegu7evMCIeBNauXbva/MmD9ClUXMqXh8h7Yd3W69xkqNkQ2twqHL85eBqYVUThxjB4nGA2n7Rd+jdXHciVBg8iyajuoAVDzMN7PxPhrweMgYzCWxhq8Hq1gokwvEDCkyk6Obeylyk5pjIyQLUUaKcuhcu93SZjXiV3tLq3HkUpb
    ["xyz.", "0030080100000e105b98d7a55b708e4f0e0f0378797a000378797a000030000100000e1000880100030803010001a3e3657b245c17493fc55cd5db69b440927db188d2e7fce38f1cc42293a963750d56dbb5c1d696d0af78654ce562442077b7e246abf1b8dd253ab15eb6ad3c613605fcdee82ace0d406b797f8dce24f4b5a23ecf4a13fbfb179a4a435a3f05721d7e69f696c5a03d31a08ad294817f879a8c8a755e6dddaaf3c84c4549592fdf0378797a000030000100000e1000880100030803010001e82eedebcc08878135ab976ef6bf3260fd0a551732a5e1f21ed87775baf7192a364436b70a872fce5e06a6155138718c1e27180da7ed177e8dd5c772254183c8b26a3ba80150f330decfc4f86bc1e320633096c61abc1ead60a24c2f1030a4ca4e8e6deca5ca4e698c8c902d451a29cba172ef774998d7895ded2eadc7914a5b0378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "7692301acc92948389994a95b7aca8e4a98b0d6810ced5ab0a86b871cf5926931c36275d2d1c584235955c7165ff8b6fd85a02954df82355cdbe9ccd5800dd098d6cec050504d0370730bcaa943ce3b3eba75a40c2f747fd251fe401a89db57a271b8e27b96f0f87c67254b30d976c13af6c2ac726a38f3a890f1967ca217326ecaad1ae893356c635296b782d99be6c6d20408fc438c8f218290070cfa95af569f8b4f0be295fa74ae283e8640796e1d6706dfd050a7691ad47aef4d43f6a43404206c001e73ee5fc562d5224648cd72ed8a26918796f6e961ea9226026657c9bd7b0700370530b966958a35b8758ec60792de81da0e97da570e73fb3bc82c9"],

    // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180918170733 20180819155629 20868 xyz. R8Oy4n86eyr2cWdaluWOwWCRsOeFfFMxCDA2tbBFYM5qYVEIAJC1ogCNzCZMGiE6S7UBCT3XH67s/aW+gAUjWvXbmU+6pPy0jOYTx8uz/z1b19Kv7TQeKUoiJ6wCuXocOdzd/koOaA96qqrPAvt2CKnR6jVmhoJZct2aazQE7N4=
    // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
    // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
    ["ethlab.xyz.", "002b080200000e105ba130d55b79932d51840378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "47c3b2e27f3a7b2af671675a96e58ec16091b0e7857c5331083036b5b04560ce6a6151080090b5a2008dcc264c1a213a4bb501093dd71faeecfda5be8005235af5db994fbaa4fcb48ce613c7cbb3ff3d5bd7d2afed341e294a2227ac02b97a1c39dcddfe4a0e680f7aaaaacf02fb7608a9d1ea356686825972dd9a6b3404ecde"],

    // ethlab.xyz.	3599	IN	RRSIG	DNSKEY 8 2 3600 20330427133000 20180516123000 42999 ethlab.xyz. OE5dzOx68Rsi1PKOAuzo2ALP972ZNI//loIzVKtyLY9gD5nXQTYeb8+uLFqLYmnUKOHQ9PzdJINnGz2urDsjig==
    // ethlab.xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
    // ethlab.xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
    ["ethlab.xyz.", "0030080200000e10771a70585afc2448a7f7066574686c61620378797a00066574686c61620378797a000030000100000e1000480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a000030000100000e1001080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "384e5dccec7af11b22d4f28e02ece8d802cff7bd99348fff96823354ab722d8f600f99d741361e6fcfae2c5a8b6269d428e1d0f4fcdd2483671b3daeac3b238a"],

    // _ens.ethlab.xyz.	21599	IN	RRSIG	TXT 8 3 86400 20330427133000 20180516123000 42999 ethlab.xyz. cPA0WMHBwKS9kUtBRW8SiHl+/M5P/vsBPOlCcJGOREaLhsva6d5fhNLcFEG26j6gXKxhcWBb6mIPzfPAeeko1Q==
    // _ens.ethlab.xyz.	21599	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
    ["_ens.ethlab.xyz.", "0010080300015180771a70585afc2448a7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262", "70f03458c1c1c0a4bd914b41456f1288797efcce4ffefb013ce94270918e44468b86cbdae9de5f84d2dc1441b6ea3ea05cac6171605bea620fcdf3c079e928d5"]
];

function hexEncodeSignedSet(keys){
  return (new Result([keys])).proofs[0].toSubmit();
}

function hexEncodeName(name){
  return '0x' + packet.name.encode(name).toString('hex');
}

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
    var name = '.';
    var sig = {
      name: '.',
      type: 'RRSIG',
      ttl: 0,
      class: 'IN',
      flush: false,
      data:
      {
        typeCovered: 'DNSKEY',
        algorithm: 253,
        labels: 0,
        originalTTL: 3600,
        expiration: 0xFFFFFFFF,
        inception: 0,
        keyTag: 5647,
        signersName: ".",
        signature: new Buffer([])
      }
    }

    var rrs = [
      {
        name: ".", type: 'DNSKEY', class: 'IN', ttl: 3600,
        data:{flags: 0x0101, algorithm: 253, key: Buffer.from("1111", "HEX")}
      },
      {
        name: ".", type: 'DNSKEY', class: 'IN', ttl: 3600,
        data:{flags: 0, algorithm: 253, key: Buffer.from("1111", "HEX")}
      },
      {
        name: ".", type: 'DNSKEY', class: 'IN', ttl: 3600,
        data:{flags: 0, algorithm: 253, key: Buffer.from("1112", "HEX")}
      }
    ]
    return { name, sig, rrs }
  }

  it("should reject signatures with non-matching algorithms", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.forEach((r)=>{r.data.algorithm = 255})
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();

    keys.rrs = [{
      name: ".", type: 'DNSKEY', class: 'IN', ttl: 3600,
      data:{flags: 0x0101, protocol: 3, algorithm: 253, key: Buffer.from("1112", "HEX")}
    }];

    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [{
      name: ".", type: 'DNSKEY', class: 'IN', ttl: 3600,
      data:{flags: 0x0001, protocol: 3, algorithm: 253, key: Buffer.from("1211", "HEX")}
    }];

    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  var rootKeyProof = undefined;
  it('should accept a root DNSKEY', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    var tx = await verifySubmission(instance, ...hexEncodeSignedSet(keys));
    rootKeyProof = tx.logs[0].args.rrset;
  });

  it('should check if root DNSKEY exist', async function(){
    var instance = await dnssec.deployed();
    var [_, _, rrs] = await instance.rrdata.call(types.toType('DNSKEY'), hexEncodeName('nonexisting.'));
    assert.equal(rrs, '0x0000000000000000000000000000000000000000');
    [_, _, rrs] = await instance.rrdata.call(types.toType('DNSKEY'), hexEncodeName('.'));
    assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
  })

  it('should accept a signed RRSET', async function() {
    var instance = await dnssec.deployed();
    await verifySubmission(instance, hexEncodeSignedSet({
      name:'test',
      sig:{
        name: 'test',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'TXT',
          algorithm: 253,
          labels: 1,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 1,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "test", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('test', 'ascii')}],
    })[0], "0x", rootKeyProof);
  });

  it('should reject signatures with non-matching classes', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet({
      name:'net',
      sig:{
        name: 'net',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'TXT',
          algorithm: 253,
          labels: 1,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 0,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "net", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('foo', 'ascii')}],
    }));
  })

  it('should reject signatures with non-matching names', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, 
    ...hexEncodeSignedSet({
      name:'foo.net',
      sig:{
        name: 'foo.net',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'TXT',
          algorithm: 253,
          labels: 1,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 0,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "foo.net", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('foo', 'ascii')}],
    }));
  });

  it('should reject signatures with the wrong type covered', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet({
      name:'net',
      sig:{
        name: 'net',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'DS',
          algorithm: 253,
          labels: 1,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 0,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "net", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('foo', 'ascii')}],
    }));
  });

  it('should reject signatures with too many labels', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet({
      name:'net',
      sig:{
        name: 'net',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'TXT',
          algorithm: 253,
          labels: 2,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 0,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "net", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('foo', 'ascii')}],
    }));
  });

  it('should reject signatures with invalid signer names', async function() {
    var instance = await dnssec.deployed();
    await verifySubmission(instance, hexEncodeSignedSet({
      name:'test',
      sig:{
        name: 'test',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'TXT',
          algorithm: 253,
          labels: 1,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 1,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "test", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('test', 'ascii')}],
    })[0], "0x", rootKeyProof);
    await verifyFailedSubmission(instance, hexEncodeSignedSet({
      name:'test',
      sig:{
        name: 'test',
        type: 'RRSIG',
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: 'TXT',
          algorithm: 253,
          labels: 1,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 1,
          keyTag: 5647,
          signersName: "com",
          signature: new Buffer([])
        }
      },
      rrs:[{name: "test", type: 'TXT', class: 'IN', ttl: 3600, data:Buffer.from('test', 'ascii')}],
    })[0], "0x", rootKeyProof);
  });

  it("should reject entries with expirations in the past", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.inception = 1;
    keys.sig.data.expiration = 123;
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it("should reject entries with inceptions in the future", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.inception = 0xFFFFFFFF;
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it("should accept updates with newer signatures", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.inception = 1;
    await verifySubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it("should reject entries that are older", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.inception = 0;
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should reject invalid RSA signatures', async function() {
    var instance = await dnssec.deployed();
    var sig = test_rrsets[0][2];
    await verifyFailedSubmission(instance, "0x" + test_rrsets[0][1], "0x" + sig.slice(0, sig.length - 2) + "FF");
  });

  // Test delete RRSET
  async function checkPresence(instance, type, name){
    var result = (await instance.rrdata.call(types.toType(type), hexEncodeName(name)))[2];
    return result != '0x0000000000000000000000000000000000000000';
  }

  function buildEntry(type, name, rrsOption, sigOption) {
      var rrs = [{name: name, type: type, class: 'IN', ttl: 3600, data:rrsOption}];
      var sig = {
        name: name,
        type: type,
        ttl: 0,
        class: 'IN',
        flush: false,
        data:{
          typeCovered: type,
          algorithm: 253,
          labels: name.split(".").length,
          originalTTL: 3600,
          expiration: 0xFFFFFFFF,
          inception: 1,
          keyTag: 5647,
          signersName: ".",
          signature: new Buffer([])
        }        
      }

      if(sigOption !== undefined) {
        Object.assign(sig.data, sigOption);
      }
      var keys = {name, rrs, sig}
      return keys;
  }

  async function submitEntry(instance, type, name, option, proof, sig){
    var keys = buildEntry(type, name, option, sig);
    var [inception, _, rrs] = await instance.rrdata.call(types.toType(type), hexEncodeName(name));
    if(inception >= keys.sig.data.inception) {
        keys.sig.data.inception = inception + 1;
    }
    tx = await verifySubmission(instance, hexEncodeSignedSet(keys)[0], "0x", proof);
    var res = await instance.rrdata.call(types.toType(type), hexEncodeName(name));
    assert.notEqual(res[2], '0x0000000000000000000000000000000000000000');
    return tx;
  }

  async function deleteEntry(instance, deletetype, deletename, nsec, proof) {
    var tx, result;
    try{
      tx = await instance.deleteRRSet(types.toType(deletetype), hexEncodeName(deletename), nsec, "0x", proof);
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
    await submitEntry(instance, 'TXT',  'b', Buffer.from('foo', 'ascii'), rootKeyProof);
    // Submit with a proof for an irrelevant record.
    assert.equal((await deleteEntry(instance, 'TXT', 'b', hexEncodeSignedSet(rootKeys())[0], rootKeyProof)), false);
    assert.equal((await checkPresence(instance, 'TXT', 'b')), true);
  })

  it('rejects if next record does not come before the deleting name', async function(){
    var instance = await dnssec.deployed();
    // text z. comes after next d.
    await submitEntry(instance, 'TXT',  'z', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'z', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
    assert.equal((await checkPresence(instance, 'TXT', 'z')), true);

  })

  it('rejects if nsec record starts after the deleting name', async function(){
    var instance = await dnssec.deployed();
    // text a. comes after nsec b.
    await submitEntry(instance, 'TXT',  'a', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'b', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
    assert.equal((await checkPresence(instance, 'TXT', 'a')), true);
  })

  it('rejects RRset if trying to delete rrset that is in the type bitmap', async function(){
    var instance = await dnssec.deployed();
    // text a. has same nsec a. with type bitmap
    await submitEntry(instance, 'TXT',  'a', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
    assert.equal((await checkPresence(instance, 'TXT', 'a')), true);
  })

  it('deletes RRset if nsec name and delete name are the same but with different rrtypes', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT',  'a', Buffer.from('foo', 'ascii'), rootKeyProof);
    // This test fails if rrtypes is empty ([]), but would that case every happen?
    var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['NSEC']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'a')), false);
  })

  it('rejects if the proof hash does not match', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT',  'a', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['NSEC']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0] + '00', rootKeyProof)), false);
    assert.equal((await checkPresence(instance, 'TXT', 'a')), true);
  })

  it('deletes RRset if NSEC next comes after delete name', async function(){
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT', 'b', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'b', hexEncodeSignedSet(nsec)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'b')), false);
  })

  it('deletes RRset if NSEC is on apex domain', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT', 'b.test', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'test', { nextDomain:'d.test', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'b.test', hexEncodeSignedSet(nsec)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'b.test')), false);
  })

  it('deletes RRset if NSEC next name is on apex domain', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT', 'b.test', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec = buildEntry('NSEC', 'a.test', { nextDomain:'test', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'b.test', hexEncodeSignedSet(nsec)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'b.test')), false);
  })

  it('will not delete a record if it is more recent than the NSEC record', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT', 'y', Buffer.from('foo', 'ascii'), rootKeyProof, {inception: 2000});
    var nsec = buildEntry('NSEC', 'x', { nextDomain:'z', rrtypes:['TXT']}, {inception: 1000});
    assert.equal((await deleteEntry(instance, 'TXT', 'y', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
    assert.equal((await checkPresence(instance, 'TXT', 'y')), true);
  })

  it('deletes record on the same name using NSEC3', async function() {
    var instance = await dnssec.deployed();
  
    await submitEntry(instance, 'TXT', 'matoken.xyz', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec3 = buildEntry(
      'NSEC3',
      'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from("5BA6AD4385844262", "hex"),
        nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')),
        rrtypes:['DNSKEY']
      }
    );
    assert.equal((await deleteEntry(instance, 'TXT', 'matoken.xyz', hexEncodeSignedSet(nsec3)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'matoken.xyz')), false);
  })

  it('deletes records in a zone using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT', 'quux.matoken.xyz', Buffer.from('foo', 'ascii'), rootKeyProof);
    var nsec3 = buildEntry('NSEC3', 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:['TXT']});
    assert.equal((await deleteEntry(instance, 'TXT', 'quux.matoken.xyz', hexEncodeSignedSet(nsec3)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'quux.matoken.xyz')), false);
  })

  it('deletes records at the end of a zone using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, 'TXT', 'foo.matoken.xyz', Buffer.from('foo', 'ascii'), rootKeyProof)
    var nsec3 = buildEntry('NSEC3', 'l54nruaka4b4f3mfm5scv7aocqls84gm.matoken.xyz', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('088VBC61O9HM3QFU7VHD3AJTILP4BC5L')), rrtypes:['TXT']});
    assert.equal((await deleteEntry(instance, 'TXT', 'foo.matoken.xyz', hexEncodeSignedSet(nsec3)[0], rootKeyProof)), true);
    assert.equal((await checkPresence(instance, 'TXT', 'foo.matoken.xyz')), false);
  })

  it("doesn't delete records before the range using NSEC3", async function() {
      var instance = await dnssec.deployed();
      await submitEntry(instance, 'TXT', '_abc.matoken.xyz', Buffer.from('foo', 'ascii'), rootKeyProof)
      var nsec3 = buildEntry('NSEC3', 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:['TXT']});
      assert.equal((await deleteEntry(instance, 'TXT', '_abc.matoken.xyz', hexEncodeSignedSet(nsec3)[0], rootKeyProof)), false);
      assert.equal((await checkPresence(instance, 'TXT', '_abc.matoken.xyz')), true);
  })

  it("doesn't delete records after the range using NSEC3", async function() {
      var instance = await dnssec.deployed();
      await submitEntry(instance, 'TXT', 'foo.matoken.xyz', Buffer.from('foo', 'ascii'), rootKeyProof)
      var nsec3 = buildEntry('NSEC3', 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:['TXT']});
      assert.equal((await deleteEntry(instance, 'TXT', 'foo.matoken.xyz', hexEncodeSignedSet(nsec3)[0], rootKeyProof)), false);
      assert.equal((await checkPresence(instance, 'TXT', 'foo.matoken.xyz')), true);
  })

  it("doesn't delete records that aren't at the end of a zone using NSEC3", async function() {
      var instance = await dnssec.deployed();
      await submitEntry(instance, 'TXT', '_abc.matoken.xyz', Buffer.from('foo', 'ascii'), rootKeyProof)
      var nsec3 = buildEntry('NSEC3', 'l54nruaka4b4f3mfm5scv7aocqls84gm.matoken.xyz', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('088VBC61O9HM3QFU7VHD3AJTILP4BC5L')), rrtypes:['TXT']});
      assert.equal((await deleteEntry(instance, 'TXT', '_abc.matoken.xyz', hexEncodeSignedSet(nsec3)[0], rootKeyProof)), false);
      assert.equal((await checkPresence(instance, 'TXT', '_abc.matoken.xyz')), true);
  })

  // // Test against real record
  // it('should accept real DNSSEC records', async function() {
  //   var instance = await dnssec.deployed();
  //   var proof = await instance.anchors();
  //   var inputs = [];
  //   for(var rrset of test_rrsets) {
  //       var buf = Buffer.alloc(rrset[1].length / 2 + rrset[2].length / 2 + 4);
  //       buf.writeUInt16BE(rrset[1].length / 2, 0);
  //       buf.write(rrset[1], 2, rrset[1].length / 2, "hex");
  //       buf.writeUInt16BE(rrset[2].length / 2, rrset[1].length / 2 + 2);
  //       buf.write(rrset[2], rrset[1].length / 2 + 4, rrset[2].length / 2, "hex");
  //       inputs.push(buf);
  //   }
  //   var buf = Buffer.concat(inputs);

  //   var tx = await instance.submitRRSets("0x" + buf.toString("hex"), proof);
  //   assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
  //   assert.equal(tx.logs.length, test_rrsets.length);
  // });
});
