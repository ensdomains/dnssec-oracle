var base32hex = require('rfc4648').base32hex;
var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
    // .	105713	IN	RRSIG	DNSKEY 8 0 172800 20180811000000 20180721000000 19036 . U2thj3DQzTGRF8m2ZytqANs9YF9PYb1BQC5bDHi+d7apJve5u3Ik1cCeYg9AlW2v2vstMSUtTR0eI2mzBeZ8aBHLwPylyDhSjbe6lwxnaoZhncO4oM9bJTUha1ovCXPOoZm5dKhfI6FradAaitRfMaC7s/+XZ/DhnlLQNe08F0qepkG52RsUJZEyiQkkOK5a/hNkV5gyKdMecjtJ7eiR1w68vWwP6iGpohuLDlapbEniJXHhEysUtRJbE3EFYgwGEGeKwEQC3tDCb8ABYnbrkMg/OqhGP1cXaYfZwhEIUOvsplTdXU1tsVbPjGtbVBjy4aKLY+pjsvWuT2dzMac18A==
    // .	105713	IN	DNSKEY	256 3 8 AwEAAfaifSqh+9ItxYRCwuiY0FY2NkaEwd/zmyVvakixDgTOkgG/PUzlEauAiKzlxGwezjqbKFPSwrY3qHmbbsSTY6G8hZtna8k26eCwy59Chh573cu8qtBkmUIXMYG3fSdlUReP+uhBWBfKI2aGwhRmQYR0zSmg7PGOde34c/rOItK1ebJhjTAJ6TmnON7qMfk/lKvH4qOvYtzstLhr7Pn9ZOVLx/WUKQpU/nEyFyTduRbz1nZqkp6yMuHwWVsABK8lUYXSaUrDAsuMSldhafmR/A15BxNhv9M7mzJj7UH2RVME9JbYinBEzWwW9GpnY+ZmBWgZiRVTaDuemCTJ5ZJWLRs=
    // .	105713	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
    // .	105713	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
    [".", "003008000002a3005b6e27005b5277804a5c0000003000010002a30001080100030803010001f6a27d2aa1fbd22dc58442c2e898d05636364684c1dff39b256f6a48b10e04ce9201bf3d4ce511ab8088ace5c46c1ece3a9b2853d2c2b637a8799b6ec49363a1bc859b676bc936e9e0b0cb9f42861e7bddcbbcaad0649942173181b77d276551178ffae8415817ca236686c21466418474cd29a0ecf18e75edf873face22d2b579b2618d3009e939a738deea31f93f94abc7e2a3af62dcecb4b86becf9fd64e54bc7f594290a54fe71321724ddb916f3d6766a929eb232e1f0595b0004af255185d2694ac302cb8c4a576169f991fc0d79071361bfd33b9b3263ed41f6455304f496d88a7044cd6c16f46a6763e666056819891553683b9e9824c9e592562d1b00003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "536b618f70d0cd319117c9b6672b6a00db3d605f4f61bd41402e5b0c78be77b6a926f7b9bb7224d5c09e620f40956dafdafb2d31252d4d1d1e2369b305e67c6811cbc0fca5c838528db7ba970c676a86619dc3b8a0cf5b2535216b5a2f0973cea199b974a85f23a16b69d01a8ad45f31a0bbb3ff9767f0e19e52d035ed3c174a9ea641b9d91b1425913289092438ae5afe136457983229d31e723b49ede891d70ebcbd6c0fea21a9a21b8b0e56a96c49e22571e1132b14b5125b137105620c0610678ac04402ded0c26fc0016276eb90c83f3aa8463f57176987d9c2110850ebeca654dd5d4d6db156cf8c6b5b5418f2e1a28b63ea63b2f5ae4f677331a735f0"],

    // xyz.	79657	IN	RRSIG	DS 8 1 86400 20180813050000 20180731040000 41656 . 6rz4Umj89Skazd42RhM2QVIaOIXl+6p84ndzbAtxAYL6piNoqmw8gp8JYUpvTOkuZJi7nwV5heu7NyfP/W7Fr6UrkvEBXP5APXyYWbsGn1w3aWt+VBt2+bV3y2OSeMDhAJJXnyPSCuxCVghRh8/dcB0/H4YP9YaZUlMRhKiB6XYBfUPcSYiedT1KEULPRz03bAgdh+8+7zkNajZKcp4W+Nku+Ld3mWTtT9KdKOjvPsMt+/P8A4r2TXdxnNYTp0Yp15WRnQ/RKP9qWsxaAL8tU25/q4WqPzAGCekudO06y7qbvdr1y5wFO4TYRXgzrblkdglbXeEHbW4Ac8Dx99Fdpg==
    // xyz.	79657	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
    // xyz.	79657	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
    ["xyz.", "002b0801000151805b7110505b5fdec0a2b8000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "eabcf85268fcf5291acdde3646133641521a3885e5fbaa7ce277736c0b710182faa62368aa6c3c829f09614a6f4ce92e6498bb9f057985ebbb3727cffd6ec5afa52b92f1015cfe403d7c9859bb069f5c37696b7e541b76f9b577cb639278c0e10092579f23d20aec4256085187cfdd701d3f1f860ff5869952531184a881e976017d43dc49889e753d4a1142cf473d376c081d87ef3eef390d6a364a729e16f8d92ef8b7779964ed4fd29d28e8ef3ec32dfbf3fc038af64d77719cd613a74629d795919d0fd128ff6a5acc5a00bf2d536e7fab85aa3f300609e92e74ed3acbba9bbddaf5cb9c053b84d8457833adb96476095b5de1076d6e0073c0f1f7d15da6"],

    // xyz.	1463	IN	RRSIG	DNSKEY 8 1 3600 20180813042111 20180713194146 3599 xyz. XjAy+cxGiBUauXrUCIyo5YrMpa+0vf4b6U/K2JqtS4ZtpjH84NXj4THDLMEnA3dgxBeMUbrZTsfHdPFpsA3UqSuV0kJ6coabq6vcsXnrnUIE70yYj/qeAl61uF+f/kyY9rD750Of6BUgBC2uv3htAKEO6pGYqbdWG4kroYDX79ZQimF64vMk1aIl6wQDeB7s41xwge5Pr3eICRKD8SD1dDT7ugK3iYrz9Uwd5NM1JMw8yJGJrgTfXvSx4bNulLYGaK1Tqm/L3ET1KWLnXxjD+QTJdicEVMmzeIgzV/PLDaMox2eF7LsmHErZTNyuPQHgHtmElDyTCnRqVZ93VppVew==
    // xyz.	1463	IN	DNSKEY	256 3 8 AwEAAaPjZXskXBdJP8Vc1dtptECSfbGI0uf8448cxCKTqWN1DVbbtcHWltCveGVM5WJEIHe34kar8bjdJTqxXratPGE2Bfze6CrODUBreX+NziT0taI+z0oT+/sXmkpDWj8Fch1+afaWxaA9MaCK0pSBf4eajIp1Xm3dqvPITEVJWS/f
    // xyz.	1463	IN	DNSKEY	256 3 8 AwEAAcG3mVoA5PySdVgn2u2ocpY4cdVU5BW9CoS4jnuWLNPcb93j0NukPnb3Ejj8WispeShLzuf0Z2bRD2w5oCCd2QE9/E9Z6Dvk/lTEhBaz20jeqrfs1rc1qV5wxwQK6UiYrmmsjdqk0PQbDmebQVCB1WUwUHQGgM/JP5H87ULqx8Bj
    // xyz.	1463	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
    ["xyz.", "0030080100000e105b7107375b49007a0e0f0378797a000378797a000030000100000e1000880100030803010001a3e3657b245c17493fc55cd5db69b440927db188d2e7fce38f1cc42293a963750d56dbb5c1d696d0af78654ce562442077b7e246abf1b8dd253ab15eb6ad3c613605fcdee82ace0d406b797f8dce24f4b5a23ecf4a13fbfb179a4a435a3f05721d7e69f696c5a03d31a08ad294817f879a8c8a755e6dddaaf3c84c4549592fdf0378797a000030000100000e1000880100030803010001c1b7995a00e4fc92755827daeda872963871d554e415bd0a84b88e7b962cd3dc6fdde3d0dba43e76f71238fc5a2b2979284bcee7f46766d10f6c39a0209dd9013dfc4f59e83be4fe54c48416b3db48deaab7ecd6b735a95e70c7040ae94898ae69ac8ddaa4d0f41b0e679b415081d5653050740680cfc93f91fced42eac7c0630378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "5e3032f9cc4688151ab97ad4088ca8e58acca5afb4bdfe1be94fcad89aad4b866da631fce0d5e3e131c32cc127037760c4178c51bad94ec7c774f169b00dd4a92b95d2427a72869bababdcb179eb9d4204ef4c988ffa9e025eb5b85f9ffe4c98f6b0fbe7439fe81520042daebf786d00a10eea9198a9b7561b892ba180d7efd6508a617ae2f324d5a225eb0403781eece35c7081ee4faf7788091283f120f57434fbba02b7898af3f54c1de4d33524cc3cc89189ae04df5ef4b1e1b36e94b60668ad53aa6fcbdc44f52962e75f18c3f904c976270454c9b378883357f3cb0da328c76785ecbb261c4ad94cdcae3d01e01ed984943c930a746a559f77569a557b"],

    // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180822175132 20180723135014 55843 xyz. jHxzYyXQD1VC4ENPu7OJdfunfX6XSYqWhgfpgXnZefDdDGmdhtEX4L5ktILcQuCbDznv50OJBRsCiGVOPa+u4t59by9isqwdXWtok2TpzcJmWLN74MGolHDoS3EGp62JMLDB+qxfG0fWZLZdUutqZj5Eua+Lpnr0t+hBfYpeMOU=
    // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
    // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
    ["ethlab.xyz.", "002b080200000e105b7da2a45b55dd16da230378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "8c7c736325d00f5542e0434fbbb38975fba77d7e97498a968607e98179d979f0dd0c699d86d117e0be64b482dc42e09b0f39efe74389051b0288654e3dafaee2de7d6f2f62b2ac1d5d6b689364e9cdc26658b37be0c1a89470e84b7106a7ad8930b0c1faac5f1b47d664b65d52eb6a663e44b9af8ba67af4b7e8417d8a5e30e5"],

    // ethlab.xyz.	3599	IN	RRSIG	DNSKEY 8 2 3600 20330427133000 20180516123000 42999 ethlab.xyz. OE5dzOx68Rsi1PKOAuzo2ALP972ZNI//loIzVKtyLY9gD5nXQTYeb8+uLFqLYmnUKOHQ9PzdJINnGz2urDsjig==
    // ethlab.xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
    // ethlab.xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
    ["ethlab.xyz.", "0030080200000e10771a70585afc2448a7f7066574686c61620378797a00066574686c61620378797a000030000100000e1000480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a000030000100000e1001080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "384e5dccec7af11b22d4f28e02ece8d802cff7bd99348fff96823354ab722d8f600f99d741361e6fcfae2c5a8b6269d428e1d0f4fcdd2483671b3daeac3b238a"],

    // _ens.ethlab.xyz.	21599	IN	RRSIG	TXT 8 3 86400 20330427133000 20180516123000 42999 ethlab.xyz. cPA0WMHBwKS9kUtBRW8SiHl+/M5P/vsBPOlCcJGOREaLhsva6d5fhNLcFEG26j6gXKxhcWBb6mIPzfPAeeko1Q==
    // _ens.ethlab.xyz.	21599	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
    ["_ens.ethlab.xyz.", "0010080300015180771a70585afc2448a7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262", "70f03458c1c1c0a4bd914b41456f1288797efcce4ffefb013ce94270918e44468b86cbdae9de5f84d2dc1441b6ea3ea05cac6171605bea620fcdf3c079e928d5"]
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
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: Buffer.from("1111", "HEX")},
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 4, algorithm: 253, pubkey: Buffer.from("1111", "HEX")},
        {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 3, algorithm: 253, pubkey: Buffer.from("1112", "HEX")}
      ],
    };
  };

  it("should reject signatures with non-matching algorithms", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: "foo.bar.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: Buffer.from("1111", "HEX")}
    ];
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: Buffer.from("1112", "HEX")}
    ];
    await verifyFailedSubmission(instance, dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: Buffer.from("1211", "HEX")}
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
        {name: "net.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: Buffer.from("1111", "HEX")}
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
        labels: name.split(".").length  - 1,
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

  it('deletes RRset if NSEC is on apex domain', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.test.', {text: ["foo"]}, rootKeyProof);
    var nsec = buildEntry(dns.TYPE_NSEC, 'test.', { next:'d.test.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.test.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.test.')), false);
  })

  it('deletes RRset if NSEC next name is on apex domain', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'b.test.', {text: ["foo"]}, rootKeyProof);
    var nsec = buildEntry(dns.TYPE_NSEC, 'a.test.', { next:'test.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.test.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.test.')), false);
  })

  it('will not delete a record if it is more recent than the NSEC record', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'y.', {text: ["foo"]}, rootKeyProof, {inception: 2000});
    var nsec = buildEntry(dns.TYPE_NSEC, 'x.', { next:'z.', rrtypes:[dns.TYPE_TXT]}, {inception: 1000});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'y.', dns.hexEncodeSignedSet(nsec), rootKeyProof)), false);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'y.')), true);
  })

  it('deletes record on the same name using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'matoken.xyz.', {text: ["foo"]}, rootKeyProof)
    var nsec3 = buildEntry(dns.TYPE_NSEC3, 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz.', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:[dns.TYPE_DNSKEY]});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'matoken.xyz.', dns.hexEncodeSignedSet(nsec3), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'matoken.xyz.')), false);
  })

  it('deletes records in a zone using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'quux.matoken.xyz.', {text: ["foo"]}, rootKeyProof)
    var nsec3 = buildEntry(dns.TYPE_NSEC3, 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz.', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:[dns.TYPE_TXT]});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'quux.matoken.xyz.', dns.hexEncodeSignedSet(nsec3), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'quux.matoken.xyz.')), false);
  })


  it('deletes records at the end of a zone using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(instance, dns.TYPE_TXT, 'foo.matoken.xyz.', {text: ["foo"]}, rootKeyProof)
    var nsec3 = buildEntry(dns.TYPE_NSEC3, 'l54nruaka4b4f3mfm5scv7aocqls84gm.matoken.xyz.', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('088VBC61O9HM3QFU7VHD3AJTILP4BC5L')), rrtypes:[dns.TYPE_TXT]});
    assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'foo.matoken.xyz.', dns.hexEncodeSignedSet(nsec3), rootKeyProof)), true);
    assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'foo.matoken.xyz.')), false);
  })

  it("doesn't delete records before the range using NSEC3", async function() {
      var instance = await dnssec.deployed();
      await submitEntry(instance, dns.TYPE_TXT, '_abc.matoken.xyz.', {text: ["foo"]}, rootKeyProof)
      var nsec3 = buildEntry(dns.TYPE_NSEC3, 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz.', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:[dns.TYPE_TXT]});
      assert.equal((await deleteEntry(instance, dns.TYPE_TXT, '_abc.matoken.xyz.', dns.hexEncodeSignedSet(nsec3), rootKeyProof)), false);
      assert.equal((await checkPresence(instance, dns.TYPE_TXT, '_abc.matoken.xyz.')), true);
  })

  it("doesn't delete records after the range using NSEC3", async function() {
      var instance = await dnssec.deployed();
      await submitEntry(instance, dns.TYPE_TXT, 'foo.matoken.xyz.', {text: ["foo"]}, rootKeyProof)
      var nsec3 = buildEntry(dns.TYPE_NSEC3, 'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz.', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')), rrtypes:[dns.TYPE_TXT]});
      assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'foo.matoken.xyz.', dns.hexEncodeSignedSet(nsec3), rootKeyProof)), false);
      assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'foo.matoken.xyz.')), true);
  })

  it("doesn't delete records that aren't at the end of a zone using NSEC3", async function() {
      var instance = await dnssec.deployed();
      await submitEntry(instance, dns.TYPE_TXT, '_abc.matoken.xyz.', {text: ["foo"]}, rootKeyProof)
      var nsec3 = buildEntry(dns.TYPE_NSEC3, 'l54nruaka4b4f3mfm5scv7aocqls84gm.matoken.xyz.', {algorithm: 1, flags: 0, iterations: 1, salt: Buffer.from("5BA6AD4385844262", "hex"), nextDomain: Buffer.from(base32hex.parse('088VBC61O9HM3QFU7VHD3AJTILP4BC5L')), rrtypes:[dns.TYPE_TXT]});
      assert.equal((await deleteEntry(instance, dns.TYPE_TXT, '_abc.matoken.xyz.', dns.hexEncodeSignedSet(nsec3), rootKeyProof)), false);
      assert.equal((await checkPresence(instance, dns.TYPE_TXT, '_abc.matoken.xyz.')), true);
  })

  // Test against real record
  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var proof = await instance.anchors();
    var inputs = [];
    for(var rrset of test_rrsets) {
        var buf = Buffer.alloc(rrset[1].length / 2 + rrset[2].length / 2 + 4);
        buf.writeUInt16BE(rrset[1].length / 2, 0);
        buf.write(rrset[1], 2, rrset[1].length / 2, "hex");
        buf.writeUInt16BE(rrset[2].length / 2, rrset[1].length / 2 + 2);
        buf.write(rrset[2], rrset[1].length / 2 + 4, rrset[2].length / 2, "hex");
        inputs.push(buf);
    }
    var buf = Buffer.concat(inputs);

    var tx = await instance.submitRRSets("0x" + buf.toString("hex"), proof);
    assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
    assert.equal(tx.logs.length, test_rrsets.length);
  });
});
