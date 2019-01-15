var base32hex = require('rfc4648').base32hex;
const anchors = require("../lib/anchors.js");
const packet = require('dns-packet');
const types = require('dns-packet/types');

var dnssec = artifacts.require("./DNSSECImpl");
const Result = require('@ensdomains/dnsprovejs/dist/dns/result')

const test_rrsets = [  
  // .	172800	DNSKEY	IN	385	3	8	AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  // .	172800	DNSKEY	IN	256	3	8	AwEAAcH+axCdUOsTc9o+jmyVq5rsGTh1EcatSumPqEfsPBT+whyj0/UhD7cWeixV9Wqzj/cnqs8iWELqhdzGX41ZtaNQUfWNfOriASnWmX2D9m/EunplHu8nMSlDnDcT7+llE9tjk5HI1Sr7d9N16ZTIrbVALf65VB2ABbBG39dyAb7tz21PICJbSp2cd77UF7NFqEVkqohl/LkDw+7Apalmp0qAQT1Mgwi2cVxZMKUiciA6EqS+KNajf0A6olO2oEhZnGGY6b1LTg34/YfHdiIIZQqAfqbieruCGHRiSscC2ZE7iNreL/76f4JyIEUNkt6bQA29JsegxorLzQkpF7NKqZc=
  // .	172800	DNSKEY	IN	257	3	8	AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  // .	9184	RRSIG	IN	DNSKEY	8	0	172800	1548979200	1547164800	20326	.	Un0dZnpfRYoUo71b8ywnIF8RzcIeEboMTCAlZXUYx23xAACVyg4KHgucuYhgxyXC29QRXF/d2n/vewjW3OdI+AWh3HoSCyYq2yWaM3+8MR1IsBpZTbkAiE2ijwzIJy+dB0FJGKC64e2g/xNmFjQJD/Hdm96rbAcrW2A4WBuSmKg8qlhe60ynfx+qCn296n2ad5JBeeG2chakM8CflJKYbetrCJhraQt7rZMheloo/M8WgcKuK+/o73VeJnG5+omWvstzUTOdjZoEkPqkttFShnP3CAUaziQUcEZ8uMGKhCGq9yUaELrceoM2Dh8/YyzKXboVcJyw/29plrCJYHKduw==
  [".","0x003008000002a3005c538c005c37dc804f660000003000010002a30001080100030803010001c1fe6b109d50eb1373da3e8e6c95ab9aec19387511c6ad4ae98fa847ec3c14fec21ca3d3f5210fb7167a2c55f56ab38ff727aacf225842ea85dcc65f8d59b5a35051f58d7ceae20129d6997d83f66fc4ba7a651eef273129439c3713efe96513db639391c8d52afb77d375e994c8adb5402dfeb9541d8005b046dfd77201beedcf6d4f20225b4a9d9c77bed417b345a84564aa8865fcb903c3eec0a5a966a74a80413d4c8308b6715c5930a52272203a12a4be28d6a37f403aa253b6a048599c6198e9bd4b4e0df8fd87c7762208650a807ea6e27abb821874624ac702d9913b88dade2ffefa7f827220450d92de9b400dbd26c7a0c68acbcd092917b34aa99700003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080181030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d","0x527d1d667a5f458a14a3bd5bf32c27205f11cdc21e11ba0c4c2025657518c76df1000095ca0e0a1e0b9cb98860c725c2dbd4115c5fddda7fef7b08d6dce748f805a1dc7a120b262adb259a337fbc311d48b01a594db900884da28f0cc8272f9d07414918a0bae1eda0ff13661634090ff1dd9bdeab6c072b5b6038581b9298a83caa585eeb4ca77f1faa0a7dbdea7d9a77924179e1b67216a433c09f9492986deb6b08986b690b7bad93217a5a28fccf1681c2ae2befe8ef755e2671b9fa8996becb7351339d8d9a0490faa4b6d1528673f708051ace241470467cb8c18a8421aaf7251a10badc7a83360e1f3f632cca5dba15709cb0ff6f6996b08960729dbb"],
  
  // xyz	86400	DS	IN	3599	8	2	uXM4abyEyGu1nRArpdprJ7IIhVIzKjnc1UvE6NZrBJk=
  // xyz	86400	DS	IN	3599	8	1	P6OyZPRdtfOL7erxqIt2qjGMLH8=
  // xyz	1765	RRSIG	IN	DS	8	1	86400	1548651600	1547524800	16749	.	gsRrztEH3bUh2Cxynj/WvP9gWlYxV/Qw0LyNzJGqIAD+sA8VbLPHMsFegArnv8cmUt1qeazpjuz+otn+Tuwcof544fA72TTdIU8tQAAfq3KF1xf0FuXD/7rkYAQQ2srjVSMBttROg9ZFySAyUhnx+VJbXgTmSBbQORZD6QSOSUQ/lWMcN4eFZUSDsLhX3+GI2oaSToJKLmBX4/KUBs8CJivtbhuA3zPYtUX0Eq6xpVBuJOMqQFyZudR57OcYetBAEVZN0WdTx1MaF8YgkTd6kyJE5eVMKwtI5Md6ShsJAfDsPfhdgqPUJaUcPcVo9NlNWHfzcaKvhxxPByTVVJk5DA==
  ["xyz","0x002b0801000151805c4e8c505c3d5ac0416d000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499","0x82c46bced107ddb521d82c729e3fd6bcff605a563157f430d0bc8dcc91aa2000feb00f156cb3c732c15e800ae7bfc72652dd6a79ace98eecfea2d9fe4eec1ca1fe78e1f03bd934dd214f2d40001fab7285d717f416e5c3ffbae4600410dacae3552301b6d44e83d645c920325219f1f9525b5e04e64816d0391643e9048e49443f95631c378785654483b0b857dfe188da86924e824a2e6057e3f29406cf02262bed6e1b80df33d8b545f412aeb1a5506e24e32a405c99b9d479ece7187ad04011564dd16753c7531a17c62091377a932244e5e54c2b0b48e4c77a4a1b0901f0ec3df85d82a3d425a51c3dc568f4d94d5877f371a2af871c4f0724d55499390c"],

  // xyz	3600	DNSKEY	IN	257	3	8	AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  // xyz	3600	DNSKEY	IN	256	3	8	AwEAAZwzsrpiStLQoYSktVQQAdw/B0IKJG2l4TVJSSPBVyUDb4VcuMEFT3E18W04Pe0CfAW/Na7Um/zQAtUcdUiTLuQwxD2VX74uuNxoQkrFy2CkYrIvqwAQksWt9hOD6242c+CqbZlZbSe2IDu87ous9wTMEf88IxM8tjgglbrnwSaR
  // xyz	3600	DNSKEY	IN	256	3	8	AwEAAalt40QoyM4leOWv7i75lMm29RHqMDt6YNNpOJH/Fc+h3cafnvSJqNziLuJUF+z73C2pfkTG3N4oDXrqo2LdrFG0EJmZjY3tHrmVZsdX8HUSkoVJDxJf70xX4A5DbOw4VZ9iq3NpC7SFra+XaMZ00zr5leonBvVrUw+jrdGDB7X1
  // xyz	927	RRSIG	IN	DNSKEY	8	1	3600	1549637105	1547069086	3599	xyz	YsyVhpJW1XEsb0nU99ZIsueDVpq0/E3jHWGyHmFZYcRvxaCsfWScQoMr/ggRbkr2cjuu555s/rwJz04mrMDVm5gFoUSHEUt1LWUcEuGdHPSLNajvAygy+5yNQyu3R/WjLaVg+Zj7HKxHdhfOop+OWBB07MAycqO//BWJEtaVnWoaqfhpi5SWsHeeAO/rKBegR0u40/KFN+jSdWGLSbqtb1JPfJbUoKKuSTRicxacvMKvUOqletHulmpbHCAIcUUE8ShSPI2cb3XZGlfTsJ1kr7Ub83i5odAmbsd7JHsuQWpe1f9Q4AJ4ErmfSWcImLAyIh8GpvwkkW+jWTnnAc4MAw==
  ["xyz","0x0030080100000e105c5d95f15c36669e0e0f0378797a000378797a000030000100000e10008801000308030100019c33b2ba624ad2d0a184a4b5541001dc3f07420a246da5e135494923c15725036f855cb8c1054f7135f16d383ded027c05bf35aed49bfcd002d51c7548932ee430c43d955fbe2eb8dc68424ac5cb60a462b22fab001092c5adf61383eb6e3673e0aa6d99596d27b6203bbcee8bacf704cc11ff3c23133cb6382095bae7c126910378797a000030000100000e1000880100030803010001a96de34428c8ce2578e5afee2ef994c9b6f511ea303b7a60d3693891ff15cfa1ddc69f9ef489a8dce22ee25417ecfbdc2da97e44c6dcde280d7aeaa362ddac51b41099998d8ded1eb99566c757f075129285490f125fef4c57e00e436cec38559f62ab73690bb485adaf9768c674d33af995ea2706f56b530fa3add18307b5f50378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983","0x62cc95869256d5712c6f49d4f7d648b2e783569ab4fc4de31d61b21e615961c46fc5a0ac7d649c42832bfe08116e4af6723baee79e6cfebc09cf4e26acc0d59b9805a14487114b752d651c12e19d1cf48b35a8ef032832fb9c8d432bb747f5a32da560f998fb1cac477617cea29f8e581074ecc03272a3bffc158912d6959d6a1aa9f8698b9496b0779e00efeb2817a0474bb8d3f28537e8d275618b49baad6f524f7c96d4a0a2ae49346273169cbcc2af50eaa57ad1ee966a5b1c2008714504f128523c8d9c6f75d91a57d3b09d64afb51bf378b9a1d0266ec77b247b2e416a5ed5ff50e0027812b99f49670898b032221f06a6fc24916fa35939e701ce0c03"],

  // ethlab.xyz	3600	DS	IN	42999	8	2	lUwCGjjlcx66qpUyP7fEcqhmzk2GrjrYYFhDtyK2IhM=
  // ethlab.xyz	3600	DS	IN	60820	8	2	0c3PjpBe0G/sQ4pjxpo00vSHGx9Iabu4UoWYkuaTyu0=
  // ethlab.xyz	1632	RRSIG	IN	DS	8	2	3600	1548068114	1545481309	48208	xyz	D7pvPD/VLFvhM+bFH0pgD07I41AXoK76Zj01KfAwQc6L3Z3IHUgqf0CxQx8Zq50wyGhUNUDpEtr9Rriqc2JGxMeX2lLdpHhIA8oMYOePbwuWAlOldEFPzhN9ZhnrS63+WoT1Q6/yZd2TN9q0VbLY0cF5HCuw5Oqow0qMC+CYGsE=
  ["ethlab.xyz","0x002b080200000e105c45a5125c1e2c5dbc500378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed","0x0fba6f3c3fd52c5be133e6c51f4a600f4ec8e35017a0aefa663d3529f03041ce8bdd9dc81d482a7f40b1431f19ab9d30c868543540e912dafd46b8aa736246c4c797da52dda4784803ca0c60e78f6f0b960253a574414fce137d6619eb4badfe5a84f543aff265dd9337dab455b2d8d1c1791c2bb0e4eaa8c34a8c0be0981ac1"],
  // ethlab.xyz	3600	DNSKEY	IN	256	3	8	AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
  // ethlab.xyz	3600	DNSKEY	IN	257	3	8	AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
  // ethlab.xyz	1632	RRSIG	IN	DNSKEY	8	2	3600	1998221400	1526473800	42999	ethlab.xyz	OE5dzOx68Rsi1PKOAuzo2ALP972ZNI//loIzVKtyLY9gD5nXQTYeb8+uLFqLYmnUKOHQ9PzdJINnGz2urDsjig==
  
  ["ethlab.xyz","0x0030080200000e10771a70585afc2448a7f7066574686c61620378797a00066574686c61620378797a000030000100000e1000480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a000030000100000e1001080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141","0x384e5dccec7af11b22d4f28e02ece8d802cff7bd99348fff96823354ab722d8f600f99d741361e6fcfae2c5a8b6269d428e1d0f4fcdd2483671b3daeac3b238a"],

  // _ens.ethlab.xyz	86400	TXT	IN	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
  // _ens.ethlab.xyz	3520	RRSIG	IN	TXT	8	3	86400	1998221400	1526473800	42999	ethlab.xyz	cPA0WMHBwKS9kUtBRW8SiHl+/M5P/vsBPOlCcJGOREaLhsva6d5fhNLcFEG26j6gXKxhcWBb6mIPzfPAeeko1Q==
  ["_ens.ethlab.xyz","0x0010080300015180771a70585afc2448a7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262","0x70f03458c1c1c0a4bd914b41456f1288797efcce4ffefb013ce94270918e44468b86cbdae9de5f84d2dc1441b6ea3ea05cac6171605bea620fcdf3c079e928d5"]
]

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

  // Test against real record
  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var proof = await instance.anchors();
    for (let i = 0; i < test_rrsets.length; i++) {
      var rrset = test_rrsets[i];
      var tx = await instance.submitRRSet(rrset[1], rrset[2], proof);
      proof = tx.logs[0].args.rrset;
      assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
    }
  });
});
