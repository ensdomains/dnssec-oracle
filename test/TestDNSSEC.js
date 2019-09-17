var base32hex = require('rfc4648').base32hex;
const anchors = require('../lib/anchors.js');
const packet = require('dns-packet');
const types = require('dns-packet/types');

var dnssec = artifacts.require('./DNSSECImpl');
const Result = require('@ensdomains/dnsprovejs/dist/dns/result');

const util = require('util');
web3.currentProvider.send = util.promisify(web3.currentProvider.send);

// When the real test start failing due to ttl expiration, you can generate the new test dataset at https://dnssec.ens.domains/?domain=ethlab.xyz&mode=advanced
let test_rrsets = [
  // .	55430	IN	RRSIG	DNSKEY 8 0 172800 20190402000000 20190312000000 20326 . A76nZ8WVsD+pLAKJh9ujKxxRDWfJf8SxayOkq3Gq9TX4BStpQM1e/KuX8am4FrVRCGQvLlhiYFNqm+PtevGGJAO0lTFLSiIuavknlkSiI3HMkrMDqSV+YlIQPk1C720khNpWy70WjjNvkq4sBU1GTkVPeFkM3gQI53pCHW+VobCPXZz70J+PnSOq7SmjrwXgU8E9iSXkI3yfhGIup2c54Sf9w0Bw10opvxXMT+1ALgWY1TnV1/gRixIUZp1K86iR8VeX9K/4UTqEa5bYux+aeIcQ2/4Qqyo3Ocb2RrbUvDNzU2lB4b1r/oHqsd6C0SiGmdo0A8R44djKMHVaD/JmLg==
  // .	55430	IN	DNSKEY	256 3 8 AwEAAcH+axCdUOsTc9o+jmyVq5rsGTh1EcatSumPqEfsPBT+whyj0/UhD7cWeixV9Wqzj/cnqs8iWELqhdzGX41ZtaNQUfWNfOriASnWmX2D9m/EunplHu8nMSlDnDcT7+llE9tjk5HI1Sr7d9N16ZTIrbVALf65VB2ABbBG39dyAb7tz21PICJbSp2cd77UF7NFqEVkqohl/LkDw+7Apalmp0qAQT1Mgwi2cVxZMKUiciA6EqS+KNajf0A6olO2oEhZnGGY6b1LTg34/YfHdiIIZQqAfqbieruCGHRiSscC2ZE7iNreL/76f4JyIEUNkt6bQA29JsegxorLzQkpF7NKqZc=
  // .	55430	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  // .	55430	IN	DNSKEY	385 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  [
    web3.utils.toHex('.'),
    '0x003008000002a3005ca2a6005c86f6804f660000003000010002a30001080100030803010001c1fe6b109d50eb1373da3e8e6c95ab9aec19387511c6ad4ae98fa847ec3c14fec21ca3d3f5210fb7167a2c55f56ab38ff727aacf225842ea85dcc65f8d59b5a35051f58d7ceae20129d6997d83f66fc4ba7a651eef273129439c3713efe96513db639391c8d52afb77d375e994c8adb5402dfeb9541d8005b046dfd77201beedcf6d4f20225b4a9d9c77bed417b345a84564aa8865fcb903c3eec0a5a966a74a80413d4c8308b6715c5930a52272203a12a4be28d6a37f403aa253b6a048599c6198e9bd4b4e0df8fd87c7762208650a807ea6e27abb821874624ac702d9913b88dade2ffefa7f827220450d92de9b400dbd26c7a0c68acbcd092917b34aa99700003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080181030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d',
    '0x03bea767c595b03fa92c028987dba32b1c510d67c97fc4b16b23a4ab71aaf535f8052b6940cd5efcab97f1a9b816b55108642f2e586260536a9be3ed7af1862403b495314b4a222e6af9279644a22371cc92b303a9257e6252103e4d42ef6d2484da56cbbd168e336f92ae2c054d464e454f78590cde0408e77a421d6f95a1b08f5d9cfbd09f8f9d23aaed29a3af05e053c13d8925e4237c9f84622ea76739e127fdc34070d74a29bf15cc4fed402e0598d539d5d7f8118b1214669d4af3a891f15797f4aff8513a846b96d8bb1f9a788710dbfe10ab2a3739c6f646b6d4bc3373536941e1bd6bfe81eab1de82d1288699da3403c478e1d8ca30755a0ff2662e'
  ],

  // xyz.	75722	IN	RRSIG	DS 8 1 86400 20190326170000 20190313160000 16749 . b8+qL5kCQQ1cXJ3WtMffVlB9DhDYjcaJLq3YMU7JKfBUO9NDiSPWx2ugrWsXdgzr+ZCmnYJ3kcFK0kqhq/hklCKai16f+XxRlw/TLRG1O1pgBt5zyb3eklEwqqJkeq2sx4n74i5zPArNsIOdkDtqreBza2cWAEyBrfCgyVmoMIjqXgM7Nc7hEGueHJ/qxCcDKGB5hzuvzgl1Nhj8FpuLOEC0SsrEULrOytTVwas/H3aoQtdWoAiKnU1Dr0VtdxtdMl1kZcZZQmLvJHlsZC8YaF8ur+d+N7SP6MMTNyWv1II0OMrznnkbYC+h/p+3l1oZjWW0CPD4KaTmoXhYxiFt4w==
  // xyz.	75722	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
  // xyz.	75722	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
  [
    web3.utils.toHex('xyz.'),
    '0x002b0801000151805c9a5a905c892900416d000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499',
    '0x6fcfaa2f9902410d5c5c9dd6b4c7df56507d0e10d88dc6892eadd8314ec929f0543bd3438923d6c76ba0ad6b17760cebf990a69d827791c14ad24aa1abf86494229a8b5e9ff97c51970fd32d11b53b5a6006de73c9bdde925130aaa2647aadacc789fbe22e733c0acdb0839d903b6aade0736b6716004c81adf0a0c959a83088ea5e033b35cee1106b9e1c9feac42703286079873bafce09753618fc169b8b3840b44acac450bacecad4d5c1ab3f1f76a842d756a0088a9d4d43af456d771b5d325d6465c6594262ef24796c642f18685f2eafe77e37b48fe8c3133725afd4823438caf39e791b602fa1fe9fb7975a198d65b408f0f829a4e6a17858c6216de3'
  ],

  // xyz.	3599	IN	RRSIG	DNSKEY 8 1 3600 20190410030245 20190310213458 3599 xyz. IDV9fvByi5DC37UAe7gYuxJDjo6nAoz58e4EmeCFsX1RjjLjmOR2juGv80AY5rDRZq1F8hCGcCL0JpgCm3m/I/r6CkqRhFMRDCQmjv3X4otEGeIDPSyiTDA9wkiH01IqtozMrff/Px2jwnRojP7xqIF79ySX1mjHTAX0LsdoJiUNA7WYlyT6F3QrrlghgyHR01RcozY4/bGKGL5Ko7FW3Aul1NOhFHBTIkaCCWbKJrXCNg0fkRPfFS8IUxxmDghf8SvCe8E9CjE9K283gUy/SVaqe4uwcph71Uer0fDTdqPHdEQ1SNZwXC3wd+hwTbkAra/an3My9twMW5Gzcc1kYA==
  // xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdkudvbXI30VVqraORIz7iVP4GX5jLvYI1vk1f8JJnvLNW9Gnsd8W4jne3PrkIIgoBeHJG1GC+5zo4Deusc8KVbQNjfL3TnuQF5iS8tkqnyqEUqHt2Rm+JHglrX0eIqftBjegf0WBTCVJIE/KqiC/X2EXr83/sAmrF5SchoEM2gx
  // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAa5jh93mWraaokFC83dqjRLypC8KijEI9DpGCL9epWGcZoEg2QpFRNaJuYjxASKjqF04TXZFOPLgSLMS6fPy6Cx4cBy4K392cbHBJafUnAecmHd4WJauED8q5OU+AnZbD07J424L9CszIXKFBBIeUXyNVhSgFszjZevNRie/Jk3v
  [
    web3.utils.toHex('xyz.'),
    '0x0030080100000e105cad5cd55c8583020e0f0378797a000378797a000030000100000e1000880100030803010001ae6387dde65ab69aa24142f3776a8d12f2a42f0a8a3108f43a4608bf5ea5619c668120d90a4544d689b988f10122a3a85d384d764538f2e048b312e9f3f2e82c78701cb82b7f7671b1c125a7d49c079c9877785896ae103f2ae4e53e02765b0f4ec9e36e0bf42b3321728504121e517c8d5614a016cce365ebcd4627bf264def0378797a000030000100000e1000880100030803010001d92e76f6d7237d1556aada391233ee254fe065f98cbbd8235be4d5ff09267bcb356f469ec77c5b88e77b73eb908220a01787246d460bee73a380debac73c2956d03637cbdd39ee405e624bcb64aa7caa114a87b76466f891e096b5f4788a9fb418de81fd1605309524813f2aa882fd7d845ebf37fec026ac5e52721a043368310378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983',
    '0x20357d7ef0728b90c2dfb5007bb818bb12438e8ea7028cf9f1ee0499e085b17d518e32e398e4768ee1aff34018e6b0d166ad45f210867022f42698029b79bf23fafa0a4a918453110c24268efdd7e28b4419e2033d2ca24c303dc24887d3522ab68cccadf7ff3f1da3c274688cfef1a8817bf72497d668c74c05f42ec76826250d03b5989724fa17742bae58218321d1d3545ca33638fdb18a18be4aa3b156dc0ba5d4d3a11470532246820966ca26b5c2360d1f9113df152f08531c660e085ff12bc27bc13d0a313d2b6f37814cbf4956aa7b8bb072987bd547abd1f0d376a3c774443548d6705c2df077e8704db900adafda9f7332f6dc0c5b91b371cd6460'
  ],

  // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20190412084119 20190313062929 53709 xyz. QYtNoU4SsRpKcSeH1UUJNwJAADRW+LNx4an35z25tb+Cw0y51sKP/2FS8gD47XReZ5mmYE1E6DWLmPbizPOAUibfLZad+zKjRyrGm59rbeSetLdDD1zKw7Wa5CB2a+wFi0AVGwO0pMqxE/N2E1SEPbPUdsroMGTgBxBf/ON0YL4=
  // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
  // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
  [
    web3.utils.toHex('ethlab.xyz.'),
    '0x002b080200000e105cb04f2f5c88a349d1cd0378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed',
    '0x418b4da14e12b11a4a712787d54509370240003456f8b371e1a9f7e73db9b5bf82c34cb9d6c28fff6152f200f8ed745e6799a6604d44e8358b98f6e2ccf3805226df2d969dfb32a3472ac69b9f6b6de49eb4b7430f5ccac3b59ae420766bec058b40151b03b4a4cab113f3761354843db3d476cae83064e007105ffce37460be'
  ],

  // ethlab.xyz.	3599	IN	RRSIG	DNSKEY 8 2 3600 20340214222653 20190305212653 42999 ethlab.xyz. DIouYhqzqxxN7fAQN8VYCSkXKFzuv1P964uctDaIfk/7BbCePJ3s3omGywNzH0/+Vzwa34AV0thIOphmLFqSQw==
  // ethlab.xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
  // ethlab.xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
  [
    web3.utils.toHex('ethlab.xyz.'),
    '0x0030080200000e10789d35ad5c7ee99da7f7066574686c61620378797a00066574686c61620378797a000030000100000e1000480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a000030000100000e1001080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141',
    '0x0c8a2e621ab3ab1c4dedf01037c558092917285ceebf53fdeb8b9cb436887e4ffb05b09e3c9decde8986cb03731f4ffe573c1adf8015d2d8483a98662c5a9243'
  ],

  // _ens.ethlab.xyz.	21599	IN	RRSIG	TXT 8 3 86400 20340214222653 20190305212653 42999 ethlab.xyz. cK9JLb6gBKY7oJi2E+94a0Eii8k4nirIKgginKID3FD7B0lVn6I0499nKzLVCWQtFc3Hnte9JaUrz4GvP3mBTA==
  // _ens.ethlab.xyz.	21599	IN	TXT	"a=0xfdb33f8ac7ce72d7d4795dd8610e323b4c122fbb"
  [
    web3.utils.toHex('_ens.ethlab.xyz.'),
    '0x0010080300015180789d35ad5c7ee99da7f7066574686c61620378797a00045f656e73066574686c61620378797a000010000100015180002d2c613d307866646233336638616337636537326437643437393564643836313065333233623463313232666262',
    '0x70af492dbea004a63ba098b613ef786b41228bc9389e2ac82a08229ca203dc50fb0749559fa234e3df672b32d509642d15cdc79ed7bd25a52bcf81af3f79814c'
  ]
];


test_rrsets = [
  //   .	172800	DNSKEY	IN	257	3	8	AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  //   .	172800	DNSKEY	IN	256	3	8	AwEAAcTQyaIe6nt3xSPOG2L/YfwBkOVTJN6mlnZ249O5Rtt3ZSRQHxQSW61AODYw6bvgxrrGq8eeOuenFjcSYgNAMcBYoEYYmKDW6e9EryW4ZaT/MCq+8Am06oR40xAA3fClOM6QjRcT85tP41Go946AicBGP8XOP/Aj1aI/oPRGzRnboUPUok/AzTNnW5npBU69+BuiIwYE7mQOiNBFePyvjQBdoiuYbmuD3Py0IyjlBxzZUXbqLsRL9gYFkCqeTY29Ik7usuzMTa+JRSLz6KGS5RSJ7CTSMjZg8aNaUbN2dvGhakJPh92HnLvMA3TefFgbKJphFNPA3BWSKLZ02cRWXqM=
  //   .	10750	RRSIG	IN	DNSKEY	8	0	172800	1569801600	1567987200	20326	.	cFdPAQZXPVRy3XFI23vFrMEDD2H8F/r+B5Hgw7p4D6vYyy7R3Ueuk2db3Oeqspd1acgwK3CC76N0pdq5kdtfJBc4KBkE29LDAmcRrU9NLDIfzgfSpXntnMhw943G3gRGHnA71WQoBXkSYQ475VVImuyEBZmg4aqWmy9taWKoQdEk4gN0/ckAocqdBL6NWvrRCdjc8i0hsJ4oWhDpp0bThlFSCeLY+ie/6EUbnnlVRqSVPYdYxrCr2SQvoVgOaxbw5VAQvsHSu7OecPv+MPTYr2lpJpWdhtp7OcBaS0ap8jCnYwbjGhczfsHHuYHe7iikv/uq2xqsqhdRIvjbGPbE/w==
  [web3.utils.toHex("."),"0x003008000002a3005d9145805d7596004f660000003000010002a30001080100030803010001c4d0c9a21eea7b77c523ce1b62ff61fc0190e55324dea6967676e3d3b946db776524501f14125bad40383630e9bbe0c6bac6abc79e3ae7a716371262034031c058a0461898a0d6e9ef44af25b865a4ff302abef009b4ea8478d31000ddf0a538ce908d1713f39b4fe351a8f78e8089c0463fc5ce3ff023d5a23fa0f446cd19dba143d4a24fc0cd33675b99e9054ebdf81ba2230604ee640e88d04578fcaf8d005da22b986e6b83dcfcb42328e5071cd95176ea2ec44bf60605902a9e4d8dbd224eeeb2eccc4daf894522f3e8a192e51489ec24d2323660f1a35a51b37676f1a16a424f87dd879cbbcc0374de7c581b289a6114d3c0dc159228b674d9c4565ea300003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5","0x70574f0106573d5472dd7148db7bc5acc1030f61fc17fafe0791e0c3ba780fabd8cb2ed1dd47ae93675bdce7aab2977569c8302b7082efa374a5dab991db5f241738281904dbd2c3026711ad4f4d2c321fce07d2a579ed9cc870f78dc6de04461e703bd56428057912610e3be555489aec840599a0e1aa969b2f6d6962a841d124e20374fdc900a1ca9d04be8d5afad109d8dcf22d21b09e285a10e9a746d386515209e2d8fa27bfe8451b9e795546a4953d8758c6b0abd9242fa1580e6b16f0e55010bec1d2bbb39e70fbfe30f4d8af696926959d86da7b39c05a4b46a9f230a76306e31a17337ec1c7b981deee28a4bffbaadb1aacaa175122f8db18f6c4ff"],
  
  //   xyz	86400	DS	IN	3599	8	1	P6OyZPRdtfOL7erxqIt2qjGMLH8=
  //   xyz	86400	DS	IN	3599	8	2	uXM4abyEyGu1nRArpdprJ7IIhVIzKjnc1UvE6NZrBJk=
  //   xyz	10266	RRSIG	IN	DS	8	1	86400	1569733200	1568606400	59944	.	od+yphoKkUdV3KmzhEw0jPacNkvA5oHRS6I8Ys3f4Wr9VGJUJ2Z9FwKRhnx4Uj+rMvKqQqpODuKFNPcWAVzgQnKJJP99VX+peSZnrxoe20BjJlFILr5G7vXcLD2hErcPjwFTyBbxu7Y/UMQFHnCNrMkR7r0Mi0lJxwy70x0+IH28D3rfZ2scV7Fri5F3ZUh5lQH56j53yYAomVuPoD2T0LqEz2X2nFdomO0AfBut1SJKWCNbmkh6o2unSrAqmsJ4Y/JtVoLhRIc64+UMzHSrwI6gKmRePflWn7zL9SzGzAw4EfCgyaLCFCNGQN4DdCXfAs2CaBkDUsOvwJEfDjFBfw==
  [web3.utils.toHex("xyz"),"0x002b0801000151805d903a505d7f08c0ea28000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499","0xa1dfb2a61a0a914755dca9b3844c348cf69c364bc0e681d14ba23c62cddfe16afd54625427667d170291867c78523fab32f2aa42aa4e0ee28534f716015ce042728924ff7d557fa9792667af1a1edb40632651482ebe46eef5dc2c3da112b70f8f0153c816f1bbb63f50c4051e708dacc911eebd0c8b4949c70cbbd31d3e207dbc0f7adf676b1c57b16b8b91776548799501f9ea3e77c98028995b8fa03d93d0ba84cf65f69c576898ed007c1badd5224a58235b9a487aa36ba74ab02a9ac27863f26d5682e144873ae3e50ccc74abc08ea02a645e3df9569fbccbf52cc6cc0c3811f0a0c9a2c214234640de037425df02cd8268190352c3afc0911f0e31417f"],
  
  //   xyz	3600	DNSKEY	IN	257	3	8	AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  //   xyz	3600	DNSKEY	IN	256	3	8	AwEAAZtZDWAQtt6eTNlxWURKrnwYhss1eoDzF471kW6BpcrEp7xBn18FLztiDPkBCQxygD2O3JPDpaiyX1isZF9XyNdwBW7WxTcA8BMyKM2Cqo+I8Qhb8VQHMaytiR60PVVktPyPzlXwPf70hLmfDxmmxBYfMh+P9Y44YanUSvMKLbpF
  //   xyz	3600	DNSKEY	IN	256	3	8	AwEAAdh4DkQ6rcrDF74QvZj2Xta1V5nANqB6m5bKfL53gvsVSUPRSTlRskIk9SNSKs0NhDyBxlew/l30Yao58hn7EthunsLV5LikY8dg2oHIZKWlOl5zx5K9S3IAIRPgyim0K+dcfm3ffIcpMBRsilf094C9tnb3y5omKkREVdSKWeyh
  //   xyz	3066	RRSIG	IN	DNSKEY	8	1	3600	1570422737	1567809316	3599	xyz	EOrrOMSLWg90AKjafe9haoznfwP37mKU2q5o1azwoauq4mT3vAgdf7wb9+vAHFhqgqNdZLjPmhLjwQXLKuQ+TD6iZjwKg8DZPM/rBn/PxyLNRVrjLGTt0C137NpEU8n2whyz6blNS3fxNiXDuVfZq+Qty3cb/HmLk00+QLARx2xRnC1rnMbFRDpHOz0XXq1pwmBk7has4zg4xTgMnqatHuiDN2/6Z2TYDRqFqVvNZ+13cyJdhgb6tuxcOj73P4wTjy/2NpyfEA+toklTZdl5Y8q+2HcWmvzVq23H6QpeIxrLbhaR4d3q5RGugFUCJpidIp7ljyBabkqAOrGH/6SauA==
  [web3.utils.toHex("xyz"),"0x0030080100000e105d9abfd15d72df240e0f0378797a000378797a000030000100000e10008801000308030100019b590d6010b6de9e4cd97159444aae7c1886cb357a80f3178ef5916e81a5cac4a7bc419f5f052f3b620cf901090c72803d8edc93c3a5a8b25f58ac645f57c8d770056ed6c53700f0133228cd82aa8f88f1085bf1540731acad891eb43d5564b4fc8fce55f03dfef484b99f0f19a6c4161f321f8ff58e3861a9d44af30a2dba450378797a000030000100000e1000880100030803010001d8780e443aadcac317be10bd98f65ed6b55799c036a07a9b96ca7cbe7782fb154943d1493951b24224f523522acd0d843c81c657b0fe5df461aa39f219fb12d86e9ec2d5e4b8a463c760da81c864a5a53a5e73c792bd4b72002113e0ca29b42be75c7e6ddf7c872930146c8a57f4f780bdb676f7cb9a262a444455d48a59eca10378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983","0x10eaeb38c48b5a0f7400a8da7def616a8ce77f03f7ee6294daae68d5acf0a1abaae264f7bc081d7fbc1bf7ebc01c586a82a35d64b8cf9a12e3c105cb2ae43e4c3ea2663c0a83c0d93ccfeb067fcfc722cd455ae32c64edd02d77ecda4453c9f6c21cb3e9b94d4b77f13625c3b957d9abe42dcb771bfc798b934d3e40b011c76c519c2d6b9cc6c5443a473b3d175ead69c26064ee16ace33838c5380c9ea6ad1ee883376ffa6764d80d1a85a95bcd67ed7773225d8606fab6ec5c3a3ef73f8c138f2ff6369c9f100fada2495365d97963cabed877169afcd5ab6dc7e90a5e231acb6e1691e1ddeae511ae80550226989d229ee58f205a6e4a803ab187ffa49ab8"],
  
  //   matoken.xyz	3600	DS	IN	37042	8	2	zyoXTFVzCFldvxA5sMWZkDfQSy52TEi9Vb3BzUjquMo=
  //   matoken.xyz	3600	RRSIG	IN	DS	8	2	3600	1570527972	1567930730	11401	xyz	Ypq2oPKgZD2FeKGHsjlGVGKGCDyle7y3pG1fFfJKthjl0z3uwF3mbTLQk0Vpl8uKmnGlaI0j3DP9bSAsRZkEJ0O10bFNaWuXG2+VSpon3ocbpIPOUYVJkzzX4ZpwwxErU4+K7EhC32SRB9E/qyIxQeG1WZhrTIbyxOwCRZkOHEc=
  [web3.utils.toHex("matoken.xyz"),"0x002b080200000e105d9c5ae45d74b96a2c890378797a00076d61746f6b656e0378797a00002b000100000e10002490b20802cf2a174c557308595dbf1039b0c5999037d04b2e764c48bd55bdc1cd48eab8ca","0x629ab6a0f2a0643d8578a187b23946546286083ca57bbcb7a46d5f15f24ab618e5d33deec05de66d32d093456997cb8a9a71a5688d23dc33fd6d202c4599042743b5d1b14d696b971b6f954a9a27de871ba483ce518549933cd7e19a70c3112b538f8aec4842df649107d13fab223141e1b559986b4c86f2c4ec0245990e1c47"],
  
  //   matoken.xyz	300	DNSKEY	IN	257	3	8	AwEAAaUPT5a7Ch5cTVkcgDVrf9FCMxCMA+7McAz2x4933N8dFqqC+9OH4yAwoQW+VjXzLF4pbw4mdHuJXMSDaN1I0YrrglEfKtwaH5NacJW4UMoyF9MW5GAoS0XoZzw2ISOOOPCOphhQdc0T9SfG5pSPTvvPMXOZm9KFR99c+jiAwT4mjJut52Mu7b5I4nsUDKQBnOnDFt4fDv2DOSI+yVbdC0swX0bZXSD382GX4+ValNf6Yjz8a1SGtabkv5/PTlMxaHUwqqesqjMVYpnQ1J7bZxlzmfBLfk5A1hpSG8kBNM/ZFUsqRNz+8nOORUvsNrbQLkIEjfduCOUza630ON3ivpE=
  //   matoken.xyz	300	DNSKEY	IN	256	3	8	AwEAAY6LVhxJdhiGG6lRtDBXMRkaiQFmbbRc+/HkD5gn4ZvpUvoZFnHBUoQ9ffN9HN5r3M6Hiuln2CqakGHt09lawk0QnNR54YZiQt/C1XBVBXvTqAG3mcerOizzOZeurCLwPrkybODfOlmNg0HXdczJM2F7x4Rr1xiqvNL/nibWxoJB
  //   matoken.xyz	300	RRSIG	IN	DNSKEY	8	2	300	1570289035	1568388235	37042	matoken.xyz	RyIkEZ3RIolISnNviNgN7ZxNDUhmhJsHmPHOMVCYx1Hz82f8tNTT4XIXHi9az/sSw+EuV5trmYZSYSImaTCKq+z719sqSjJqgfhcsvK5E+hXYZP0s305OmjJJgaDpI+KpWRkg+3jR4yEXRmg9OUBuBqhonFNW/wqSzrkWats9sad7Fjc+zIvwHkeO/tR4jssLOuEWQna2U5F8nMYNCRJ0RoZgFFdKjGX77fnwO/faSamuHeFhZe1dCJUmSdRPeqb4FYY+w0XuaDljSysg785+ccORy4hCQy0gbw/9POzy0wDssIvlgiaI73/42P0uo+dX7sij6AkVuK3OUxjk9lUBA==
  [web3.utils.toHex("matoken.xyz"),"0x003008020000012c5d98b58b5d7bb48b90b2076d61746f6b656e0378797a00076d61746f6b656e0378797a00003000010000012c008801000308030100018e8b561c497618861ba951b4305731191a8901666db45cfbf1e40f9827e19be952fa191671c152843d7df37d1cde6bdcce878ae967d82a9a9061edd3d95ac24d109cd479e1866242dfc2d57055057bd3a801b799c7ab3a2cf33997aeac22f03eb9326ce0df3a598d8341d775ccc933617bc7846bd718aabcd2ff9e26d6c68241076d61746f6b656e0378797a00003000010000012c01080101030803010001a50f4f96bb0a1e5c4d591c80356b7fd14233108c03eecc700cf6c78f77dcdf1d16aa82fbd387e32030a105be5635f32c5e296f0e26747b895cc48368dd48d18aeb82511f2adc1a1f935a7095b850ca3217d316e460284b45e8673c3621238e38f08ea6185075cd13f527c6e6948f4efbcf3173999bd28547df5cfa3880c13e268c9bade7632eedbe48e27b140ca4019ce9c316de1f0efd8339223ec956dd0b4b305f46d95d20f7f36197e3e55a94d7fa623cfc6b5486b5a6e4bf9fcf4e5331687530aaa7acaa33156299d0d49edb67197399f04b7e4e40d61a521bc90134cfd9154b2a44dcfef2738e454bec36b6d02e42048df76e08e5336badf438dde2be91","0x472224119dd12289484a736f88d80ded9c4d0d4866849b0798f1ce315098c751f3f367fcb4d4d3e172171e2f5acffb12c3e12e579b6b99865261222669308aabecfbd7db2a4a326a81f85cb2f2b913e8576193f4b37d393a68c9260683a48f8aa5646483ede3478c845d19a0f4e501b81aa1a2714d5bfc2a4b3ae459ab6cf6c69dec58dcfb322fc0791e3bfb51e23b2c2ceb845909dad94e45f27318342449d11a1980515d2a3197efb7e7c0efdf6926a6b877858597b57422549927513dea9be05618fb0d17b9a0e58d2cac83bf39f9c70e472e21090cb481bc3ff4f3b3cb4c03b2c22f96089a23bdffe363f4ba8f9d5fbb228fa02456e2b7394c6393d95404"],
  
  //   _ens.matoken.xyz	300	TXT	IN	"a=0xfFD1Ac3e8818AdCbe5C597ea076E8D3210B45df5"
  //   _ens.matoken.xyz	300	RRSIG	IN	TXT	8	3	300	1570289035	1568388235	62926	matoken.xyz	Nrcsg6vHpV8KAxB+GBfycDFPE+YbRNZF2ZciMntB2Ji3eq2FvPjRkYyF4THGYr7+KZudjv++++RkF83U2CLMC3JyPDO9XzeWo34p5NzoYcaNpPnjobvCjvcNDuzt+XB0d3PYlPqDktbUSg7fo6VMFJRIRKUw760wkKFsTZ4CJEs=
  [web3.utils.toHex("_ens.matoken.xyz") ,"0x001008030000012c5d98b58b5d7bb48bf5ce076d61746f6b656e0378797a00045f656e73076d61746f6b656e0378797a00001000010000012c002d2c613d307866464431416333653838313841644362653543353937656130373645384433323130423435646635","0x36b72c83abc7a55f0a03107e1817f270314f13e61b44d645d99722327b41d898b77aad85bcf8d1918c85e131c662befe299b9d8effbefbe46417cdd4d822cc0b72723c33bd5f3796a37e29e4dce861c68da4f9e3a1bbc28ef70d0eecedf970747773d894fa8392d6d44a0edfa3a54c14944844a530efad3090a16c4d9e02244b"],]


function hexEncodeSignedSet(keys) {
  return new Result([keys]).proofs[0].toSubmit();
}

function hexEncodeName(name) {
  return '0x' + packet.name.encode(name).toString('hex');
}

async function verifySubmission(instance, data, sig, proof) {
  if (proof === undefined) {
    proof = await instance.anchors();
  }

  var tx = await instance.submitRRSet(data, sig, proof);

  assert.equal(tx.receipt.status, true);
  assert.equal(tx.logs.length, 1);
  return tx;
}

async function verifyFailedSubmission(instance, data, sig, proof) {
  if (proof === undefined) {
    proof = await instance.anchors();
  }

  try {
    var tx = await instance.submitRRSet(data, sig, proof);
  } catch (error) {
    // @TODO use: https://github.com/ensdomains/root/blob/master/test/helpers/Utils.js#L8
    // Assert ganache revert exception
    assert.equal(
      error.message,
      'Returned error: VM Exception while processing transaction: revert'
    );
  }

  // Assert geth failed transaction
  if (tx !== undefined) {
    assert.equal(tx.receipt.status, false);
  }
}

contract('DNSSEC', function(accounts) {
  before(async () => {
    const instance = await dnssec.deployed();
    const keys = rootKeys();
    const [signedData] = hexEncodeSignedSet(keys);
    await instance.submitRRSet(
      signedData,
      Buffer.alloc(0),
      anchors.encode(anchors.realEntries)
    );
  });

  let result;
  beforeEach(async () => {
    ({ result } = await web3.currentProvider.send({
      method: 'evm_snapshot'
    }));
  });
  afterEach(async () => {
    await web3.currentProvider.send({
      method: 'evm_revert',
      params: result
    });
  });

  it('should have a default algorithm and digest set', async function() {
    var instance = await dnssec.deployed();
    assert.notEqual(
      await instance.algorithms(8),
      '0x0000000000000000000000000000000000000000'
    );
    assert.notEqual(
      await instance.algorithms(253),
      '0x0000000000000000000000000000000000000000'
    );
    assert.notEqual(
      await instance.digests(2),
      '0x0000000000000000000000000000000000000000'
    );
    assert.notEqual(
      await instance.digests(253),
      '0x0000000000000000000000000000000000000000'
    );
  });

  const validityPeriod = 2419200;
  const expiration = Date.now() / 1000 - 15 * 60 + validityPeriod;
  const inception = Date.now() / 1000 - 15 * 60;
  function rootKeys() {
    var name = '.';
    var sig = {
      name: '.',
      type: 'RRSIG',
      ttl: 0,
      class: 'IN',
      flush: false,
      data: {
        typeCovered: 'DNSKEY',
        algorithm: 253,
        labels: 0,
        originalTTL: 3600,
        expiration,
        inception,
        keyTag: 1278,
        signersName: '.',
        signature: new Buffer([])
      }
    };

    var rrs = [
      {
        name: '.',
        type: 'DNSKEY',
        class: 'IN',
        ttl: 3600,
        data: { flags: 0, algorithm: 253, key: Buffer.from('0000', 'HEX') }
      },
      {
        name: '.',
        type: 'DNSKEY',
        class: 'IN',
        ttl: 3600,
        data: { flags: 0, algorithm: 253, key: Buffer.from('1112', 'HEX') }
      },
      {
        name: '.',
        type: 'DNSKEY',
        class: 'IN',
        ttl: 3600,
        data: { flags: 0x0101, algorithm: 253, key: Buffer.from('0000', 'HEX') }
      }
    ];
    return { name, sig, rrs };
  }

  it('should reject signatures with non-matching algorithms', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.forEach(r => {
      r.data.algorithm = 255;
    });
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should reject signatures with non-matching keytags', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();

    keys.rrs = [
      {
        name: '.',
        type: 'DNSKEY',
        class: 'IN',
        ttl: 3600,
        data: {
          flags: 0x0101,
          protocol: 3,
          algorithm: 253,
          key: Buffer.from('1112', 'HEX')
        }
      }
    ];

    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should accept odd-length public keys', async () => {
    const instance = await dnssec.deployed();
    const keys = rootKeys();
    keys.rrs = [
      {
        name: '.',
        type: 'DNSKEY',
        data: {
          flags: 257,
          algorithm: 253,
          key: Buffer.from('00', 'hex')
        }
      }
    ];
    const [signedData] = hexEncodeSignedSet(keys);
    await verifySubmission(instance, signedData, Buffer.alloc(0));
  });

  it('should reject signatures by keys without the ZK bit set', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {
        name: '.',
        type: 'DNSKEY',
        class: 'IN',
        ttl: 3600,
        data: {
          flags: 0x0001,
          protocol: 3,
          algorithm: 253,
          key: Buffer.from('1211', 'HEX')
        }
      }
    ];

    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  const { rrs } = rootKeys();
  const rootKeyProof = anchors.encode(rrs);
  it('should accept a root DNSKEY', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    await verifySubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should check if root DNSKEY exist', async function() {
    var instance = await dnssec.deployed();
    var result = await instance.rrdata.call(
      types.toType('DNSKEY'),
      hexEncodeName('nonexisting.')
    );
    var rrs = result['2'];
    assert.equal(rrs, '0x0000000000000000000000000000000000000000');
    result = await instance.rrdata.call(
      types.toType('DNSKEY'),
      hexEncodeName('.')
    );
    rrs = result['2'];
    assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
  });

  it('should accept a signed RRSET', async function() {
    var instance = await dnssec.deployed();
    await verifySubmission(
      instance,
      hexEncodeSignedSet({
        name: 'test',
        sig: {
          name: 'test',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'TXT',
            algorithm: 253,
            labels: 1,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: '.',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'test',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('test', 'ascii')
          }
        ]
      })[0],
      '0x',
      rootKeyProof
    );
  });

  it('should reject signatures with non-matching classes', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(
      instance,
      ...hexEncodeSignedSet({
        name: 'net',
        sig: {
          name: 'net',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'TXT',
            algorithm: 253,
            labels: 1,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: '.',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'net',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('foo', 'ascii')
          }
        ]
      })
    );
  });

  it('should reject signatures with non-matching names', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(
      instance,
      ...hexEncodeSignedSet({
        name: 'foo.net',
        sig: {
          name: 'foo.net',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'TXT',
            algorithm: 253,
            labels: 1,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: '.',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'foo.net',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('foo', 'ascii')
          }
        ]
      })
    );
  });

  it('should reject signatures with the wrong type covered', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(
      instance,
      ...hexEncodeSignedSet({
        name: 'net',
        sig: {
          name: 'net',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'DS',
            algorithm: 253,
            labels: 1,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: '.',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'net',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('foo', 'ascii')
          }
        ]
      })
    );
  });

  it('should reject signatures with too many labels', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(
      instance,
      ...hexEncodeSignedSet({
        name: 'net',
        sig: {
          name: 'net',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'TXT',
            algorithm: 253,
            labels: 2,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: '.',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'net',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('foo', 'ascii')
          }
        ]
      })
    );
  });

  it('should reject signatures with invalid signer names', async function() {
    var instance = await dnssec.deployed();
    await verifySubmission(
      instance,
      hexEncodeSignedSet({
        name: 'test',
        sig: {
          name: 'test',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'TXT',
            algorithm: 253,
            labels: 1,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: '.',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'test',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('test', 'ascii')
          }
        ]
      })[0],
      '0x',
      rootKeyProof
    );
    await verifyFailedSubmission(
      instance,
      hexEncodeSignedSet({
        name: 'test',
        sig: {
          name: 'test',
          type: 'RRSIG',
          ttl: 0,
          class: 'IN',
          flush: false,
          data: {
            typeCovered: 'TXT',
            algorithm: 253,
            labels: 1,
            originalTTL: 3600,
            expiration,
            inception,
            keyTag: 1278,
            signersName: 'com',
            signature: new Buffer([])
          }
        },
        rrs: [
          {
            name: 'test',
            type: 'TXT',
            class: 'IN',
            ttl: 3600,
            data: Buffer.from('test', 'ascii')
          }
        ]
      })[0],
      '0x',
      rootKeyProof
    );
  });

  it('should reject entries with expirations in the past', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.expiration = Date.now() / 1000 - 2;
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should reject entries with inceptions in the future', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.inception = Date.now() / 1000 + 15 * 60;
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should accept updates with newer signatures', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    await verifySubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('updates the inception whether the RRs/hash have changed or not', async () => {
    const instance = await dnssec.deployed();
    const keys = rootKeys();
    keys.sig.data.inception++;
    const [signedData] = hexEncodeSignedSet(keys);
    const [oldInception] = Object.values(
      await instance.rrdata(
        types.toType('DNSKEY'),
        `0x${packet.name.encode('.').toString('hex')}`
      )
    );
    assert.notEqual(oldInception, keys.sig.data.inception >>> 0);
    await instance.submitRRSet(
      signedData,
      Buffer.alloc(0),
      anchors.encode(anchors.realEntries)
    );
    const [newInception] = Object.values(
      await instance.rrdata(
        types.toType('DNSKEY'),
        `0x${packet.name.encode('.').toString('hex')}`
      )
    );
    assert.equal(newInception, keys.sig.data.inception >>> 0);
  });

  it('should reject entries that are older', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.sig.data.inception--;
    await verifyFailedSubmission(instance, ...hexEncodeSignedSet(keys));
  });

  it('should reject invalid RSA signatures', async function() {
    var instance = await dnssec.deployed();
    var sig = test_rrsets[0][2];
    await verifyFailedSubmission(
      instance,
      test_rrsets[0][1],
      sig.slice(0, sig.length - 2) + 'FF'
    );
  });

  // Test delete RRSET
  async function checkPresence(instance, type, name) {
    var result = (await instance.rrdata.call(
      types.toType(type),
      hexEncodeName(name)
    ))[2];
    return result != '0x0000000000000000000000000000000000000000';
  }

  function buildEntry(type, name, rrsOption, sigOption) {
    var rrs = [
      { name: name, type: type, class: 'IN', ttl: 3600, data: rrsOption }
    ];
    var sig = {
      name: name,
      type: type,
      ttl: 0,
      class: 'IN',
      flush: false,
      data: {
        typeCovered: type,
        algorithm: 253,
        labels: name.split('.').length,
        originalTTL: 3600,
        expiration,
        inception,
        keyTag: 1278,
        signersName: '.',
        signature: new Buffer([])
      }
    };

    if (sigOption !== undefined) {
      Object.assign(sig.data, sigOption);
    }
    var keys = { name, rrs, sig };
    return keys;
  }

  async function submitEntry(instance, type, name, option, proof, sig) {
    var keys = buildEntry(type, name, option, sig);
    tx = await verifySubmission(
      instance,
      hexEncodeSignedSet(keys)[0],
      '0x',
      proof
    );
    var res = await instance.rrdata.call(
      types.toType(type),
      hexEncodeName(name)
    );
    assert.notEqual(res['2'], '0x0000000000000000000000000000000000000000');
    return tx;
  }

  async function deleteEntry(instance, deletetype, deletename, nsec, proof) {
    var tx, result;
    try {
      tx = await instance.deleteRRSet(
        types.toType(deletetype),
        hexEncodeName(deletename),
        nsec,
        '0x',
        proof
      );
    } catch (error) {
      result = false;
    }
    // Assert geth failed transaction
    if (tx !== undefined) {
      result = tx.receipt.status;
    }
    return result;
  }

  it('rejects if a proof with the wrong type is supplied', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'b',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    // Submit with a proof for an irrelevant record.
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'b',
        hexEncodeSignedSet(rootKeys())[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'b'), true);
  });

  it('rejects if next record does not come before the deleting name', async function() {
    var instance = await dnssec.deployed();
    // text z. comes after next d.
    await submitEntry(
      instance,
      'TXT',
      'z',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'a', { nextDomain: 'd', rrtypes: ['TXT'] });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'z',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'z'), true);
  });

  it('rejects if nsec record starts after the deleting name', async function() {
    var instance = await dnssec.deployed();
    // text a. comes after nsec b.
    await submitEntry(
      instance,
      'TXT',
      'a',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'b', { nextDomain: 'd', rrtypes: ['TXT'] });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'a',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'a'), true);
  });

  it('rejects RRset if trying to delete rrset that is in the type bitmap', async function() {
    var instance = await dnssec.deployed();
    // text a. has same nsec a. with type bitmap
    await submitEntry(
      instance,
      'TXT',
      'a',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'a', { nextDomain: 'd', rrtypes: ['TXT'] });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'a',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'a'), true);
  });

  it('deletes RRset if nsec name and delete name are the same but with different rrtypes', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'a',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    // This test fails if rrtypes is empty ([]), but would that case every happen?
    var nsec = buildEntry('NSEC', 'a', { nextDomain: 'd', rrtypes: ['NSEC'] });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'a',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(await checkPresence(instance, 'TXT', 'a'), false);
  });

  it('rejects if the proof hash does not match', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'a',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'a', { nextDomain: 'd', rrtypes: ['NSEC'] });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'a',
        hexEncodeSignedSet(nsec)[0] + '00',
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'a'), true);
  });

  it('deletes RRset if NSEC next comes after delete name', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'b',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'a', { nextDomain: 'd', rrtypes: ['TXT'] });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'b',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(await checkPresence(instance, 'TXT', 'b'), false);
  });

  it('deletes RRset if NSEC is on apex domain', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'b.test',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'test', {
      nextDomain: 'd.test',
      rrtypes: ['TXT']
    });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'b.test',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(await checkPresence(instance, 'TXT', 'b.test'), false);
  });

  it('deletes RRset if NSEC next name is on apex domain', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'b.test',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry('NSEC', 'a.test', {
      nextDomain: 'test',
      rrtypes: ['TXT']
    });
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'b.test',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(await checkPresence(instance, 'TXT', 'b.test'), false);
  });

  it('will not delete a record if it is more recent than the NSEC record', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'y',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec = buildEntry(
      'NSEC',
      'x',
      { nextDomain: 'z', rrtypes: ['TXT'] },
      { inception: inception - 1 }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'y',
        hexEncodeSignedSet(nsec)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'y'), true);
  });

  //                       088vbc61o9hm3qfu7vhd3ajtilp4bc5l
  // H(matoken.xyz)      = bst4hlje7r0o8c8p4o8q582lm0ejmiqt
  // H(quux.matoken.xyz) = gjjkn49ondfjc1thska8ai4csj8pd7af
  //                       l54nruaka4b4f3mfm5scv7aocqls84gm
  // H(foo.matoken.xyz)  = nvlh0ajql16jp0bigvm9jcmm50c3f8gj
  // H(_abc.matoken.xyz) = q116ronfpgiloujs07ueb829e1rjg0pa

  it('deletes record on the same name using NSEC3', async function() {
    var instance = await dnssec.deployed();

    await submitEntry(
      instance,
      'TXT',
      'matoken.xyz',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec3 = buildEntry(
      'NSEC3',
      'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from('5BA6AD4385844262', 'hex'),
        nextDomain: Buffer.from(
          base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')
        ),
        rrtypes: ['DNSKEY']
      }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'matoken.xyz',
        hexEncodeSignedSet(nsec3)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(await checkPresence(instance, 'TXT', 'matoken.xyz'), false);
  });

  it('deletes records in a zone using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'quux.matoken.xyz',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec3 = buildEntry(
      'NSEC3',
      'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from('5BA6AD4385844262', 'hex'),
        nextDomain: Buffer.from(
          base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')
        ),
        rrtypes: ['TXT']
      }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'quux.matoken.xyz',
        hexEncodeSignedSet(nsec3)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(
      await checkPresence(instance, 'TXT', 'quux.matoken.xyz'),
      false
    );
  });

  it('deletes records at the end of a zone using NSEC3', async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'foo.matoken.xyz',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec3 = buildEntry(
      'NSEC3',
      'l54nruaka4b4f3mfm5scv7aocqls84gm.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from('5BA6AD4385844262', 'hex'),
        nextDomain: Buffer.from(
          base32hex.parse('088VBC61O9HM3QFU7VHD3AJTILP4BC5L')
        ),
        rrtypes: ['TXT']
      }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'foo.matoken.xyz',
        hexEncodeSignedSet(nsec3)[0],
        rootKeyProof
      ),
      true
    );
    assert.equal(
      await checkPresence(instance, 'TXT', 'foo.matoken.xyz'),
      false
    );
  });

  it("doesn't delete records before the range using NSEC3", async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      '_abc.matoken.xyz',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec3 = buildEntry(
      'NSEC3',
      'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from('5BA6AD4385844262', 'hex'),
        nextDomain: Buffer.from(
          base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')
        ),
        rrtypes: ['TXT']
      }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        '_abc.matoken.xyz',
        hexEncodeSignedSet(nsec3)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(
      await checkPresence(instance, 'TXT', '_abc.matoken.xyz'),
      true
    );
  });

  it("doesn't delete records after the range using NSEC3", async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'foo.matoken.xyz',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec3 = buildEntry(
      'NSEC3',
      'bst4hlje7r0o8c8p4o8q582lm0ejmiqt.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from('5BA6AD4385844262', 'hex'),
        nextDomain: Buffer.from(
          base32hex.parse('L54NRUAKA4B4F3MFM5SCV7AOCQLS84GM')
        ),
        rrtypes: ['TXT']
      }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'foo.matoken.xyz',
        hexEncodeSignedSet(nsec3)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(await checkPresence(instance, 'TXT', 'foo.matoken.xyz'), true);
  });

  it("doesn't delete records that aren't at the end of a zone using NSEC3", async function() {
    var instance = await dnssec.deployed();
    await submitEntry(
      instance,
      'TXT',
      'quux.matoken.xyz',
      Buffer.from('foo', 'ascii'),
      rootKeyProof
    );
    var nsec3 = buildEntry(
      'NSEC3',
      'l54nruaka4b4f3mfm5scv7aocqls84gm.matoken.xyz',
      {
        algorithm: 1,
        flags: 0,
        iterations: 1,
        salt: Buffer.from('5BA6AD4385844262', 'hex'),
        nextDomain: Buffer.from(
          base32hex.parse('088VBC61O9HM3QFU7VHD3AJTILP4BC5L')
        ),
        rrtypes: ['TXT']
      }
    );
    assert.equal(
      await deleteEntry(
        instance,
        'TXT',
        'quux.matoken.xyz',
        hexEncodeSignedSet(nsec3)[0],
        rootKeyProof
      ),
      false
    );
    assert.equal(
      await checkPresence(instance, 'TXT', 'quux.matoken.xyz'),
      true
    );
  });
});

// Test against real record
contract('DNSSEC', accounts => {
  async function checkPresence(instance, type, name) {
    var result = (await instance.rrdata.call(
      types.toType(type),
      hexEncodeName(name)
    ))[2];
    return result != '0x0000000000000000000000000000000000000000';
  }

  it('checks real DNSSEC records', async function(){
    instance = await dnssec.at('0x0AF7BfB9bC54E4ca0D48C30d6c0396B919c5abd7');
    assert.equal(await checkPresence(instance, 'TXT', '_ens.matoken.xyz'), true);
  })


    //   matoken.xyz	300	DNSKEY	IN	257	3	8	AwEAAaUPT5a7Ch5cTVkcgDVrf9FCMxCMA+7McAz2x4933N8dFqqC+9OH4yAwoQW+VjXzLF4pbw4mdHuJXMSDaN1I0YrrglEfKtwaH5NacJW4UMoyF9MW5GAoS0XoZzw2ISOOOPCOphhQdc0T9SfG5pSPTvvPMXOZm9KFR99c+jiAwT4mjJut52Mu7b5I4nsUDKQBnOnDFt4fDv2DOSI+yVbdC0swX0bZXSD382GX4+ValNf6Yjz8a1SGtabkv5/PTlMxaHUwqqesqjMVYpnQ1J7bZxlzmfBLfk5A1hpSG8kBNM/ZFUsqRNz+8nOORUvsNrbQLkIEjfduCOUza630ON3ivpE=
    //   matoken.xyz	300	DNSKEY	IN	256	3	8	AwEAAY6LVhxJdhiGG6lRtDBXMRkaiQFmbbRc+/HkD5gn4ZvpUvoZFnHBUoQ9ffN9HN5r3M6Hiuln2CqakGHt09lawk0QnNR54YZiQt/C1XBVBXvTqAG3mcerOizzOZeurCLwPrkybODfOlmNg0HXdczJM2F7x4Rr1xiqvNL/nibWxoJB
    //   matoken.xyz	299	RRSIG	IN	DNSKEY	8	2	300	1570289035	1568388235	37042	matoken.xyz	RyIkEZ3RIolISnNviNgN7ZxNDUhmhJsHmPHOMVCYx1Hz82f8tNTT4XIXHi9az/sSw+EuV5trmYZSYSImaTCKq+z719sqSjJqgfhcsvK5E+hXYZP0s305OmjJJgaDpI+KpWRkg+3jR4yEXRmg9OUBuBqhonFNW/wqSzrkWats9sad7Fjc+zIvwHkeO/tR4jssLOuEWQna2U5F8nMYNCRJ0RoZgFFdKjGX77fnwO/faSamuHeFhZe1dCJUmSdRPeqb4FYY+w0XuaDljSysg785+ccORy4hCQy0gbw/9POzy0wDssIvlgiaI73/42P0uo+dX7sij6AkVuK3OUxjk9lUBA==
    // ["matoken.xyz","0x003008020000012c5d98b58b5d7bb48b90b2076d61746f6b656e0378797a00076d61746f6b656e0378797a00003000010000012c008801000308030100018e8b561c497618861ba951b4305731191a8901666db45cfbf1e40f9827e19be952fa191671c152843d7df37d1cde6bdcce878ae967d82a9a9061edd3d95ac24d109cd479e1866242dfc2d57055057bd3a801b799c7ab3a2cf33997aeac22f03eb9326ce0df3a598d8341d775ccc933617bc7846bd718aabcd2ff9e26d6c68241076d61746f6b656e0378797a00003000010000012c01080101030803010001a50f4f96bb0a1e5c4d591c80356b7fd14233108c03eecc700cf6c78f77dcdf1d16aa82fbd387e32030a105be5635f32c5e296f0e26747b895cc48368dd48d18aeb82511f2adc1a1f935a7095b850ca3217d316e460284b45e8673c3621238e38f08ea6185075cd13f527c6e6948f4efbcf3173999bd28547df5cfa3880c13e268c9bade7632eedbe48e27b140ca4019ce9c316de1f0efd8339223ec956dd0b4b305f46d95d20f7f36197e3e55a94d7fa623cfc6b5486b5a6e4bf9fcf4e5331687530aaa7acaa33156299d0d49edb67197399f04b7e4e40d61a521bc90134cfd9154b2a44dcfef2738e454bec36b6d02e42048df76e08e5336badf438dde2be91","0x472224119dd12289484a736f88d80ded9c4d0d4866849b0798f1ce315098c751f3f367fcb4d4d3e172171e2f5acffb12c3e12e579b6b99865261222669308aabecfbd7db2a4a326a81f85cb2f2b913e8576193f4b37d393a68c9260683a48f8aa5646483ede3478c845d19a0f4e501b81aa1a2714d5bfc2a4b3ae459ab6cf6c69dec58dcfb322fc0791e3bfb51e23b2c2ceb845909dad94e45f27318342449d11a1980515d2a3197efb7e7c0efdf6926a6b877858597b57422549927513dea9be05618fb0d17b9a0e58d2cac83bf39f9c70e472e21090cb481bc3ff4f3b3cb4c03b2c22f96089a23bdffe363f4ba8f9d5fbb228fa02456e2b7394c6393d95404"],
    
    //   r8u7h0kpjdkv8tlp07e79fvascqsdbl2.matoken.xyz	300	NSEC3	IN	{"algorithm":1,"flags":0,"iterations":1,"salt":{"type":"Buffer","data":[238,133,139,204,143,18,43,84]},"nextDomain":{"type":"Buffer","data":[48,231,172,215,13,64,134,128,62,98,41,105,128,99,66,59,88,69,121,162]},"rrtypes":["NS","SOA","RRSIG","DNSKEY","NSEC3PARAM","CDS"]}
    //   63jqplod82380fj255ko0oq27dc4aud2.matoken.xyz	300	NSEC3	IN	{"algorithm":1,"flags":0,"iterations":1,"salt":{"type":"Buffer","data":[238,133,139,204,143,18,43,84]},"nextDomain":{"type":"Buffer","data":[218,60,120,130,153,155,105,244,118,185,1,220,116,191,234,227,53,198,174,162]},"rrtypes":["CNAME","RRSIG"]}
    //   r8u7h0kpjdkv8tlp07e79fvascqsdbl2.matoken.xyz	300	RRSIG	IN	NSEC3	8	3	300	1570289035	1568388235	62926	matoken.xyz	c5n+Vxl1DfLhQf/2z0f+7poSvFZwxy5zrrkEJv5j9cBH3RYBS5WIcx5HRQca/0WWvAcDicyEM3RpVaratjhZUCAz/kfvoB28UFHMVrGan8dgiA8r30HDTDP56tD1XCgpqO0sqx+c+g/HeirYJ2gDEtLzNsja4dcXqWDoRkn5ScU=
    // ["_ens.matoken.xyz","0x003208030000012c5d98b58b5d7bb48bf5ce076d61746f6b656e0378797a002036336a71706c6f643832333830666a3235356b6f306f71323764633461756432076d61746f6b656e0378797a00003200010000012c002a0100000108ee858bcc8f122b5414da3c7882999b69f476b901dc74bfeae335c6aea20006040000000002207238753768306b706a646b7638746c7030376537396676617363717364626c32076d61746f6b656e0378797a00003200010000012c002c0100000108ee858bcc8f122b541430e7acd70d4086803e6229698063423b584579a200082200000000029010","0x7399fe5719750df2e141fff6cf47feee9a12bc5670c72e73aeb90426fe63f5c047dd16014b9588731e4745071aff4596bc070389cc8433746955aadab63859502033fe47efa01dbc5051cc56b19a9fc760880f2bdf41c34c33f9ead0f55c2829a8ed2cab1f9cfa0fc77a2ad827680312d2f336c8dae1d717a960e84649f949c5"],]

  // it.only('deleteRRSet', async function(){
  it('deleteRRSet', async function(){
    const contractAddress = ''
    instance = await dnssec.at(contractAddress);
    deleteType = 16
    // '0x' + packet.name.encode('_ens.matoken.xyz').toString('hex')
    // deleteName = '0x045f656e73076d61746f6b656e0378797a00',

    // '0x' + packet.name.encode('r8u7h0kpjdkv8tlp07e79fvascqsdbl2.matoken.xyz').toString('hex')
    // deleteName = '0x207238753768306b706a646b7638746c7030376537396676617363717364626c32076d61746f6b656e0378797a00',

    // '0x' + packet.name.encode('63jqplod82380fj255ko0oq27dc4aud2.matoken.xyz').toString('hex')
    // deleteName = '0x2036336a71706c6f643832333830666a3235356b6f306f71323764633461756432076d61746f6b656e0378797a00',

    deleteName = '0x045f656e73076d61746f6b656e0378797a00',
    nsec = '0x003208030000012c5d98b58b5d7bb48bf5ce076d61746f6b656e0378797a002036336a71706c6f643832333830666a3235356b6f306f71323764633461756432076d61746f6b656e0378797a00003200010000012c002a0100000108ee858bcc8f122b5414da3c7882999b69f476b901dc74bfeae335c6aea20006040000000002207238753768306b706a646b7638746c7030376537396676617363717364626c32076d61746f6b656e0378797a00003200010000012c002c0100000108ee858bcc8f122b541430e7acd70d4086803e6229698063423b584579a200082200000000029010',
    sig = '0x63c23fd082110ddf30ed82453aac77c55e1f2b1eb17bef8f87d1c28be45cdd9f703ceb733f9aae8e017cbbb666279c5064622345c3f2783cb98f17372d074ef9be71e7fed6832c7756d6c8b9a22964f686ce91bd1a30e0a9124f5de4aa0225bbcf6790bff9296979c5b3aeeae3cb226cb49db451e92cbb9a08846056cc1007b2',
    proof = '0x076d61746f6b656e0378797a00003000010000012c008801000308030100018e8b561c497618861ba951b4305731191a8901666db45cfbf1e40f9827e19be952fa191671c152843d7df37d1cde6bdcce878ae967d82a9a9061edd3d95ac24d109cd479e1866242dfc2d57055057bd3a801b799c7ab3a2cf33997aeac22f03eb9326ce0df3a598d8341d775ccc933617bc7846bd718aabcd2ff9e26d6c68241076d61746f6b656e0378797a00003000010000012c01080101030803010001a50f4f96bb0a1e5c4d591c80356b7fd14233108c03eecc700cf6c78f77dcdf1d16aa82fbd387e32030a105be5635f32c5e296f0e26747b895cc48368dd48d18aeb82511f2adc1a1f935a7095b850ca3217d316e460284b45e8673c3621238e38f08ea6185075cd13f527c6e6948f4efbcf3173999bd28547df5cfa3880c13e268c9bade7632eedbe48e27b140ca4019ce9c316de1f0efd8339223ec956dd0b4b305f46d95d20f7f36197e3e55a94d7fa623cfc6b5486b5a6e4bf9fcf4e5331687530aaa7acaa33156299d0d49edb67197399f04b7e4e40d61a521bc90134cfd9154b2a44dcfef2738e454bec36b6d02e42048df76e08e5336badf438dde2be91'    
    let result = await instance.deleteRRSet(deleteType, deleteName, nsec, sig, proof);
    assert.equal(await checkPresence(instance, 'TXT', '_ens.matoken.xyz'), false);
  })

  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    console.log('instance.address', instance.address)
    var proof = await instance.anchors();
    // They were all valid at Fri Mar 15 14:06:45 2019 +1300 and
    // will be again every 2^32 seconds or 136 years
    // await web3.currentProvider.send({
    //   method: 'evm_increaseTime',
    //   params: (1552612005 - Date.now() / 1000) >>> 0
    // });
    for (let i = 0; i < test_rrsets.length; i++) {
      var rrset = test_rrsets[i];
      var tx = await instance.submitRRSet(rrset[1], rrset[2], proof);
      proof = tx.logs[0].args.rrset;
      assert.equal(tx.receipt.status, true);
    }
  });
});
