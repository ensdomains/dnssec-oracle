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
  //   .	172800	DNSKEY	IN	256	3	8	AwEAAdauOGxLhfAKFTTZwGhBXbk793QKdWIQRjiSftWdusCwkPhNyJrIjwtNffCWXGLlZAbpcs414RE3oS1qVwV+AdXsO92SBu5haGlxMUk0NqZO7Xlf84/wrzGZVRRouPo5pNX/CKS8Mv9UOi0olKGCu31dNfh8qCszWZcloLDgeLzSnQSkvFoGe69vNCfh7feESKedkBC2qRz0BZv9+oJI0IY/3D7WEnV0NOlf8gSHozhfJFJ/ZAKtvw/Q3ogrVJFk0LyVaU/NVtVA5FM4pVMIRID7pfrPi78aAzG7b/Wh/Pce4jPAIpS3dApq25YkvMuPvfB91NMf9FemKwlp78PBVcM=
  //   .	172800	DNSKEY	IN	256	3	8	AwEAAfC/6HLClwss6h7rPfoG2cliv4/SPJRd2HPEglRsvKZRbPP2RLfiobeAkczcdqaD5q8loEt14lcTgDqwzOISZ3YvSVkM4JRMFwKzcjukKo5CsDVbMmhTD0C0yxWICRQ1M+Y5/XkZAT7mt4cb3fWcN9xgyq1wEXQX+zdLQHrNEVQSiL5SoA5cOtCSoQ45n8bKDXdw/0jjP9Rw1FVKsdzLVkQSrVMm8k30WUkHm/SK/n/954KENkdQOA6Li2vO9nicQdegyAkDeNJCdPN/p3jEhCTQLyO4AlAmyaPcDHeeo7OXr/VsYu4NTDde9hBuS0zx/rewD+BvSnmnNHNmH2FjUE8=
  //   .	172800	DNSKEY	IN	257	3	8	AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  //   .	4686	RRSIG	IN	DNSKEY	8	0	172800	1603324800	1601510400	20326	.	GQCWSqHk5UAy6044TUk7tkhOAiL0q7r1AtYQlBCZU9SVbvL5c0acMjhmoT13SgUEWFhBkLb+vfpsrQbdj3j2Q3zENCC5Cg8MbBAwUKKSECdztMbDwgxvfwWpu9toDdLylMYIhxB6cBdBlpe5foArtbaLPchgozSEFYHTlXeALgLmdGwqFYC+IbDTIHDN16HqwLM6yWV5UR7n8JO5Zn4Qpw0HEsfv+MixVgckYWhKGgzUwWHLfHgXE1oG4Nm8egLtin0FeDatlMHengKWZC1XlZCQC8A6kwWP0tGivJZnd1MbScEU7UJC2J2AzCuPbZGIetePet7+3QiQzwIl2Sa7cQ==
  [web3.utils.toHex("."),"0x003008000002a3005f90cb805f751c004f660000003000010002a30001080100030803010001d6ae386c4b85f00a1534d9c068415db93bf7740a7562104638927ed59dbac0b090f84dc89ac88f0b4d7df0965c62e56406e972ce35e11137a12d6a57057e01d5ec3bdd9206ee6168697131493436a64eed795ff38ff0af3199551468b8fa39a4d5ff08a4bc32ff543a2d2894a182bb7d5d35f87ca82b33599725a0b0e078bcd29d04a4bc5a067baf6f3427e1edf78448a79d9010b6a91cf4059bfdfa8248d0863fdc3ed612757434e95ff20487a3385f24527f6402adbf0fd0de882b549164d0bc95694fcd56d540e45338a553084480fba5facf8bbf1a0331bb6ff5a1fcf71ee233c02294b7740a6adb9624bccb8fbdf07dd4d31ff457a62b0969efc3c155c300003000010002a30001080100030803010001f0bfe872c2970b2cea1eeb3dfa06d9c962bf8fd23c945dd873c482546cbca6516cf3f644b7e2a1b78091ccdc76a683e6af25a04b75e25713803ab0cce21267762f49590ce0944c1702b3723ba42a8e42b0355b3268530f40b4cb158809143533e639fd7919013ee6b7871bddf59c37dc60caad70117417fb374b407acd11541288be52a00e5c3ad092a10e399fc6ca0d7770ff48e33fd470d4554ab1dccb564412ad5326f24df45949079bf48afe7ffde78284364750380e8b8b6bcef6789c41d7a0c8090378d24274f37fa778c48424d02f23b8025026c9a3dc0c779ea3b397aff56c62ee0d4c375ef6106e4b4cf1feb7b00fe06f4a79a73473661f6163504f00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5","0x1900964aa1e4e54032eb4e384d493bb6484e0222f4abbaf502d61094109953d4956ef2f973469c323866a13d774a050458584190b6febdfa6cad06dd8f78f6437cc43420b90a0f0c6c103050a292102773b4c6c3c20c6f7f05a9bbdb680dd2f294c60887107a7017419697b97e802bb5b68b3dc860a334841581d39577802e02e6746c2a1580be21b0d32070cdd7a1eac0b33ac96579511ee7f093b9667e10a70d0712c7eff8c8b156072461684a1a0cd4c161cb7c7817135a06e0d9bc7a02ed8a7d057836ad94c1de9e0296642d579590900bc03a93058fd2d1a2bc966777531b49c114ed4242d89d80cc2b8f6d91887ad78f7adefedd0890cf0225d926bb71"],
  
  //   xyz	86400	DS	IN	3599	8	1	P6OyZPRdtfOL7erxqIt2qjGMLH8=
  //   xyz	86400	DS	IN	3599	8	2	uXM4abyEyGu1nRArpdprJ7IIhVIzKjnc1UvE6NZrBJk=
  //   xyz	79938	RRSIG	IN	DS	8	1	86400	1603256400	1602129600	26116	.	vOpqYltb7/q8MNz017xrXe9anw7xFnd4DSVwL3aW/KZXVPBBpGAh025TENlL32ggVQZ8rGCyShYPEkSPn20atbCHnTSe7HzGt7ZJwsvDsPgPTfDONcUoOqGhxM98VD1C5dGQACfa2xsX8qlHCrg6fyyCH4pNDh1qmBpIyLKZCZHxRy+kyEjEiAvTlx5jWGP2A8RsLTY+Cxb4oykGA/a7kLD02AtB2crCZUT4zwlrBBimUlnMotTl5XftvS6+mYX73S0LY7Zv2hcJ4F4+V7T9ipv8AIsGT2Vn600MCAMYv6/b9FJdmukk3601PgerkJhCDNqEZg/xIZrCVBpe615xDg==
  [web3.utils.toHex("xyz"),"0x002b0801000151805f8fc0505f7e8ec06604000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499","0xbcea6a625b5beffabc30dcf4d7bc6b5def5a9f0ef11677780d25702f7696fca65754f041a46021d36e5310d94bdf682055067cac60b24a160f12448f9f6d1ab5b0879d349eec7cc6b7b649c2cbc3b0f80f4df0ce35c5283aa1a1c4cf7c543d42e5d1900027dadb1b17f2a9470ab83a7f2c821f8a4d0e1d6a981a48c8b2990991f1472fa4c848c4880bd3971e635863f603c46c2d363e0b16f8a3290603f6bb90b0f4d80b41d9cac26544f8cf096b0418a65259cca2d4e5e577edbd2ebe9985fbdd2d0b63b66fda1709e05e3e57b4fd8a9bfc008b064f6567eb4d0c080318bfafdbf4525d9ae924dfad353e07ab9098420cda84660ff1219ac2541a5eeb5e710e"],
  
  //   xyz	3600	DNSKEY	IN	256	3	8	AwEAAaF51jQdGVbVYLfa/2QmM/gwwFQTFTDq8UdbB30ZZMgIOq6f0Sf+ln7W+4IKAvpyiy9Udzn9tegd4f3fB5EMJKRe9ywLq3/O0cQCIo8R8dYU3fB65lZ+r44EfMt6alQF9sHT9QEilLFpopWry2m4EP0i6zbkxvkSlKJdDiwHzN8z
  //   xyz	3600	DNSKEY	IN	256	3	8	AwEAAbtLVZ0OIxoYWI0828eo0RAdTCzPRiF4u7CKKlbhEXcFBs7ZI9wSrZUSnXpvhlujBCRdT4fpfzpwY2WWfz4uWc+GXTDw0lxBKvThXebi2phK4zhXJJQPExPX4jRU3l4DUbJ1tHBYCtA/MDAUVgzcBeNSZeVuyaaIqPhpTygW8cRx
  //   xyz	3600	DNSKEY	IN	257	3	8	AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
  //   xyz	2407	RRSIG	IN	DNSKEY	8	1	3600	1604141051	1601510791	3599	xyz	XVHhVQhyTtzYD0fWiHthtLZqJ3jOTrXgBYbRnoCSFayaZesUjaUZWU6MA7hA+h9cIyjj14Ec0fZy6Nl1pYmBNTE9qNGMmKZ8vYeV4aG/T58lm9z9HjUW2KoN2nXohhBNJQoMeAY99nT3EQAfrKDTKK9U2T8PpUXap9F3tetDuK7hm+BN03o1vQZ++AOrP+2/z8Ay+lMLHHEyhdJp8P5lJfMt/I/8cPWfortdSlDAOmc2KpQesfxFTrwJ1lqo7uSPUNWUsyrGIE/YmCOE5K3AtSAMnLKm7ne8hyyJT6rL2FfH2HOj/nVhZsWFkgG7VUiJ3B5o1STA12204IMlAjxGXw==
  [web3.utils.toHex("xyz"),"0x0030080100000e105f9d3ffb5f751d870e0f0378797a000378797a000030000100000e1000880100030803010001a179d6341d1956d560b7daff642633f830c054131530eaf1475b077d1964c8083aae9fd127fe967ed6fb820a02fa728b2f547739fdb5e81de1fddf07910c24a45ef72c0bab7fced1c402228f11f1d614ddf07ae6567eaf8e047ccb7a6a5405f6c1d3f5012294b169a295abcb69b810fd22eb36e4c6f91294a25d0e2c07ccdf330378797a000030000100000e1000880100030803010001bb4b559d0e231a18588d3cdbc7a8d1101d4c2ccf462178bbb08a2a56e111770506ced923dc12ad95129d7a6f865ba304245d4f87e97f3a706365967f3e2e59cf865d30f0d25c412af4e15de6e2da984ae3385724940f1313d7e23454de5e0351b275b470580ad03f303014560cdc05e35265e56ec9a688a8f8694f2816f1c4710378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983","0x5d51e15508724edcd80f47d6887b61b4b66a2778ce4eb5e00586d19e809215ac9a65eb148da519594e8c03b840fa1f5c2328e3d7811cd1f672e8d975a5898135313da8d18c98a67cbd8795e1a1bf4f9f259bdcfd1e3516d8aa0dda75e886104d250a0c78063df674f711001faca0d328af54d93f0fa545daa7d177b5eb43b8aee19be04dd37a35bd067ef803ab3fedbfcfc032fa530b1c713285d269f0fe6525f32dfc8ffc70f59fa2bb5d4a50c03a67362a941eb1fc454ebc09d65aa8eee48f50d594b32ac6204fd8982384e4adc0b5200c9cb2a6ee77bc872c894faacbd857c7d873a3fe756166c5859201bb554889dc1e68d524c0d76db4e08325023c465f"],
  
  //   matoken.xyz	3600	DS	IN	37042	8	2	zyoXTFVzCFldvxA5sMWZkDfQSy52TEi9Vb3BzUjquMo=
  //   matoken.xyz	3600	RRSIG	IN	DS	8	2	3600	1603162927	1600527912	30778	xyz	XQU7v2e5WaUAXUSZxhs/7f8SGho7jNgsybjvdGUTThvWJMo2RzNLGx69rIjLuvfDWAWMtEbdcgnMwJyULakzl/OsnGNs+/nPImYxewcH60qaCEN4Gr3Lw1bH3GWGM1QeZadrSBezA9ba0YC8XhVKkyFhRPY/3lChz6GMfOpTmZI=
  [web3.utils.toHex("matoken.xyz"),"0x002b080200000e105f8e532f5f661e28783a0378797a00076d61746f6b656e0378797a00002b000100000e10002490b20802cf2a174c557308595dbf1039b0c5999037d04b2e764c48bd55bdc1cd48eab8ca","0x5d053bbf67b959a5005d4499c61b3fedff121a1a3b8cd82cc9b8ef7465134e1bd624ca3647334b1b1ebdac88cbbaf7c358058cb446dd7209ccc09c942da93397f3ac9c636cfbf9cf2266317b0707eb4a9a0843781abdcbc356c7dc658633541e65a76b4817b303d6dad180bc5e154a93216144f63fde50a1cfa18c7cea539992"],
  
  //   matoken.xyz	300	DNSKEY	IN	256	3	8	AwEAAZsNaUDJhD+bXyCGG/ukLMpJAhyEQjkucJOTJWqvog1dIveojiUQvQHCxZHyYR5wcH6sWSx7LDEpPRwdeIEmGLe1pLEOcK3P0iz23cb6OHflSjnz+SxDdbhy8vVVYQYg0IRLW44ekmN4Oyww7M7pP5G907ApP5R17GpR1mFEogu7
  //   matoken.xyz	300	DNSKEY	IN	256	3	8	AwEAAd9bGUPjwLiwoCzNcXrHbrzJp3kMK+8w9IZtdpiU62h6cACgZ+OtRFaUoj0ZbZMZtTQ/F64uaw3IpzO+/5MPz+w+WIGS5WTvjtfvtDyo2b6Q75CbLdrCw8qw0OH+WrRmdZhucZB/zrbL2iiZbDuWikgqdj5+HWSdsIgr3ITDQY3v
  //   matoken.xyz	300	DNSKEY	IN	257	3	8	AwEAAaUPT5a7Ch5cTVkcgDVrf9FCMxCMA+7McAz2x4933N8dFqqC+9OH4yAwoQW+VjXzLF4pbw4mdHuJXMSDaN1I0YrrglEfKtwaH5NacJW4UMoyF9MW5GAoS0XoZzw2ISOOOPCOphhQdc0T9SfG5pSPTvvPMXOZm9KFR99c+jiAwT4mjJut52Mu7b5I4nsUDKQBnOnDFt4fDv2DOSI+yVbdC0swX0bZXSD382GX4+ValNf6Yjz8a1SGtabkv5/PTlMxaHUwqqesqjMVYpnQ1J7bZxlzmfBLfk5A1hpSG8kBNM/ZFUsqRNz+8nOORUvsNrbQLkIEjfduCOUza630ON3ivpE=
  //   matoken.xyz	300	RRSIG	IN	DNSKEY	8	2	300	1603753979	1601853179	37042	matoken.xyz	K6H0Y6o1h/b33rHPGFzj3Co0m4onIefrrK9HgNXejFbHq58dEdEPuOyixDgVcEpTcBZADYB6vZyvqXmAIliMqFfQNxAcUGohNkwnOHs+zB6zt2MLqluoaU+CjjSKUHO/ltmbkQztoFIcr4lceJz7oGjS8xGY1VAgm5/BTxRjsTTHLRP0VIK3N+wuaFiCloFzsqp614i5+ePLqbOwmTKqjaI6X+pAxFQ1ID6nvY18Cm+ETqv99HQo+XMQ6BemhhYl+BgwisCLZUXtRaL4wKfDbMO2DlRY5C1KCPkup7YE0p9XibQ57JBOEicZ9tgABOlPzKhZDNhEDa3efryOaCSKDQ==
  [web3.utils.toHex("matoken.xyz"),"0x003008020000012c5f9757fb5f7a56fb90b2076d61746f6b656e0378797a00076d61746f6b656e0378797a00003000010000012c008801000308030100019b0d6940c9843f9b5f20861bfba42cca49021c8442392e709393256aafa20d5d22f7a88e2510bd01c2c591f2611e70707eac592c7b2c31293d1c1d78812618b7b5a4b10e70adcfd22cf6ddc6fa3877e54a39f3f92c4375b872f2f555610620d0844b5b8e1e9263783b2c30eccee93f91bdd3b0293f9475ec6a51d66144a20bbb076d61746f6b656e0378797a00003000010000012c00880100030803010001df5b1943e3c0b8b0a02ccd717ac76ebcc9a7790c2bef30f4866d769894eb687a7000a067e3ad445694a23d196d9319b5343f17ae2e6b0dc8a733beff930fcfec3e588192e564ef8ed7efb43ca8d9be90ef909b2ddac2c3cab0d0e1fe5ab46675986e71907fceb6cbda28996c3b968a482a763e7e1d649db0882bdc84c3418def076d61746f6b656e0378797a00003000010000012c01080101030803010001a50f4f96bb0a1e5c4d591c80356b7fd14233108c03eecc700cf6c78f77dcdf1d16aa82fbd387e32030a105be5635f32c5e296f0e26747b895cc48368dd48d18aeb82511f2adc1a1f935a7095b850ca3217d316e460284b45e8673c3621238e38f08ea6185075cd13f527c6e6948f4efbcf3173999bd28547df5cfa3880c13e268c9bade7632eedbe48e27b140ca4019ce9c316de1f0efd8339223ec956dd0b4b305f46d95d20f7f36197e3e55a94d7fa623cfc6b5486b5a6e4bf9fcf4e5331687530aaa7acaa33156299d0d49edb67197399f04b7e4e40d61a521bc90134cfd9154b2a44dcfef2738e454bec36b6d02e42048df76e08e5336badf438dde2be91","0x2ba1f463aa3587f6f7deb1cf185ce3dc2a349b8a2721e7ebacaf4780d5de8c56c7ab9f1d11d10fb8eca2c43815704a537016400d807abd9cafa9798022588ca857d037101c506a21364c27387b3ecc1eb3b7630baa5ba8694f828e348a5073bf96d99b910ceda0521caf895c789cfba068d2f31198d550209b9fc14f1463b134c72d13f45482b737ec2e685882968173b2aa7ad788b9f9e3cba9b3b09932aa8da23a5fea40c45435203ea7bd8d7c0a6f844eabfdf47428f97310e817a6861625f818308ac08b6545ed45a2f8c0a7c36cc3b60e5458e42d4a08f92ea7b604d29f5789b439ec904e122719f6d80004e94fcca8590cd8440dadde7ebc8e68248a0d"],
  
  //   _ens.matoken.xyz	300	TXT	IN	"a=0xfFD1Ac3e8818AdCbe5C597ea076E8D3210B45df5"
  //   _ens.matoken.xyz	300	RRSIG	IN	TXT	8	3	300	1603753979	1601853179	14899	matoken.xyz	OZbmQH7EA1MMpViZOZI9skHRyUE6GScLwfO2A8h3u8BNO5cr8q+2DnTLXTusWX2/XOxa/IQGFITt0nwC/DK1XsvB30wZ+WTE8kiZlhPQ4RKzUPJnN9mD+/bk3B0AlIUy9C/XFSiOUyzSGb36j8jDpDZdA9d37DS5wpOwDdSlsFI=
  [web3.utils.toHex("_ens.matoken.xyz"),"0x001008030000012c5f9757fb5f7a56fb3a33076d61746f6b656e0378797a00045f656e73076d61746f6b656e0378797a00001000010000012c002d2c613d307866464431416333653838313841644362653543353937656130373645384433323130423435646635","0x3996e6407ec403530ca5589939923db241d1c9413a19270bc1f3b603c877bbc04d3b972bf2afb60e74cb5d3bac597dbf5cec5afc84061484edd27c02fc32b55ecbc1df4c19f964c4f248999613d0e112b350f26737d983fbf6e4dc1d00948532f42fd715288e532cd219bdfa8fc8c3a4365d03d777ec34b9c293b00dd4a5b052"]]


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
contract.only('DNSSEC', accounts => {
  async function checkPresence(instance, type, name) {
    var result = (await instance.rrdata.call(
      types.toType(type),
      hexEncodeName(name)
    ))[2];
    return result != '0x0000000000000000000000000000000000000000';
  }

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

  it('deleteRRSet', async function(){
    var instance = await dnssec.deployed();
    console.log('instance.address', instance.address)    
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
});
