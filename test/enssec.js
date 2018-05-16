var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
//	.	61452	IN	RRSIG	DNSKEY	8	0	172800	1527811200	1525996800	19036	.	k0XCRTsOetHy2ybnDwZx1Lq0wSc80YksHYTEs+PgpMsR3lYcp+QX7p5zX1pf/78Mhh1m2pW6M6onpWZCIeM+OPyqDNjKpRV9siF/Aw7idpNKSraqs4ceOtJlrKi6chRlfgDhXliNy8lpfj8PnPaGNaihL9Tvmv4bIlHZiFRJMpdz43UFb9vkpQOCdZu7sfK9lZGYU+cpjVT4OqfC0JfmpTA3H3lcpOy2o7VDKB0dEuldy07hBigh6toAYWTD1Qk6WPMRVn+YQBe40hgFLItHHwYdpOLH3uSBJb2R3fzOTh6+hx3rUDJvoEajbou4pUP8Y7dhNXc3zPiI6tG8A5dNoA==
//	.	61452	IN	DNSKEY	256	8	AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZRrPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aRZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aCIK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtjwG0I78sfMZc=
//	.	61452	IN	DNSKEY	257	8	AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
//	.	61452	IN	DNSKEY	257	8	AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
[".", "003008000002a3005b108c805af4dd004a5c0000003000010002a30001080100030803010001d53868a943804a57596a47e5a5c7259235566f429b8da6180b2a933dda90572d4bacec6470b7a4d34cba0f7d7ca6bb396fad44723064473ffe65fc26de9b730e5b3e04471babb6793f2f5296d70cf56cd4808647a16197015610ecb16c82220df77b12ae9e00b93944d71abb213efd93fe55dae15990de116651acf04b8c1c815931e5faffdffb1bd32774ad72adad12a9f34b60823abe914c97a9a6b621bbee5897a69166611504adbb5825b566b9352de909bc95df7322922a4d7d0b93392565f9f29c7a9c1d484b4a4cb3a68220adb2690415354120f57c90cc14affeb33154d372dd502a3a3be1f8e012a4b326e061026d249ef23b63c06d08efcb1f319700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "9345c2453b0e7ad1f2db26e70f0671d4bab4c1273cd1892c1d84c4b3e3e0a4cb11de561ca7e417ee9e735f5a5fffbf0c861d66da95ba33aa27a5664221e33e38fcaa0cd8caa5157db2217f030ee276934a4ab6aab3871e3ad265aca8ba7214657e00e15e588dcbc9697e3f0f9cf68635a8a12fd4ef9afe1b2251d9885449329773e375056fdbe4a50382759bbbb1f2bd95919853e7298d54f83aa7c2d097e6a530371f795ca4ecb6a3b543281d1d12e95dcb4ee1062821eada006164c3d5093a58f311567f984017b8d218052c8b471f061da4e2c7dee48125bd91ddfcce4e1ebe871deb50326fa046a36e8bb8a543fc63b761357737ccf888ead1bc03974da0"],



//	xyz	81156	IN	RRSIG	DS	8	1	86400	1527570000	1526443200	39570	.	Okt2k/qrjAFFnaklSLvUptwiRTgtodlfxekVq7KqkHerE+/VPFGd8GbnwzP1cYlgC8Yx1hxyfX9w1SuqH/YqhbvNoj+8SFnEAKeZr9ZltUuiyevOvHAxgFLoZmFNuuSSiDjnXxcRu1cvTyeMO8s42aOg6M83cDvU9Pdi46fyrb8UamECS9xdVTdBKAuOF7O/tugliUDXJXYnTn+nPIPnqWaUS9Dq1oxZUQ62FEHNNP1HAerAqLE796l6FgdCLcZB0wTc6QkQK51g2QCacMW5EQ/lxm5mWmbCmzqulmJ7sp4/9V0hKksw3a0ZoX5Q3SCD3J0R3cORKixGxR6gaXiVgw==
//	xyz	81156	IN	DS	3599	8	1	3fa3b264f45db5f38bedeaf1a88b76aa318c2c7f
//	xyz	81156	IN	DS	3599	8	2	b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499
["xyz.", "002b0801000151805b0cde505afbacc09a92000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "3a4b7693faab8c01459da92548bbd4a6dc2245382da1d95fc5e915abb2aa9077ab13efd53c519df066e7c333f57189600bc631d61c727d7f70d52baa1ff62a85bbcda23fbc4859c400a799afd665b54ba2c9ebcebc70318052e866614dbae4928838e75f1711bb572f4f278c3bcb38d9a3a0e8cf37703bd4f4f762e3a7f2adbf146a61024bdc5d553741280b8e17b3bfb6e8258940d72576274e7fa73c83e7a966944bd0ead68c59510eb61441cd34fd4701eac0a8b13bf7a97a1607422dc641d304dce909102b9d60d9009a70c5b9110fe5c66e665a66c29b3aae96627bb29e3ff55d212a4b30ddad19a17e50dd2083dc9d11ddc3912a2c46c51ea069789583"],



//	xyz	713	IN	RRSIG	DNSKEY	8	1	3600	1528895358	1526325631	3599	xyz	FLzhcG4KLcYx6837aEZ3xWCYA2SNIMjv7sBVJG2TLkl7pq+9wWwZHfCpUaRr/Q/Mnfuu77ljkEx3ZFAmut7/AKXvoC12BHfNUiOxjARQUpiFDWzF+AAKIGqweimjj/0fv/L0E0Vvu9wbKopUnw58f3RGc+4RUtvl4cvPhZUNc6s1k9csjfvZcTWvx5caso9hGU/4f5H0GzBOnv6LL96rzW+UAuk543ndkbqPd+niC61ZF80h3s0b9JnhJ06D7BAIf4AhJWf6DA+jzspaa5J8qZh/EWbPFYNCgewK020zQfCzxFxlUPUZ8ix47Lbfx++KOHUKvOHV2JNNYjT/xFdS/g==
//	xyz	713	IN	DNSKEY	257	8	AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
//	xyz	713	IN	DNSKEY	256	8	AwEAAbi90iT9b2z/i2CJyxKwJk7wVxTBizJhqB7Uabh55DwvDiBRUP3GMw1Qsng01aC4Ve92SUVBc3LIBTJ1FerN2OnByWBAnjizWuOn9RSGFlehJSbtHNdMlUktiyRxM+6j9/DUR1UYZCCChwuzkaQtNH5e4EKX5PhjwMeT2GfOg69v
//	xyz	713	IN	DNSKEY	256	8	AwEAAYNktvUuoOalRZ7fB2EGfUkqOqIVNZcx9YaU3i8CubvOetVo8n+oUvvivq8+Vs2XithtiMzExJPGtJOjk38hibkBfCFcjNdiMQpce+ZfpJtRcmB30R+hxpHXiRwS7y6pPT3g2/dyeQJckH7R1qR6TQgqqVi/Mgbs6FmvpxgI9Dy7
["xyz.", "0030080100000e105b21177e5af9e17f0e0f0378797a000378797a000030000100000e10008801000308030100018364b6f52ea0e6a5459edf0761067d492a3aa215359731f58694de2f02b9bbce7ad568f27fa852fbe2beaf3e56cd978ad86d88ccc4c493c6b493a3937f2189b9017c215c8cd762310a5c7be65fa49b51726077d11fa1c691d7891c12ef2ea93d3de0dbf77279025c907ed1d6a47a4d082aa958bf3206ece859afa71808f43cbb0378797a000030000100000e1000880100030803010001b8bdd224fd6f6cff8b6089cb12b0264ef05714c18b3261a81ed469b879e43c2f0e205150fdc6330d50b27834d5a0b855ef764945417372c805327515eacdd8e9c1c960409e38b35ae3a7f514861657a12526ed1cd74c95492d8b247133eea3f7f0d4475518642082870bb391a42d347e5ee04297e4f863c0c793d867ce83af6f0378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "14bce1706e0a2dc631ebcdfb684677c5609803648d20c8efeec055246d932e497ba6afbdc16c191df0a951a46bfd0fcc9dfbaeefb963904c77645026badeff00a5efa02d760477cd5223b18c04505298850d6cc5f8000a206ab07a29a38ffd1fbff2f413456fbbdc1b2a8a549f0e7c7f744673ee1152dbe5e1cbcf85950d73ab3593d72c8dfbd97135afc7971ab28f61194ff87f91f41b304e9efe8b2fdeabcd6f9402e939e379dd91ba8f77e9e20bad5917cd21decd1bf499e1274e83ec10087f80212567fa0c0fa3ceca5a6b927ca9987f1166cf15834281ec0ad36d3341f0b3c45c6550f519f22c78ecb6dfc7ef8a38750abce1d5d8934d6234ffc45752fe"],



//	matoken.xyz	2761	IN	RRSIG	DS	8	2	3600	1528135831	1525512361	48429	xyz	ZO+wjVfvZ9tyRBAzJ9E3dRNSgCk87L+HUJb77I41z1CnbbHycg3PZhnQ2P5A6HtxWUv4fPdP+nNx1SnTE+ffB66KgXGPKHKkB04xxMOaN8BpyQkEX1ihpkp30jNL6CZUZaUNoLxVjuOXJnYdudPCzBwUPFpBLi5hyn5G+H4Cpuo=
//	matoken.xyz	2761	IN	DS	26386	8	2	57fd27737d6cfe4fd9bd0560645bbaf94ae42625bd4fd0536b166e3ac5f44ea4
["matoken.xyz.", "002b080200000e105b1580975aed78a9bd2d0378797a00076d61746f6b656e0378797a00002b000100000e1000246712080257fd27737d6cfe4fd9bd0560645bbaf94ae42625bd4fd0536b166e3ac5f44ea4", "64efb08d57ef67db7244103327d13775135280293cecbf875096fbec8e35cf50a76db1f2720dcf6619d0d8fe40e87b71594bf87cf74ffa7371d529d313e7df07ae8a81718f2872a4074e31c4c39a37c069c909045f58a1a64a77d2334be8265465a50da0bc558ee39726761db9d3c2cc1c143c5a412e2e61ca7e46f87e02a6ea"],



//	matoken.xyz	299	IN	RRSIG	DNSKEY	8	2	300	1528232842	1526332042	26386	matoken.xyz	Lr9BkpzOYkSHi4pg3c2L/Xzh4m0uVucydlgjPcrlBaD0eTO8R6ZYuVWw8egWfqbbe2sO1p4Nt+VCYseeW2qanu2B8KadyGDnBYP7RxhH9OgV3GgVhrCTn0zHomzzAc1u8d9gCZuJn5SBMFt9LKIAB9izQqaR5VFm+2Jt8ujVK16l8KpIrRSYlNf2PvHEa8xXip1jfuAYqIVECGJ5KZs6wLc/kc8LY9oe/A6OWf+y5hzEmKyKBilVWWvnm/nLNG8eHrMgTUyWSjgRaVGYt/yIrh+KMmtIXvsTYehCNtce+0kKgR0mp+4CucKR58czTGpEDzU86T9HeqBnabgZ1VRRoA==
//	matoken.xyz	299	IN	DNSKEY	256	8	AwEAAa2J5SB6Uqzr4SVhImbC60REOD0LPyJXxprbgLw410DFCoAbYOSJPW2TXQh8n3RrStIx92fnzpH9pU+vilYGYG8V8vy8ldNL9r73glU00P3N71z/YDdTJv38LYBc5xgKhF2KE+EdxIZjyp1++inuiZ6fi2R7wE1Wc8Vxpin1mAI5
//	matoken.xyz	299	IN	DNSKEY	257	8	AwEAAaoFsBLNpqXZHYDclwolLktwr/FoOB2mG9fGVdtDiv4TIsw4dEKoqAH5dNv0/7EQ5baMAyAspHRwvafP9AxQwnYqDkUiKk3x5sbWmh3Mr9FTWhu4LWwX3SrAS40CYJLUGJq2MNE0i6rC/1YS+vB5YfSEglcfWekix0TauLnHrPYpX8xyVmYmxkI3dhydVxYW4cvu9DlBPzSPnG6JImqXGzk/yNRUcpUdaIl+ryZKzbtc1UtsTqUgtFw6u714+ifdETkh0/rLzB1gQCQ8l2GGfGmh3BPZ9xiYEh/2llYUWNnZ+HU21qhPtgLJH5sH5WH6L1TrD58ZhPPL5yjsFCy+1S8=
["matoken.xyz.", "003008020000012c5b16fb8a5af9fa8a6712076d61746f6b656e0378797a00076d61746f6b656e0378797a00003000010000012c00880100030803010001ad89e5207a52acebe125612266c2eb4444383d0b3f2257c69adb80bc38d740c50a801b60e4893d6d935d087c9f746b4ad231f767e7ce91fda54faf8a5606606f15f2fcbc95d34bf6bef7825534d0fdcdef5cff60375326fdfc2d805ce7180a845d8a13e11dc48663ca9d7efa29ee899e9f8b647bc04d5673c571a629f5980239076d61746f6b656e0378797a00003000010000012c01080101030803010001aa05b012cda6a5d91d80dc970a252e4b70aff168381da61bd7c655db438afe1322cc387442a8a801f974dbf4ffb110e5b68c03202ca47470bda7cff40c50c2762a0e45222a4df1e6c6d69a1dccafd1535a1bb82d6c17dd2ac04b8d026092d4189ab630d1348baac2ff5612faf07961f48482571f59e922c744dab8b9c7acf6295fcc72566626c64237761c9d571616e1cbeef439413f348f9c6e89226a971b393fc8d45472951d68897eaf264acdbb5cd54b6c4ea520b45c3abbbd78fa27dd113921d3facbcc1d6040243c9761867c69a1dc13d9f71898121ff696561458d9d9f87536d6a84fb602c91f9b07e561fa2f54eb0f9f1984f3cbe728ec142cbed52f", "2ebf41929cce6244878b8a60ddcd8bfd7ce1e26d2e56e7327658233dcae505a0f47933bc47a658b955b0f1e8167ea6db7b6b0ed69e0db7e54262c79e5b6a9a9eed81f0a69dc860e70583fb471847f4e815dc681586b0939f4cc7a26cf301cd6ef1df60099b899f9481305b7d2ca20007d8b342a691e55166fb626df2e8d52b5ea5f0aa48ad149894d7f63ef1c46bcc578a9d637ee018a88544086279299b3ac0b73f91cf0b63da1efc0e8e59ffb2e61cc498ac8a062955596be79bf9cb346f1e1eb3204d4c964a3811695198b7fc88ae1f8a326b485efb1361e84236d71efb490a811d26a7ee02b9c291e7c7334c6a440f353ce93f477aa06769b819d55451a0"],



//	_ens.matoken.xyz	299	IN	RRSIG	TXT	8	3	300	1528232842	1526332042	62544	matoken.xyz	X0tpHWwyHn5PDYhdGK2WLzgXa7jd8jyfTWDNOOrYRkBnh6Eu/CiReH/k81s0SiFlj+GXPcK2uMi0EhHPI7DcCG2Bcdbcw12G5/7TJXxDAaPtaqbzecvrfOR8XNnXEZy0AOObG65N0RiXAO/Ez/bJh0VRoDO3Uu53RMtrASG/3K0=
//	_ens.matoken.xyz	299	IN	TXT	a=0x5aBc7749d0cd2b4219912323a423492CDA3513B2
["_ens.matoken.xyz.", "001008030000012c5b16fb8a5af9fa8af450076d61746f6b656e0378797a00045f656e73076d61746f6b656e0378797a00001000010000012c002d2c613d307835614263373734396430636432623432313939313233323361343233343932434441333531334232", "5f4b691d6c321e7e4f0d885d18ad962f38176bb8ddf23c9f4d60cd38ead846406787a12efc2891787fe4f35b344a21658fe1973dc2b6b8c8b41211cf23b0dc086d8171d6dcc35d86e7fed3257c4301a3ed6aa6f379cbeb7ce47c5cd9d7119cb400e39b1bae4dd1189700efc4cff6c9874551a033b752ee7744cb6b0121bfdcad"],
];

async function verifySubmission(instance, name, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }
  console.log('verifySubmission', name);
  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(name, data, sig, proof);
  assert.equal(parseInt(tx.receipt.status), parseInt('0x1'));
  assert.equal(tx.logs.length, 1);
  assert.equal(tx.logs[0].args.name, name);
  return tx;
}

async function verifyFailedSubmission(instance, name, data, sig, proof) {
  if(proof === undefined) {
    proof = await instance.anchors();
  }

  var name = dns.hexEncodeName(name);
  try{
    var tx = await instance.submitRRSet(name, data, sig, proof);
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
  // it('should have a default algorithm and digest set', async function() {
  //   var instance = await dnssec.deployed();
  //   assert.notEqual(await instance.algorithms(8), "0x0000000000000000000000000000000000000000");
  //   assert.notEqual(await instance.algorithms(253), "0x0000000000000000000000000000000000000000");
  //   assert.notEqual(await instance.digests(2), "0x0000000000000000000000000000000000000000");
  //   assert.notEqual(await instance.digests(253), "0x0000000000000000000000000000000000000000");
  // });

  // function rootKeys() {
  //   return {
  //     typeCovered: dns.TYPE_DNSKEY,
  //     algorithm: 253,
  //     labels: 0,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
  //       {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 4, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
  //       {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
  //     ],
  //   };
  // };

  // it("should reject signatures with non-matching algorithms", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.rrs = [
  //     {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: new Buffer("1111", "HEX")}
  //   ];
  //   await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // it("should reject signatures with non-matching keytags", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.rrs = [
  //     {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
  //   ];
  //   await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // it("should reject signatures by keys without the ZK bit set", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.rrs = [
  //     {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: new Buffer("1211", "HEX")}
  //   ];
  //   await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // var rootKeyProof = undefined;
  // it('should accept a root DNSKEY', async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   var tx = await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  //   rootKeyProof = tx.logs[0].args.rrset;
  // });

  // it('should check if root DNSKEY exist', async function(){
  //   var instance = await dnssec.deployed();
  //   var [_, _, rrs] = await instance.rrdata.call(dns.TYPE_DNSKEY, dns.hexEncodeName('nonexisting.'));
  //   assert.equal(rrs, '0x0000000000000000000000000000000000000000');
  //   [_, _, rrs] = await instance.rrdata.call(dns.TYPE_DNSKEY, dns.hexEncodeName('.'));
  //   assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
  // })

  // it('should accept a signed RRSET', async function() {
  //   var instance = await dnssec.deployed();
  //   var proof = dns.hexEncodeRRs(rootKeys().rrs);
  //   await verifySubmission(instance, "test.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_TXT,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 1,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "test.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["test"]}
  //     ],
  //   }), "0x", proof);
  // });

  // it('should reject signatures with non-matching classes', async function() {
  //   var instance = await dnssec.deployed();
  //   await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_TXT,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "net.", type: dns.TYPE_TXT, klass: 2, ttl: 3600, text: ["foo"]}
  //     ],
  //   }), "0x");
  // })

  // it('should reject signatures with non-matching names', async function() {
  //   var instance = await dnssec.deployed();
  //   await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_TXT,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "foo.net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
  //     ],
  //   }), "0x");
  // });

  // it('should reject signatures with the wrong type covered', async function() {
  //   var instance = await dnssec.deployed();
  //   await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_DS,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
  //     ],
  //   }), "0x");
  // });

  // it('should reject signatures with too many labels', async function() {
  //   var instance = await dnssec.deployed();
  //   await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_TXT,
  //     algorithm: 253,
  //     labels: 2,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
  //     ],
  //   }), "0x");
  // });

  // it('should support wildcard subdomains', async function() {
  //   var instance = await dnssec.deployed();
  //   var proof = dns.hexEncodeRRs(rootKeys().rrs);
  //   await verifySubmission(instance, "foo.net.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_TXT,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 1,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "*.net.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
  //     ],
  //   }), "0x", proof);
  // });

  // it('should reject signatures with invalid signer names', async function() {
  //   var instance = await dnssec.deployed();

  //   await verifySubmission(instance, "net.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_DNSKEY,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [
  //       {name: "net.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")}
  //     ]
  //   }), "0x");

  //   await verifyFailedSubmission(instance, "com.", dns.hexEncodeSignedSet({
  //     typeCovered: dns.TYPE_TXT,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 0,
  //     keytag: 5647,
  //     signerName: "net.",
  //     rrs: [
  //       {name: "com.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
  //     ],
  //   }), "0x");
  // });

  // it("should reject entries with expirations in the past", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.inception = 1;
  //   keys.expiration = 123;
  //   await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // it("should reject entries with inceptions in the future", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.inception = 0xFFFFFFFF;
  //   await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // it("should accept updates with newer signatures", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.inception = 1;
  //   await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // it("should reject entries that are older", async function() {
  //   var instance = await dnssec.deployed();
  //   var keys = rootKeys();
  //   keys.inception = 0;
  //   await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  // });

  // it('should reject invalid RSA signatures', async function() {
  //   var instance = await dnssec.deployed();
  //   var sig = test_rrsets[0][2];
  //   await verifyFailedSubmission(instance, test_rrsets[0][0], "0x" + test_rrsets[0][1], "0x" + sig.slice(0, sig.length - 2) + "FF");
  // });

  // // Test delete RRSET
  // async function checkPresence(instance, type, name){
  //   var result = (await instance.rrdata.call(type, dns.hexEncodeName(name)))[2];
  //   return result != '0x0000000000000000000000000000000000000000';
  // }

  // async function submitEntry(instance, type, name, option, proof){
  //   var rrs = {name: name, type: type, klass: 1, ttl: 3600};
  //   Object.assign(rrs, option)
  //   var keys = {
  //     typeCovered: type,
  //     algorithm: 253,
  //     labels: 1,
  //     originalTTL: 3600,
  //     expiration: 0xFFFFFFFF,
  //     inception: 1,
  //     keytag: 5647,
  //     signerName: ".",
  //     rrs: [rrs],
  //   };
  //   var [inception, _, rrs] = await instance.rrdata.call(type, dns.hexEncodeName(name));
  //   if(rrs != '0x0000000000000000000000000000000000000000'){
  //     keys.inception = inception + 1;
  //   };
  //   tx = await verifySubmission(instance, name, dns.hexEncodeSignedSet(keys), "0x", proof);
  //   [_, _, rrs] = await instance.rrdata.call(type, dns.hexEncodeName(name));
  //   assert.notEqual(rrs, '0x0000000000000000000000000000000000000000');
  //   return tx;
  // }

  // async function deleteEntry(instance, deletetype, deletename, ensname, proof) {
  //   var tx, result;
  //   try{
  //     tx = await instance.deleteRRSet(deletetype, dns.hexEncodeName(deletename), dns.hexEncodeName(ensname), proof);
  //   }
  //   catch(error){
  //     // Assert ganache revert exception
  //     assert.equal(error.message, 'VM Exception while processing transaction: revert');
  //     result = false;
  //   }
  //   // Assert geth failed transaction
  //   if(tx !== undefined) {
  //     result = (parseInt(tx.receipt.status) == parseInt('0x1'));
  //   }
  //   return result;
  // }

  // it('rejects if a proof with the wrong type is supplied', async function(){
  //   var instance = await dnssec.deployed();
  //   await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]}, rootKeyProof);
  //   // Submit with a proof for an irrelevant record.
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.', 'a.', rootKeyProof)), false);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.')), true);
  // })

  // it('rejects if next record does not come before the deleting name', async function(){
  //   var instance = await dnssec.deployed();
  //   // text z. comes after next d.
  //   await submitEntry(instance, dns.TYPE_TXT, 'z.', {text: ["foo"]}, rootKeyProof);
  //   var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', {next:'d.', rrtypes:[dns.TYPE_TXT]}, rootKeyProof);
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'z.', 'a.', tx.logs[0].args.rrset)), false);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'z.')), true);
  // })

  // it('rejects if nsec record starts after the deleting name', async function(){
  //   var instance = await dnssec.deployed();
  //   // text a. comes after nsec b.
  //   await submitEntry(instance, dns.TYPE_TXT, 'a.', {text: ["foo"]}, rootKeyProof);
  //   var tx = await submitEntry(instance, dns.TYPE_NSEC, 'b.', {next:'d.', rrtypes:[dns.TYPE_TXT]}, rootKeyProof);
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'b.', tx.logs[0].args.rrset)), false);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  // })

  // it('rejects RRset if trying to delete rrset that is in the type bitmap', async function(){
  //   var instance = await dnssec.deployed();
  //   // text a. has same nsec a. with type bitmap
  //   await submitEntry(instance, dns.TYPE_TXT, 'a.', { text:['foo']}, rootKeyProof);
  //   var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_TXT] }, rootKeyProof);
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'a.', tx.logs[0].args.rrset)), false);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  // })

  // it('deletes RRset if nsec name and delete name are the same but with different rrtypes', async function(){
  //   var instance = await dnssec.deployed();
  //   await submitEntry(instance, dns.TYPE_TXT,  'a.', { text: ["foo"] }, rootKeyProof);
  //   // This test fails if rrtypes is empty ([]), but would that case every happen?
  //   var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_NSEC] }, rootKeyProof);
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'a.', tx.logs[0].args.rrset)), true);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), false);
  // })

  // it('rejects if the proof hash does not match', async function(){
  //   var instance = await dnssec.deployed();
  //   await submitEntry(instance, dns.TYPE_TXT,  'a.', { text: ["foo"] }, rootKeyProof);
  //   // This test fails if rrtypes is empty ([]), but would that case every happen?
  //   var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_NSEC] }, rootKeyProof);
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'a.', 'a.', tx.logs[0].args.rrset + '00')), false);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'a.')), true);
  // })

  // it('deletes RRset if NSEC next comes after delete name', async function(){
  //   var instance = await dnssec.deployed();
  //   await submitEntry(instance, dns.TYPE_TXT, 'b.', {text: ["foo"]}, rootKeyProof);
  //   var tx = await submitEntry(instance, dns.TYPE_NSEC, 'a.', { next:'d.', rrtypes:[dns.TYPE_TXT] }, rootKeyProof);
  //   assert.equal((await deleteEntry(instance, dns.TYPE_TXT, 'b.', 'a.', tx.logs[0].args.rrset)), true);
  //   assert.equal((await checkPresence(instance, dns.TYPE_TXT, 'b.')), false);
  // })

  // Test against real record
  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var proof = await instance.anchors();
    for(var rrset of test_rrsets) {
      console.log('0', rrset[0]);
      console.log('1', rrset[1]);
      console.log('2', rrset[2]);
      console.log('proof', proof);
      var tx = await verifySubmission(instance, rrset[0], "0x" + rrset[1], "0x" + rrset[2], proof);
      assert.equal(tx.logs.length, 1);
      assert.equal(tx.logs[0].event, 'RRSetUpdated');
      proof = tx.logs[0].args.rrset;
    }
  });
});
