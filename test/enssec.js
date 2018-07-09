var base32hex = require('rfc4648').base32hex;
var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./DNSSEC.sol");

const test_rrsets = [
    // .	89907	IN	RRSIG	DNSKEY 8 0 172800 20180722000000 20180701000000 19036 . I3gcUYC8GwZmq4TTEy1SFxvFyZuCvGCiosqlQ1MPBbsLz4GXUkw7jcbbtgBfsZXPTtxIuPnOLamt6yHHGadAUxcDdH6YX9ots2yS5n1Qy56maFyboEcFc77V9945b16lCKwyitks+7tGDanG1tb/XhNgpGFw0+rurdb3p6wKvQvMUbyQIu8u0WGbcR1SiFD6zLlJdD6upIYQyYDKMI6YgYP2UQqbGiEkbmdPWOKHvKDc85+BRvcaRng7+SYk1aCFRqzVg/m9MNSaeSgOP0Nwo3YvTFRDy/jMEyWAoujNopUCR8lFPqcV9DCLXh2tFSH7G8fdeB3234RyPPx6VK/xCQ==
    // .	89907	IN	DNSKEY	256 3 8 AwEAAdU4aKlDgEpXWWpH5aXHJZI1Vm9Cm42mGAsqkz3akFctS6zsZHC3pNNMug99fKa7OW+tRHIwZEc//mX8Jt6bcw5bPgRHG6u2eT8vUpbXDPVs1ICGR6FhlwFWEOyxbIIiDfd7Eq6eALk5RNcauyE+/ZP+VdrhWZDeEWZRrPBLjByBWTHl+v/f+xvTJ3Stcq2tEqnzS2CCOr6RTJepprYhu+5Yl6aRZmEVBK27WCW1Zrk1LekJvJXfcyKSKk19C5M5JWX58px6nB1IS0pMs6aCIK2yaQQVNUEg9XyQzBSv/rMxVNNy3VAqOjvh+OASpLMm4GECbSSe8jtjwG0I78sfMZc=
    // .	89907	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
    // .	89907	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
    // .	89907	IN	DNSKEY	256 3 8 AwEAAfaifSqh+9ItxYRCwuiY0FY2NkaEwd/zmyVvakixDgTOkgG/PUzlEauAiKzlxGwezjqbKFPSwrY3qHmbbsSTY6G8hZtna8k26eCwy59Chh573cu8qtBkmUIXMYG3fSdlUReP+uhBWBfKI2aGwhRmQYR0zSmg7PGOde34c/rOItK1ebJhjTAJ6TmnON7qMfk/lKvH4qOvYtzstLhr7Pn9ZOVLx/WUKQpU/nEyFyTduRbz1nZqkp6yMuHwWVsABK8lUYXSaUrDAsuMSldhafmR/A15BxNhv9M7mzJj7UH2RVME9JbYinBEzWwW9GpnY+ZmBWgZiRVTaDuemCTJ5ZJWLRs=
    [".", "003008000002a3005b53c9005b3819804a5c0000003000010002a30001080100030803010001d53868a943804a57596a47e5a5c7259235566f429b8da6180b2a933dda90572d4bacec6470b7a4d34cba0f7d7ca6bb396fad44723064473ffe65fc26de9b730e5b3e04471babb6793f2f5296d70cf56cd4808647a16197015610ecb16c82220df77b12ae9e00b93944d71abb213efd93fe55dae15990de116651acf04b8c1c815931e5faffdffb1bd32774ad72adad12a9f34b60823abe914c97a9a6b621bbee5897a69166611504adbb5825b566b9352de909bc95df7322922a4d7d0b93392565f9f29c7a9c1d484b4a4cb3a68220adb2690415354120f57c90cc14affeb33154d372dd502a3a3be1f8e012a4b326e061026d249ef23b63c06d08efcb1f319700003000010002a30001080100030803010001f6a27d2aa1fbd22dc58442c2e898d05636364684c1dff39b256f6a48b10e04ce9201bf3d4ce511ab8088ace5c46c1ece3a9b2853d2c2b637a8799b6ec49363a1bc859b676bc936e9e0b0cb9f42861e7bddcbbcaad0649942173181b77d276551178ffae8415817ca236686c21466418474cd29a0ecf18e75edf873face22d2b579b2618d3009e939a738deea31f93f94abc7e2a3af62dcecb4b86becf9fd64e54bc7f594290a54fe71321724ddb916f3d6766a929eb232e1f0595b0004af255185d2694ac302cb8c4a576169f991fc0d79071361bfd33b9b3263ed41f6455304f496d88a7044cd6c16f46a6763e666056819891553683b9e9824c9e592562d1b00003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "23781c5180bc1b0666ab84d3132d52171bc5c99b82bc60a2a2caa543530f05bb0bcf8197524c3b8dc6dbb6005fb195cf4edc48b8f9ce2da9adeb21c719a740531703747e985fda2db36c92e67d50cb9ea6685c9ba0470573bed5f7de396f5ea508ac328ad92cfbbb460da9c6d6d6ff5e1360a46170d3eaeeadd6f7a7ac0abd0bcc51bc9022ef2ed1619b711d528850faccb949743eaea48610c980ca308e988183f6510a9b1a21246e674f58e287bca0dcf39f8146f71a46783bf92624d5a08546acd583f9bd30d49a79280e3f4370a3762f4c5443cbf8cc132580a2e8cda2950247c9453ea715f4308b5e1dad1521fb1bc7dd781df6df84723cfc7a54aff109"],

    // xyz.	57080	IN	RRSIG	DS 8 1 86400 20180721170000 20180708160000 41656 . vrBWpWBGTqA+rELrgE1KhDUrbhIXxC/aUTUjgOGb5Nh81Hi+9fKZbaJcyjGSEuIyNwywhimaZkU9tmR3+NRmyiKbWgRkC10gj4uAZz5W0aEgZ/O7D66g7FgL1ia0GSUMVxckC4z9knpaozQdhqizjZb4GCuBSfGJIZ8fb3aI5C33grQSC1jROnrrHeSipA9eSEOsMwbXlA5XG0+ypuPmWbwNzF0v5yICtxZxqZ1Mvh+IWf2Sj2lSTWH/zAaTPbioEd0ZlPm8If7d1fWRiycaOAVazE6RzlTDd4Urzs2fYzHSzM60NnLI87mqt28naE+MD4FeH7Qbg+zpoM5Tr6Kv8g==
    // xyz.	57080	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
    // xyz.	57080	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
    ["xyz.", "002b0801000151805b5366905b423500a2b8000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "beb056a560464ea03eac42eb804d4a84352b6e1217c42fda51352380e19be4d87cd478bef5f2996da25cca319212e232370cb086299a66453db66477f8d466ca229b5a04640b5d208f8b80673e56d1a12067f3bb0faea0ec580bd626b419250c5717240b8cfd927a5aa3341d86a8b38d96f8182b8149f189219f1f6f7688e42df782b4120b58d13a7aeb1de4a2a40f5e4843ac3306d7940e571b4fb2a6e3e659bc0dcc5d2fe72202b71671a99d4cbe1f8859fd928f69524d61ffcc06933db8a811dd1994f9bc21feddd5f5918b271a38055acc4e91ce54c377852bcecd9f6331d2ccceb43672c8f3b9aab76f27684f8c0f815e1fb41b83ece9a0ce53afa2aff2"],

    // xyz.	3599	IN	RRSIG	DNSKEY 8 1 3600 20180713103547 20180613193436 3599 xyz. NKAsxzPw55cq8rjhAtCuv5tWBCo4VKq11VybLZ4AX2ms3e2gxGhjsjNqhro0Nm8MS3Jk2lWZ4hgn9mNnuwHAnktbnZwLiNpY/wilaf6pem6gztbM7YP2XoAJdLS1uG0vff+KQcwRSaOUdJ5OEsyOG9m8oLyjIx3uKGmmWfJspmYV0UrHsEJ10WkyVXWBttPKEbcEHG08+s0EcpJUO0CR0fwKsllP1XxX3QiNLIqKs4KNPQyk/u9ECgWYQ16tGLu80s1cD/W1qtKSorf+g4qFTun2K09qJN3MuUSf7QDSMoFGkQM+aohT5eaPiAU+d5sTy3cYXYALH9i+sk3OJjc5dA==
    // xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
    // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAbi90iT9b2z/i2CJyxKwJk7wVxTBizJhqB7Uabh55DwvDiBRUP3GMw1Qsng01aC4Ve92SUVBc3LIBTJ1FerN2OnByWBAnjizWuOn9RSGFlehJSbtHNdMlUktiyRxM+6j9/DUR1UYZCCChwuzkaQtNH5e4EKX5PhjwMeT2GfOg69v
    // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAcG3mVoA5PySdVgn2u2ocpY4cdVU5BW9CoS4jnuWLNPcb93j0NukPnb3Ejj8WispeShLzuf0Z2bRD2w5oCCd2QE9/E9Z6Dvk/lTEhBaz20jeqrfs1rc1qV5wxwQK6UiYrmmsjdqk0PQbDmebQVCB1WUwUHQGgM/JP5H87ULqx8Bj
    ["xyz.", "0030080100000e105b4880835b2171cc0e0f0378797a000378797a000030000100000e1000880100030803010001b8bdd224fd6f6cff8b6089cb12b0264ef05714c18b3261a81ed469b879e43c2f0e205150fdc6330d50b27834d5a0b855ef764945417372c805327515eacdd8e9c1c960409e38b35ae3a7f514861657a12526ed1cd74c95492d8b247133eea3f7f0d4475518642082870bb391a42d347e5ee04297e4f863c0c793d867ce83af6f0378797a000030000100000e1000880100030803010001c1b7995a00e4fc92755827daeda872963871d554e415bd0a84b88e7b962cd3dc6fdde3d0dba43e76f71238fc5a2b2979284bcee7f46766d10f6c39a0209dd9013dfc4f59e83be4fe54c48416b3db48deaab7ecd6b735a95e70c7040ae94898ae69ac8ddaa4d0f41b0e679b415081d5653050740680cfc93f91fced42eac7c0630378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "34a02cc733f0e7972af2b8e102d0aebf9b56042a3854aab5d55c9b2d9e005f69acddeda0c46863b2336a86ba34366f0c4b7264da5599e21827f66367bb01c09e4b5b9d9c0b88da58ff08a569fea97a6ea0ced6cced83f65e800974b4b5b86d2f7dff8a41cc1149a394749e4e12cc8e1bd9bca0bca3231dee2869a659f26ca66615d14ac7b04275d16932557581b6d3ca11b7041c6d3cfacd047292543b4091d1fc0ab2594fd57c57dd088d2c8a8ab3828d3d0ca4feef440a0598435ead18bbbcd2cd5c0ff5b5aad292a2b7fe838a854ee9f62b4f6a24ddccb9449fed00d232814691033e6a8853e5e68f88053e779b13cb77185d800b1fd8beb24dce26373974"],

    // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20180726154739 20180626183802 55203 xyz. OZW+Ii24CIKiS9zfaDKvpUuKfZ4KFTXTXKVJsz9lfIzZzywh5ydSn14bAeRIQaAx6subVohZWwazaCZawwTxg2bHIiaKaYEHyTzVHtEMO/bhG+eftyJhG3iZx7cfmzmTAJeAm3L1EQ4oaz5erI+ypB7fMZsH9/oSCzAGuBy+sZ4=
    // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
    // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
    ["ethlab.xyz.", "002b080200000e105b59ed1b5b32880ad7a30378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "3995be222db80882a24bdcdf6832afa54b8a7d9e0a1535d35ca549b33f657c8cd9cf2c21e727529f5e1b01e44841a031eacb9b5688595b06b368265ac304f18366c722268a698107c93cd51ed10c3bf6e11be79fb722611b7899c7b71f9b39930097809b72f5110e286b3e5eac8fb2a41edf319b07f7fa120b3006b81cbeb19e"],

    // ethlab.xyz.	3599	IN	RRSIG	DNSKEY 8 2 3600 20330427133000 20180516123000 42999 ethlab.xyz. OE5dzOx68Rsi1PKOAuzo2ALP972ZNI//loIzVKtyLY9gD5nXQTYeb8+uLFqLYmnUKOHQ9PzdJINnGz2urDsjig==
    // ethlab.xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
    // ethlab.xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
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
