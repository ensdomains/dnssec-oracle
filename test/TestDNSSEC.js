var base32hex = require('rfc4648').base32hex;
const anchors = require("../lib/anchors.js");
const packet = require('dns-packet');
const types = require('dns-packet/types');

var dnssec = artifacts.require("./DNSSECImpl");
const Result = require('@ensdomains/dnsprovejs/dist/dns/result')

const test_rrsets = [
    // .	92478	IN	RRSIG	DNSKEY 8 0 172800 20181221000000 20181130000000 20326 . NGhrAoMGpLEivdICl6xZoDQkxVHjlIndYueDrSr5CCvfSRvB5US/lDtZwxjm4rVSE4Gykc1iKgfx3Juv4/BSG9PlXUuCqqi7ia4kDbHD0KWIuThzcDPPmxm1Pk9Ug2qo1Tk6JU1/1s7IFwf11bQvf+YO8BYTE8bnULq5LZlpAuOjFbidarPoijGRUK9uYpkCxthxfd9wMvjnL+wF/UtIR0qRHcYNKsGaj0Tmt/9lCj1MtaVQBvqoBjdfCs6Ie2cziZQ3Jx8NcSW+4AZ3IYjDLde0iT1IgPm3u4b0t2qFKbfrPlYcx/O0ODKrBrXWH6nFGdXUJEEz799ZVb/ErjdnVg==
    // .	92478	IN	DNSKEY	256 3 8 AwEAAdp440E6Mz7c+Vl4sPd0lTv2Qnc85dTW64j0RDD7sS/zwxWDJ3QRES2VKDO0OXLMqVJSs2YCCSDKuZXpDPuf++YfAu0j7lzYYdWTGwyNZhEaXtMQJIKYB96pW6cRkiG2Dn8S2vvo/PxW9PKQsyLbtd8PcwWglHgReBVp7kEv/Dd+3b3YMukt4jnWgDUddAySg558Zld+c9eGWkgWoOiuhg4rQRkFstMX1pRyOSHcZuH38o1WcsT4y3eT0U/SR6TOSLIB/8Ftirux/h297oS7tCcwSPt0wwry5OFNTlfMo8v7WGurogfk8hPipf7TTKHIi20LWen5RCsvYsQBkYGpF78=
    // .	92478	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
    // .	92478	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
    [".", "003008000002a3005c1c2d005c007d804f660000003000010002a30001080100030803010001da78e3413a333edcf95978b0f774953bf642773ce5d4d6eb88f44430fbb12ff3c31583277411112d952833b43972cca95252b366020920cab995e90cfb9ffbe61f02ed23ee5cd861d5931b0c8d66111a5ed31024829807dea95ba7119221b60e7f12dafbe8fcfc56f4f290b322dbb5df0f7305a0947811781569ee412ffc377eddbdd832e92de239d680351d740c92839e7c66577e73d7865a4816a0e8ae860e2b411905b2d317d694723921dc66e1f7f28d5672c4f8cb7793d14fd247a4ce48b201ffc16d8abbb1fe1dbdee84bbb4273048fb74c30af2e4e14d4e57cca3cbfb586baba207e4f213e2a5fed34ca1c88b6d0b59e9f9442b2f62c4019181a917bf00003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "34686b028306a4b122bdd20297ac59a03424c551e39489dd62e783ad2af9082bdf491bc1e544bf943b59c318e6e2b5521381b291cd622a07f1dc9bafe3f0521bd3e55d4b82aaa8bb89ae240db1c3d0a588b938737033cf9b19b53e4f54836aa8d5393a254d7fd6cec81707f5d5b42f7fe60ef0161313c6e750bab92d996902e3a315b89d6ab3e88a319150af6e629902c6d8717ddf7032f8e72fec05fd4b48474a911dc60d2ac19a8f44e6b7ff650a3d4cb5a55006faa806375f0ace887b6733899437271f0d7125bee006772188c32dd7b4893d4880f9b7bb86f4b76a8529b7eb3e561cc7f3b43832ab06b5d61fa9c519d5d4244133efdf5955bfc4ae376756"],

    // xyz.	83249	IN	RRSIG	DS 8 1 86400 20181217050000 20181204040000 2134 . Ns7RoM1FSSmexCVS1weXqHtBtzpbDY7yW/WsjSkR2qr8pL1uRe3pQCz9Jpv2HMuXq99Mx0E+3FoFJXKoBV02GQziwUF6on1bkPb0OA2um1ROFlHRtdHC3Fl50xamdBhX7ssSURHyCVWqhtEnHukn87+igFdCNUqtQRjs4Rx6fI2svGeYSaycQENOaMA6MoB3kTMwcGr+dYJkhZ3/mZvrASM0atfpQ918YQDhbNOUgIsjLzIV06ISv+QU1AaFCajcvlcGTAJv9YWss9qkQLqzlFYsvHEm1C3Gy5ZyqA+h/FPxY2iEpllUSec07VmT5bixDQd9eGEPmzITMMynO7jcGQ==
    // xyz.	83249	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
    // xyz.	83249	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
    ["xyz.", "002b0801000151805c172d505c05fbc00856000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "36ced1a0cd4549299ec42552d70797a87b41b73a5b0d8ef25bf5ac8d2911daaafca4bd6e45ede9402cfd269bf61ccb97abdf4cc7413edc5a052572a8055d36190ce2c1417aa27d5b90f6f4380dae9b544e1651d1b5d1c2dc5979d316a6741857eecb125111f20955aa86d1271ee927f3bfa2805742354aad4118ece11c7a7c8dacbc679849ac9c40434e68c03a328077913330706afe758264859dff999beb0123346ad7e943dd7c6100e16cd394808b232f3215d3a212bfe414d4068509a8dcbe57064c026ff585acb3daa440bab394562cbc7126d42dc6cb9672a80fa1fc53f1636884a6595449e734ed5993e5b8b10d077d78610f9b321330cca73bb8dc19"],

    // xyz.	3599	IN	RRSIG	DNSKEY 8 1 3600 20181225142613 20181125095514 3599 xyz. jp3YrIpsk753l5z27ublBitTA428T3dxMzSxr+0ON/4H2gGyRJP9h7RIW0mg5mngHtm3hBbyXeLbu0P4oqEAvOQ2hOvTCKtMlbOcqWkMVSOXmvIFS5y3kkELjpbjVmDpZU/aaR8YhDzOPkKltCxC1dR1a7JaFGX9IIdMEmSnYXZLugfsebyrZT7G/byu6+5uF0wNaKKgzyxVUKLIJ8gXTV/Bfhk9meBqvkkHhtcOyHhhcnXEaUB78mlG5s12POcmbhpCv1U6FNzILo+2KT2YX/Oo8hd/BpJS+6KYkqJ/JXyM9dOZ1cZHMch2Mgjnv1vPB/PanI4Zxutd/zUhTZBD4Q==
    // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAZtrWHvfT23xrg5tdWj+CMzj4b/ERa/atL/TxokA7Hh9n0SDzoBX6zmRk/cKfW1oHhjKGB57pClqhF9qddD0qjkddjjLqHT9VfxrKtb5/STZQviCVPKWEWnnuqyn09HmIN+iCzZkuVJHb2JXDcdIuNsF6nuvIok3H2qZikel1vbZ
    // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdjZhkaV7KzpysXw1hmEWyoqyis1SAAtMGCHGUIQmXZ6BlRzqDlKd5dyj7a1HWUFHmLPlnoSj45vJbXOoWqrPHZuK9YmIFqmRWh+lJ7eBK8j8uIfpiLrSU9A0WbX3qVox/N7Rcrl2NiHM2uAuL0i3UU6GWwP9e+kyuAZVJDyDci1
    // xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
    ["xyz.", "0030080100000e105c223e055bfa71820e0f0378797a000378797a000030000100000e10008801000308030100019b6b587bdf4f6df1ae0e6d7568fe08cce3e1bfc445afdab4bfd3c68900ec787d9f4483ce8057eb399193f70a7d6d681e18ca181e7ba4296a845f6a75d0f4aa391d7638cba874fd55fc6b2ad6f9fd24d942f88254f2961169e7baaca7d3d1e620dfa20b3664b952476f62570dc748b8db05ea7baf2289371f6a998a47a5d6f6d90378797a000030000100000e1000880100030803010001d8d9864695ecace9cac5f0d619845b2a2aca2b3548002d30608719421099767a065473a8394a7797728fb6b51d65051e62cf967a128f8e6f25b5cea16aab3c766e2bd626205aa645687e949ede04af23f2e21fa622eb494f40d166d7dea568c7f37b45cae5d8d887336b80b8bd22dd453a196c0ff5efa4cae0195490f20dc8b50378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "8e9dd8ac8a6c93be77979cf6eee6e5062b53038dbc4f77713334b1afed0e37fe07da01b24493fd87b4485b49a0e669e01ed9b78416f25de2dbbb43f8a2a100bce43684ebd308ab4c95b39ca9690c5523979af2054b9cb792410b8e96e35660e9654fda691f18843cce3e42a5b42c42d5d4756bb25a1465fd20874c1264a761764bba07ec79bcab653ec6fdbcaeebee6e174c0d68a2a0cf2c5550a2c827c8174d5fc17e193d99e06abe490786d70ec878617275c469407bf26946e6cd763ce7266e1a42bf553a14dcc82e8fb6293d985ff3a8f2177f069252fba29892a27f257c8cf5d399d5c64731c8763208e7bf5bcf07f3da9c8e19c6eb5dff35214d9043e1"],

    // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20181225141755 20181125095514 52053 xyz. zQilLKtDq6LnWAJ2/VbAiJG25KUQSyci4075VeAplCajY1rFwsk/cylFgn/Ok8C9gF36iua1YWxl2Sbc6L7WV1hsRgc67mA5MXzRvfZHW00YNEuq5NinvMbQ42XXnv0FBzkLMuzfj/m6bsZ96d23532T1q/XVo7P9GNKTDeKEEI=
    // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
    // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
    ["ethlab.xyz.", "002b080200000e105c223c135bfa7182cb550378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "cd08a52cab43aba2e7580276fd56c08891b6e4a5104b2722e34ef955e0299426a3635ac5c2c93f732945827fce93c0bd805dfa8ae6b5616c65d926dce8bed657586c46073aee6039317cd1bdf6475b4d18344baae4d8a7bcc6d0e365d79efd0507390b32ecdf8ff9ba6ec67de9ddb7e77d93d6afd7568ecff4634a4c378a1042"],

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

    var tx = await instance.submitRRSet(data, sig, proof); // @todo we revert here for some fucking reason

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
        // @TODO use: https://github.com/ensdomains/root/blob/master/test/helpers/Utils.js#L8
        // Assert ganache revert exception
        assert.equal(error.message, 'Returned error: VM Exception while processing transaction: revert');
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
        let result = await instance.rrdata.call(types.toType(type), hexEncodeName(name));
        var inception = result['0'];
        var rrs = result['2'];

        if(inception >= keys.sig.data.inception) {
            keys.sig.data.inception = inception + 1;
        }
        tx = await verifySubmission(instance, hexEncodeSignedSet(keys)[0], "0x", proof);
        var res = await instance.rrdata.call(types.toType(type), hexEncodeName(name));
        assert.notEqual(res['2'], '0x0000000000000000000000000000000000000000');
        return tx;
    }

    async function deleteEntry(instance, deletetype, deletename, nsec, proof) {
        var tx, result;
        try{
            tx = await instance.deleteRRSet(types.toType(deletetype), hexEncodeName(deletename), nsec, "0x", proof);
        }
        catch(error){
            // Assert ganache revert exception
            assert.equal(error.message, 'Returned error: VM Exception while processing transaction: revert');
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
        await submitEntry(instance, 'TXT', 'b', Buffer.from('foo', 'ascii'), rootKeyProof);
        // Submit with a proof for an irrelevant record.
        assert.equal((await deleteEntry(instance, 'TXT', 'b', hexEncodeSignedSet(rootKeys())[0], rootKeyProof)), false);
        assert.equal((await checkPresence(instance, 'TXT', 'b')), true);
    })

    it('rejects if next record does not come before the deleting name', async function(){
        var instance = await dnssec.deployed();
        // text z. comes after next d.
        await submitEntry(instance, 'TXT',    'z', Buffer.from('foo', 'ascii'), rootKeyProof);
        var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
        assert.equal((await deleteEntry(instance, 'TXT', 'z', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
        assert.equal((await checkPresence(instance, 'TXT', 'z')), true);
    })

    it('rejects if nsec record starts after the deleting name', async function(){
        var instance = await dnssec.deployed();
        // text a. comes after nsec b.
        await submitEntry(instance, 'TXT',    'a', Buffer.from('foo', 'ascii'), rootKeyProof);
        var nsec = buildEntry('NSEC', 'b', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
        assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
        assert.equal((await checkPresence(instance, 'TXT', 'a')), true);
    })

    it('rejects RRset if trying to delete rrset that is in the type bitmap', async function(){
        var instance = await dnssec.deployed();
        // text a. has same nsec a. with type bitmap
        await submitEntry(instance, 'TXT',    'a', Buffer.from('foo', 'ascii'), rootKeyProof);
        var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['TXT']}, {inception: 1000});
        assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0], rootKeyProof)), false);
        assert.equal((await checkPresence(instance, 'TXT', 'a')), true);
    })

    it('deletes RRset if nsec name and delete name are the same but with different rrtypes', async function(){
        var instance = await dnssec.deployed();
        await submitEntry(instance, 'TXT',    'a', Buffer.from('foo', 'ascii'), rootKeyProof);
        // This test fails if rrtypes is empty ([]), but would that case every happen?
        var nsec = buildEntry('NSEC', 'a', { nextDomain:'d', rrtypes:['NSEC']}, {inception: 1000});
        assert.equal((await deleteEntry(instance, 'TXT', 'a', hexEncodeSignedSet(nsec)[0], rootKeyProof)), true);
        assert.equal((await checkPresence(instance, 'TXT', 'a')), false);
    })

    it('rejects if the proof hash does not match', async function(){
        var instance = await dnssec.deployed();
        await submitEntry(instance, 'TXT',    'a', Buffer.from('foo', 'ascii'), rootKeyProof);
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
