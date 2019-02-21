var base32hex = require('rfc4648').base32hex;
const anchors = require("../lib/anchors.js");
const packet = require('dns-packet');
const types = require('dns-packet/types');

var dnssec = artifacts.require("./DNSSECImpl");
const Result = require('@ensdomains/dnsprovejs/dist/dns/result')

// When the real test start failing due to ttl expiration, you can generate the new test dataset at https://dnssec.ens.domains/?domain=ethlab.xyz&mode=advanced
const test_rrsets = [
    // .	35429	IN	RRSIG	DNSKEY 8 0 172800 20190313000000 20190220000000 20326 . bKvs4iBtsS7x4UItBsNxJnGzKUowmON76AJt6DQlUjcDXdmNUGW0DNfwz91UCnfonlNeG09mCbRFzhfrgNiE2Niu0Qxh+EcygOjuy1uObcPgFBUsKp201u0WFQwrUl4O0NQfPY5Fa01e44v1u+L/yj2WK4gW2BKfW+5d9GIJhWRAPYWphOiG0+G1MUlWQ45cS07wu2X90+UDREw0prI0c4yJ9OiI6OnSvUvDhoyIgf5oHHYPieU7qu/aaiY8MdyJgfIelmFA65VzLDsTAHGoaagxJEolJehWSJl6AhY0mIs6lF2WXVCtEQbdLocsuCXln3w/n8jO2oJBotQ7S6E4bQ==
    // .	35429	IN	DNSKEY	256 3 8 AwEAAcH+axCdUOsTc9o+jmyVq5rsGTh1EcatSumPqEfsPBT+whyj0/UhD7cWeixV9Wqzj/cnqs8iWELqhdzGX41ZtaNQUfWNfOriASnWmX2D9m/EunplHu8nMSlDnDcT7+llE9tjk5HI1Sr7d9N16ZTIrbVALf65VB2ABbBG39dyAb7tz21PICJbSp2cd77UF7NFqEVkqohl/LkDw+7Apalmp0qAQT1Mgwi2cVxZMKUiciA6EqS+KNajf0A6olO2oEhZnGGY6b1LTg34/YfHdiIIZQqAfqbieruCGHRiSscC2ZE7iNreL/76f4JyIEUNkt6bQA29JsegxorLzQkpF7NKqZc=
    // .	35429	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
    // .	35429	IN	DNSKEY	385 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
    [web3.utils.toHex("."), "0x003008000002a3005c8848005c6c98804f660000003000010002a30001080100030803010001c1fe6b109d50eb1373da3e8e6c95ab9aec19387511c6ad4ae98fa847ec3c14fec21ca3d3f5210fb7167a2c55f56ab38ff727aacf225842ea85dcc65f8d59b5a35051f58d7ceae20129d6997d83f66fc4ba7a651eef273129439c3713efe96513db639391c8d52afb77d375e994c8adb5402dfeb9541d8005b046dfd77201beedcf6d4f20225b4a9d9c77bed417b345a84564aa8865fcb903c3eec0a5a966a74a80413d4c8308b6715c5930a52272203a12a4be28d6a37f403aa253b6a048599c6198e9bd4b4e0df8fd87c7762208650a807ea6e27abb821874624ac702d9913b88dade2ffefa7f827220450d92de9b400dbd26c7a0c68acbcd092917b34aa99700003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080181030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d", "0x6cabece2206db12ef1e1422d06c3712671b3294a3098e37be8026de834255237035dd98d5065b40cd7f0cfdd540a77e89e535e1b4f6609b445ce17eb80d884d8d8aed10c61f8473280e8eecb5b8e6dc3e014152c2a9db4d6ed16150c2b525e0ed0d41f3d8e456b4d5ee38bf5bbe2ffca3d962b8816d8129f5bee5df462098564403d85a984e886d3e1b5314956438e5c4b4ef0bb65fdd3e503444c34a6b234738c89f4e888e8e9d2bd4bc3868c8881fe681c760f89e53baaefda6a263c31dc8981f21e966140eb95732c3b130071a869a831244a2525e85648997a021634988b3a945d965d50ad1106dd2e872cb825e59f7c3f9fc8ceda8241a2d43b4ba1386d"],

    // xyz.	60563	IN	RRSIG	DS 8 1 86400 20190306050000 20190221040000 16749 . gxkvpoGEt/dQWJdA4TOBe+alMeTsarYW479ng2NtUvxV4qYqFMI3yoPvIOGYUhc/c6ePjIDZYD2M+eVLJtxHAt9FJ0ae6BsKMY3BS9Wv7LIL4gPLdTjOQdhdCy6eNw6p33HZu9TiLyKU5MtodR6Vho5WOXJpX4iZYKgVtO+6cwvTbOlPXxecp6IlX8nZGRSQxRS4OWpyP6LkBoR2voHqHJPgmwaUdmWQhPWjQE3TRkXWln2KIp9HB8d6YO1+vIQK2KYMUDb0ACgU2io2dfFQLjRv2IJpv2vLCo7Qa8q17kxXUdD5pzFn1wQkihT1ina1cuI1JNFdawmhy5UovcjfBw==
    // xyz.	60563	IN	DS	3599 8 1 3FA3B264F45DB5F38BEDEAF1A88B76AA318C2C7F
    // xyz.	60563	IN	DS	3599 8 2 B9733869BC84C86BB59D102BA5DA6B27B2088552332A39DCD54BC4E8D66B0499
    [web3.utils.toHex("xyz."), "0x002b0801000151805c7f53d05c6e2240416d000378797a00002b00010001518000180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b00010001518000240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b0499", "0x83192fa68184b7f750589740e133817be6a531e4ec6ab616e3bf6783636d52fc55e2a62a14c237ca83ef20e19852173f73a78f8c80d9603d8cf9e54b26dc4702df4527469ee81b0a318dc14bd5afecb20be203cb7538ce41d85d0b2e9e370ea9df71d9bbd4e22f2294e4cb68751e95868e563972695f889960a815b4efba730bd36ce94f5f179ca7a2255fc9d9191490c514b8396a723fa2e4068476be81ea1c93e09b069476659084f5a3404dd34645d6967d8a229f4707c77a60ed7ebc840ad8a60c5036f4002814da2a3675f1502e346fd88269bf6bcb0a8ed06bcab5ee4c5751d0f9a73167d704248a14f58a76b572e23524d15d6b09a1cb9528bdc8df07"],

    // xyz.	3599	IN	RRSIG	DNSKEY 8 1 3600 20190311043734 20190208212945 3599 xyz. p12bb0m2ZCH32zN9ZTZUv7RXNHcv9aIGIScfuw4CrMnu28M/WNtXR3ScdF5/W7GcIHL97fX1WWMjQE2xVkFoi8T/v/iBkDm8nLaHuMb7lVr76hQ3etrrITdYXhwPFFEx0OoLiUq0C5OF7vGHiBHwdwIxITKf64NZ+pMK7S2EmqaniDuem5PLq1urzU++IgRx+ZLPwdapjfbzs5EMkDucSCsjqfgWZa3ISDxdUSL61vg3jiD9qMeSN/wTATKTMExbVQi7e5H3WGhqW3xsxgUMIKqmuPj/3x1nrFlxOAtS7wL/gl6lDW4jyvT2BeYW+wiOwYWZD7SFoS9gjQi9NqHAow==
    // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAa5jh93mWraaokFC83dqjRLypC8KijEI9DpGCL9epWGcZoEg2QpFRNaJuYjxASKjqF04TXZFOPLgSLMS6fPy6Cx4cBy4K392cbHBJafUnAecmHd4WJauED8q5OU+AnZbD07J424L9CszIXKFBBIeUXyNVhSgFszjZevNRie/Jk3v
    // xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbYRTzkgLg4oxcFb/+oFQMvluEut45siTtLiNL7t5Fim/ZnYhkxal6TiCUywnfgiycJyneNmtC/3eoTcz5dlrlRB5dwDehcqiZoFiqjaXGHcykHGFBDynD0/sRcEAQL+bLMv2qA+o2L7pDPHbCGJVXlUq57oTWfS4esbGDIa+1Bs8gDVMGUZcbRmeeKkc/MH2Oq1ApE5EKjH0ZRvYWS6afsWyvlXD2NXDthS5LltVKqqjhi6dy2O02stOt41z1qwfRlU89b3HXfDghlJ/L33DE+OcTyK0yRJ+ay4WpBgQJL8GDFKz1hnR2lOjYXLttJD7aHfcYyVO6zYsx2aeHI0OYM=
    // xyz.	3599	IN	DNSKEY	256 3 8 AwEAAalt40QoyM4leOWv7i75lMm29RHqMDt6YNNpOJH/Fc+h3cafnvSJqNziLuJUF+z73C2pfkTG3N4oDXrqo2LdrFG0EJmZjY3tHrmVZsdX8HUSkoVJDxJf70xX4A5DbOw4VZ9iq3NpC7SFra+XaMZ00zr5leonBvVrUw+jrdGDB7X1
    [web3.utils.toHex("xyz."), "0x0030080100000e105c85e60e5c5df4c90e0f0378797a000378797a000030000100000e1000880100030803010001a96de34428c8ce2578e5afee2ef994c9b6f511ea303b7a60d3693891ff15cfa1ddc69f9ef489a8dce22ee25417ecfbdc2da97e44c6dcde280d7aeaa362ddac51b41099998d8ded1eb99566c757f075129285490f125fef4c57e00e436cec38559f62ab73690bb485adaf9768c674d33af995ea2706f56b530fa3add18307b5f50378797a000030000100000e1000880100030803010001ae6387dde65ab69aa24142f3776a8d12f2a42f0a8a3108f43a4608bf5ea5619c668120d90a4544d689b988f10122a3a85d384d764538f2e048b312e9f3f2e82c78701cb82b7f7671b1c125a7d49c079c9877785896ae103f2ae4e53e02765b0f4ec9e36e0bf42b3321728504121e517c8d5614a016cce365ebcd4627bf264def0378797a000030000100000e1001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a7872343983", "0xa75d9b6f49b66421f7db337d653654bfb45734772ff5a20621271fbb0e02acc9eedbc33f58db5747749c745e7f5bb19c2072fdedf5f5596323404db15641688bc4ffbff8819039bc9cb687b8c6fb955afbea14377adaeb2137585e1c0f145131d0ea0b894ab40b9385eef1878811f077023121329feb8359fa930aed2d849aa6a7883b9e9b93cbab5babcd4fbe220471f992cfc1d6a98df6f3b3910c903b9c482b23a9f81665adc8483c5d5122fad6f8378e20fda8c79237fc13013293304c5b5508bb7b91f758686a5b7c6cc6050c20aaa6b8f8ffdf1d67ac5971380b52ef02ff825ea50d6e23caf4f605e616fb088ec185990fb485a12f608d08bd36a1c0a3"],

    // ethlab.xyz.	3599	IN	RRSIG	DS 8 2 3600 20190316082331 20190214162442 33603 xyz. OSUpCEkK4LVuyby+B82DZl8cxlNJNF2gNUtny63jhJ8kD/KK41sJd4TE1mq1lRxCVep3IK8GvvD9fEZHr64VvEv+c+84WZf3OicCy0AzKQudV+KR5uIvqPzE3fC0ZKZzxkKnUsPtVPiXDLUXeoIPbMabqTmp+xomKkWiTOezujU=
    // ethlab.xyz.	3599	IN	DS	60820 8 2 D1CDCF8E905ED06FEC438A63C69A34D2F4871B1F4869BBB852859892E693CAED
    // ethlab.xyz.	3599	IN	DS	42999 8 2 954C021A38E5731EBAAA95323FB7C472A866CE4D86AE3AD8605843B722B62213
    [web3.utils.toHex("ethlab.xyz."), "0x002b080200000e105c8cb2835c65964a83430378797a00066574686c61620378797a00002b000100000e100024a7f70802954c021a38e5731ebaaa95323fb7c472a866ce4d86ae3ad8605843b722b62213066574686c61620378797a00002b000100000e100024ed940802d1cdcf8e905ed06fec438a63c69a34d2f4871b1f4869bbb852859892e693caed", "0x39252908490ae0b56ec9bcbe07cd83665f1cc65349345da0354b67cbade3849f240ff28ae35b097784c4d66ab5951c4255ea7720af06bef0fd7c4647afae15bc4bfe73ef385997f73a2702cb4033290b9d57e291e6e22fa8fcc4ddf0b464a673c642a752c3ed54f8970cb5177a820f6cc69ba939a9fb1a262a45a24ce7b3ba35"],

    // ethlab.xyz.	3599	IN	RRSIG	DNSKEY 8 2 3600 20330427133000 20180516123000 42999 ethlab.xyz. OE5dzOx68Rsi1PKOAuzo2ALP972ZNI//loIzVKtyLY9gD5nXQTYeb8+uLFqLYmnUKOHQ9PzdJINnGz2urDsjig==
    // ethlab.xyz.	3599	IN	DNSKEY	257 3 8 AwEAAbjW5+pT9WirUzRujl+Haab7lw8NOa7N1FdRjpJ4ICzvOfc1vSYULj2eBIQJq5lys1Bhgs0NXHGsR0UDVok+uu7dic+UlEH8gIAa82yPefJOotD6yCZfqk1cuLX2+RGMHfpVgs4qwQa+PdajYfpw+sjzafGBuwiygycuZe40p4/Azm3E5/9lFsis4z3bXOd5vTdKYv5AWdEgKRdzZIRjIxurKz6G7nXPaxOn4zo4LM/kXxn4KjSLQQxQflr+xxHxda8zJZOY1Pj3iKcMzPtPHUsxbHbcjszmwNrn7sqNpSEPsoAw4+UQCG0FnhwsQxnAo5rE2YxJV1S+BRcAunyEsUE=
    // ethlab.xyz.	3599	IN	DNSKEY	256 3 8 AwEAAdlnRTgge2TmnkenqHAh6YXRNWobwj0r23zHhgLxkN3IB7iAyUulB1L92aS60hHbfYJ1aXjFnF1fhXvAxaAgQN0=
    [web3.utils.toHex("ethlab.xyz."), "0x0030080200000e10771a70585afc2448a7f7066574686c61620378797a00066574686c61620378797a000030000100000e1000480100030803010001d9674538207b64e69e47a7a87021e985d1356a1bc23d2bdb7cc78602f190ddc807b880c94ba50752fdd9a4bad211db7d82756978c59c5d5f857bc0c5a02040dd066574686c61620378797a000030000100000e1001080101030803010001b8d6e7ea53f568ab53346e8e5f8769a6fb970f0d39aecdd457518e9278202cef39f735bd26142e3d9e048409ab9972b3506182cd0d5c71ac47450356893ebaeedd89cf949441fc80801af36c8f79f24ea2d0fac8265faa4d5cb8b5f6f9118c1dfa5582ce2ac106be3dd6a361fa70fac8f369f181bb08b283272e65ee34a78fc0ce6dc4e7ff6516c8ace33ddb5ce779bd374a62fe4059d120291773648463231bab2b3e86ee75cf6b13a7e33a382ccfe45f19f82a348b410c507e5afec711f175af33259398d4f8f788a70cccfb4f1d4b316c76dc8ecce6c0dae7eeca8da5210fb28030e3e510086d059e1c2c4319c0a39ac4d98c495754be051700ba7c84b141", "0x384e5dccec7af11b22d4f28e02ece8d802cff7bd99348fff96823354ab722d8f600f99d741361e6fcfae2c5a8b6269d428e1d0f4fcdd2483671b3daeac3b238a"],

    // ethlab.xyz.	299	IN	RRSIG	NSEC 8 2 300 20330427133000 20180516123000 42999 ethlab.xyz. IAtuGJYMCnZSn76kXRTCvikHUB9Q7FEzYgq90jiFPyGoBv1DusxS6gFW4WvSe0NK4ZPmtzuNn+aqYjw9v/DpAg==
    // ethlab.xyz.	299	IN	NSEC	_ens.ethlab.xyz. NS SOA RRSIG NSEC DNSKEY
    [web3.utils.toHex("ethlab.xyz."), "0x002f08020000012c771a70585afc2448a7f7066574686c61620378797a00066574686c61620378797a00002f00010000012c001a045f656e73066574686c61620378797a00000722000000000380", "0x200b6e18960c0a76529fbea45d14c2be2907501f50ec5133620abdd238853f21a806fd43bacc52ea0156e16bd27b434ae193e6b73b8d9fe6aa623c3dbff0e902"]
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

    assert.equal(tx.receipt.status, true);
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
        assert.equal(tx.receipt.status, false);
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
        var result = await instance.rrdata.call(types.toType('DNSKEY'), hexEncodeName('nonexisting.'));
        var rrs = result['2']
        assert.equal(rrs, '0x0000000000000000000000000000000000000000');
        result = await instance.rrdata.call(types.toType('DNSKEY'), hexEncodeName('.'));
        rrs = result['2']
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
        await verifyFailedSubmission(instance, test_rrsets[0][1], sig.slice(0, sig.length - 2) + "FF");
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
            result = tx.receipt.status;
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
        for (let i = 0; i < test_rrsets.length; i++) {
            var rrset = test_rrsets[i];
            var tx = await instance.submitRRSet(rrset[1], rrset[2], proof);
            proof = tx.logs[0].args.rrset;
            assert.equal(tx.receipt.status, true);
        }
    });
});
