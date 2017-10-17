var dns = require("../lib/dns.js");
var dnssec = artifacts.require("./dnssec.sol");

const test_rrsets = [
  // .	162922	IN	RRSIG	DNSKEY 8 0 172800 20171101000000 20171011000000 19036 . UIXyPFLTvJm0fq4rlLLvnyLQTKFPiLXtssnsvdiTmLC+OU3SqyFYKPvPZ0wY63m+AZPBSMDC0LdwSCbTN3gJtcKVAV0c4MT3jB1CQ0Tp/LPXh+mER+cPXkypz/sVGnjkjmjJFTF3+SclVLxvOuSaQdULdUTpeLq3SjkYCzChrc8oXIQJLXPcyNbLheiMGLoJEFfMQw4vS1xM7AwRdocl0LELPcpcLVWQvFSEj4nzXH3nT1G53aj27XIhK208WLlwq3Rk6yC4nopo6sBjYOlHaFwDFTsNJI39uRcaDAY9pw+osy6r7TLG0KHikTzbTdVrLdxXPWu8fv13DF7FBPcszQ==
  // .	162922	IN	DNSKEY	256 3 8 AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+bP7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPyG6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1ylsr4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjveD1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2/PFENcoFERc=
  // .	162922	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
  // .	162922	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
  [1, ".", "003008000002a30059f90e8059dd5f004a5c0000003000010002a30001080100030803010001c44865fc6c91d12530a823c2f5903b66d07bb10602f5face021aaa66ec68caa632b229775f9b3fb9f250b2ee2fc8d69ca02a71a55f6a5db2243e74820e73165e725bf17d74a3575c4148ed511c1ab3f21bafceac0f51054f291969b4ab1a6c366e542204d4e485fba5bff4ac18faedcfd1eea967f2c8c7d7296caf87f563747aa7f76bba211a94a6ac12318a03d2f6c3d8f3510bac5b133b7d0c7f4fc73fdf1ddbb23bde0f5765790e8c25a0b1e1ba4f5d8669a97992bc69fe4f6bf9df9d1c055005a952a119b8f11325c0c1e7a6f1c4d4e0bd69f8357b51ad756b5b4c7f44e5bbca64a4bc21ecd408820204849c0484f7971371380ba436fcf14435ca05111700003000010002a30001080101030803010001a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d00003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5", "5085f23c52d3bc99b47eae2b94b2ef9f22d04ca14f88b5edb2c9ecbdd89398b0be394dd2ab215828fbcf674c18eb79be0193c148c0c2d0b7704826d3377809b5c295015d1ce0c4f78c1d424344e9fcb3d787e98447e70f5e4ca9cffb151a78e48e68c9153177f9272554bc6f3ae49a41d50b7544e978bab74a39180b30a1adcf285c84092d73dcc8d6cb85e88c18ba091057cc430e2f4b5c4cec0c11768725d0b10b3dca5c2d5590bc54848f89f35c7de74f51b9dda8f6ed72212b6d3c58b970ab7464eb20b89e8a68eac06360e947685c03153b0d248dfdb9171a0c063da70fa8b32eabed32c6d0a1e2913cdb4dd56b2ddc573d6bbc7efd770c5ec504f72ccd"],

  // net.	35020	IN	RRSIG	DS 8 1 86400 20171027170000 20171014160000 46809 . vJXpbyveGYO4eAD4b9Noeh5iy4nHWWRExAH2iOzP/ySp/nkBob+s9hjko47xyMvidveEr5HU0II4j2uaC3YKeEYYtdQrIhB8x24wY0isxbm67kByeZUmgnbtoByEg3podw5P6geIrd8mX6yJS2qN5Rcd8c6hCs68lguq4TABq4WF+Eh5XIlUpfyM9EuIaiODgFfMmkuA/LkgEWjnI2+vIXdeTFOJVq5PHGY0/XSvIEa+pdf5FIsbJnZ5KRDD3JMvC5WrEmJmCw2i/tz66h0KD0rcSG4v9vMC3fEXFFEbrLd0QTO+QexmIJJVGEV5716Ji7sg18Inh4lRqTPYAyTaGw==
  // net.	35020	IN	DS	35886 8 2 7862B27F5F516EBE19680444D4CE5E762981931842C465F00236401D8BD973EE
  [1, "net.", "002b08010001518059f3661059e23480b6d900036e657400002b00010001518000248c2e08027862b27f5f516ebe19680444d4ce5e762981931842c465f00236401d8bd973ee", "bc95e96f2bde1983b87800f86fd3687a1e62cb89c7596444c401f688eccfff24a9fe7901a1bfacf618e4a38ef1c8cbe276f784af91d4d082388f6b9a0b760a784618b5d42b22107cc76e306348acc5b9baee40727995268276eda01c84837a68770e4fea0788addf265fac894b6a8de5171df1cea10acebc960baae13001ab8585f848795c8954a5fc8cf44b886a23838057cc9a4b80fcb9201168e7236faf21775e4c538956ae4f1c6634fd74af2046bea5d7f9148b1b2676792910c3dc932f0b95ab1262660b0da2fedcfaea1d0a0f4adc486e2ff6f302ddf11714511bacb7744133be41ec66209255184579ef5e898bbb20d7c227878951a933d80324da1b"],

  // net.	35021	IN	RRSIG	DNSKEY 8 1 86400 20171022163857 20171007163357 35886 net. j53+p2TR/gQt31fcoM716rvSdkNMVdOe7o74AGK/iKnQsuPXSQ1nmlK01MfjuSMitUIuAjhajoVuCdBxxb3IvDALZFrByCWN6fVMzMBOIkhKnmP1jsVYiUw8kLDFLbIrGOr7lMFf/3mgAhYDWB/AOqiJ+NDyEZEI6IdmT4aqFWanyPuclNkMva4/J35UJQ2tpcMnMZCO7jvLIme+wuvs2ACksETn/TJrVUXDje8znMoDATV77qhErvvosjZqoAiK+69VupJPP9N2hG5/PUP9/X4YKR1fnpSST2JFplT6/f2l13R+XJOtY0dH3FlsD7s7PN8iw5rURtDRuOu0FoNMZA==
  // net.	35021	IN	DNSKEY	257 3 8 AQOYBnzqWXIEj6mlgXg4LWC0HP2n8eK8XqgHlmJ/69iuIHsa1TrHDG6TcOra/pyeGKwH0nKZhTmXSuUFGh9BCNiwVDuyyb6OBGy2Nte9Kr8NwWg4q+zhSoOf4D+gC9dEzg0yFdwT0DKEvmNPt0K4jbQDS4Yimb+uPKuF6yieWWrPYYCrv8C9KC8JMze2uT6NuWBfsl2fDUoV4l65qMww06D7n+p7RbdwWkAZ0fA63mXVXBZF6kpDtsYD7SUB9jhhfLQE/r85bvg3FaSs5Wi2BaqN06SzGWI1DHu7axthIOeHwg00zxlhTpoYCH0ldoQz+S65zWYi/fRJiyLSBb6JZOvn
  // net.	35021	IN	DNSKEY	256 3 8 AQPFldP/nh7WBMtZ1Bp2lylH1oj66mfsmMUk2M1lTK2YlATxWJ9oOWf+Jx8seZuHcxtZ19ffr/UXy2pxyKUcKvT/A7cvdjy5++7F4sGWluOkR4m66Uwc/F7fQV06b2OoiMOpGToTIxwURRX0xXfiyNIDDzHfJXm0W6pIHY5O4E3U6w==
  // net.	35021	IN	DNSKEY	256 3 8 AQPjDcP37XO95AaEmoSv2MHIRVz3BUzXYKzrBqEw/P4vZmp+TqYp8KB3oYW54dmzT04HZ9FcvBROOtdt6eciz50jw7xq0S6ypWkVLL+iWTZdXaagaKzjcNcXGn2Epafd74ED793EH/zC2qtqyzhpKKjN1qa65x+0PkHP+BRpdJpFOw==
  [1, "net.", "003008010001518059ecc9a159d901f58c2e036e657400036e65740000300001000151800086010003080103c595d3ff9e1ed604cb59d41a76972947d688faea67ec98c524d8cd654cad989404f1589f683967fe271f2c799b87731b59d7d7dfaff517cb6a71c8a51c2af4ff03b72f763cb9fbeec5e2c19696e3a44789bae94c1cfc5edf415d3a6f63a888c3a9193a13231c144515f4c577e2c8d2030f31df2579b45baa481d8e4ee04dd4eb036e65740000300001000151800086010003080103e30dc3f7ed73bde406849a84afd8c1c8455cf7054cd760aceb06a130fcfe2f666a7e4ea629f0a077a185b9e1d9b34f4e0767d15cbc144e3ad76de9e722cf9d23c3bc6ad12eb2a569152cbfa259365d5da6a068ace370d7171a7d84a5a7ddef8103efddc41ffcc2daab6acb386928a8cdd6a6bae71fb43e41cff81469749a453b036e6574000030000100015180010601010308010398067cea5972048fa9a58178382d60b41cfda7f1e2bc5ea80796627febd8ae207b1ad53ac70c6e9370eadafe9c9e18ac07d272998539974ae5051a1f4108d8b0543bb2c9be8e046cb636d7bd2abf0dc16838abece14a839fe03fa00bd744ce0d3215dc13d03284be634fb742b88db4034b862299bfae3cab85eb289e596acf6180abbfc0bd282f093337b6b93e8db9605fb25d9f0d4a15e25eb9a8cc30d3a0fb9fea7b45b7705a4019d1f03ade65d55c1645ea4a43b6c603ed2501f638617cb404febf396ef83715a4ace568b605aa8dd3a4b31962350c7bbb6b1b6120e787c20d34cf19614e9a18087d25768433f92eb9cd6622fdf4498b22d205be8964ebe7", "8f9dfea764d1fe042ddf57dca0cef5eabbd276434c55d39eee8ef80062bf88a9d0b2e3d7490d679a52b4d4c7e3b92322b5422e02385a8e856e09d071c5bdc8bc300b645ac1c8258de9f54cccc04e22484a9e63f58ec558894c3c90b0c52db22b18eafb94c15fff79a0021603581fc03aa889f8d0f2119108e887664f86aa1566a7c8fb9c94d90cbdae3f277e54250dada5c32731908eee3bcb2267bec2ebecd800a4b044e7fd326b5545c38def339cca0301357beea844aefbe8b2366aa0088afbaf55ba924f3fd376846e7f3d43fdfd7e18291d5f9e94924f6245a654fafdfda5d7747e5c93ad634747dc596c0fbb3b3cdf22c39ad446d0d1b8ebb416834c64"],

  // rootcanary.net.	35021	IN	RRSIG	DS 8 2 86400 20171020051914 20171013040914 57899 net. OERbrahnVXbTMKyPUCW4eoOciLTxorjF4zdPp9QkdE4WeFg//Y63EDMOHg2C/MKN/M07iGKzxF9menAia3IZEOTPJXPdrmSsBx2SLsLNsaPI0PxuktIhtSO0XD0DDU6dvmLmer/163364JzqDNtIY7I4ZY8FrkUXfTDcOnexQFY=
  // rootcanary.net.	35021	IN	DS	64786 8 2 5CD8F125F5487708121A497BD0B1079406ADD42002B3C195EE0669D2AEB763C9
  [1, "rootcanary.net.", "002b08020001518059e9875259e03c6ae22b036e6574000a726f6f7463616e617279036e657400002b0001000151800024fd1208025cd8f125f5487708121a497bd0b1079406add42002b3c195ee0669d2aeb763c9", "38445bada8675576d330ac8f5025b87a839c88b4f1a2b8c5e3374fa7d424744e1678583ffd8eb710330e1e0d82fcc28dfccd3b8862b3c45f667a70226b721910e4cf2573ddae64ac071d922ec2cdb1a3c8d0fc6e92d221b523b45c3d030d4e9dbe62e67abff5eb7dfae09cea0cdb4863b238658f05ae45177d30dc3a77b14056"],

  // rootcanary.net.	16	IN	RRSIG	DNSKEY 8 2 60 20171019063714 20171009063714 64786 rootcanary.net. vEuZ+7LfWE5GF1znMEXSG2CV4KCZltADlfTbAL1V7LLJArKD9i6r6nu1Q8E6qxNuJGzDxG33UnWhVsxBxmqvDh91xsXtuNh9qxIs6PUXsn3LHWEYvQEO35u5K+XWB2znCjvguMufNMgigbxfgNrMcoOHt1SRAjBHIf8tcn+qG7g=
  // rootcanary.net.	16	IN	DNSKEY	257 3 8 AwEAAdDk0xPx74/+J4BFAtodd6j2yTDoX9D+paSjzxVl+jMQmrsrQprdBxX3fale9f62j4oo7scfU+wabBXl56lehbw/wds6oVqDNun9ORQisXhIq9H+u3a9WtTAF+OQyPoSirRLYdNR7+wWvb88L27w88+jL0gkFb8klGzr03EFrq6r
  // rootcanary.net.	16	IN	DNSKEY	256 3 8 AwEAAbTt2EpLNxL2BJh6zgrhiEBK1sfxYPvEQgQkM1O53+lnT+c8W+9lYMhI1m2mLwecKvq7ePok5d1XO11UKUXV5pRD9d66qXLwDxMJ4krEMlOvmMS/HWskybkREtMdPdcv5eNdtuT8VeCPTGZuoNe2oEK4NFSUU5eG0pkWo27Kl3oV
  [1, "rootcanary.net.", "003008020000003c59e8481a59db191afd120a726f6f7463616e617279036e6574000a726f6f7463616e617279036e657400003000010000003c00880100030803010001b4edd84a4b3712f604987ace0ae188404ad6c7f160fbc44204243353b9dfe9674fe73c5bef6560c848d66da62f079c2afabb78fa24e5dd573b5d542945d5e69443f5debaa972f00f1309e24ac43253af98c4bf1d6b24c9b91112d31d3dd72fe5e35db6e4fc55e08f4c666ea0d7b6a042b8345494539786d29916a36eca977a150a726f6f7463616e617279036e657400003000010000003c00880101030803010001d0e4d313f1ef8ffe27804502da1d77a8f6c930e85fd0fea5a4a3cf1565fa33109abb2b429add0715f77da95ef5feb68f8a28eec71f53ec1a6c15e5e7a95e85bc3fc1db3aa15a8336e9fd391422b17848abd1febb76bd5ad4c017e390c8fa128ab44b61d351efec16bdbf3c2f6ef0f3cfa32f482415bf24946cebd37105aeaeab", "bc4b99fbb2df584e46175ce73045d21b6095e0a09996d00395f4db00bd55ecb2c902b283f62eabea7bb543c13aab136e246cc3c46df75275a156cc41c66aaf0e1f75c6c5edb8d87dab122ce8f517b27dcb1d6118bd010edf9bb92be5d6076ce70a3be0b8cb9f34c82281bc5f80dacc728387b7549102304721ff2d727faa1bb8"],

  // d2a8n3.rootcanary.net.	60	IN	RRSIG	DS 8 3 60 20171019063714 20171009063714 25188 rootcanary.net. rs/zwSPGixrtaJYqfjk/sNX0cHoGKbuWOLor86WrA3NpuxvSmoUhJQ3djpNC3i9vXe3BDNesjRI4ITepompsXTfK0l6bzom+Fg60oirnuyXDnTqzmKPMWORlEJ+z/O9Ck2rnIsSkkrh9w7yQk5Fr7bVQASQPBUO9DDanupahrpQ=
  // d2a8n3.rootcanary.net.	60	IN	DS	37159 8 2 90B1E98F2D54D7A02AF91B1D15F305077B165779A78D2F6CEB483BAF78259087
  [1, "d2a8n3.rootcanary.net.", "002b08030000003c59e8481a59db191a62640a726f6f7463616e617279036e65740006643261386e330a726f6f7463616e617279036e657400002b00010000003c00249127080290b1e98f2d54d7a02af91b1d15f305077b165779a78d2f6ceb483baf78259087", "aecff3c123c68b1aed68962a7e393fb0d5f4707a0629bb9638ba2bf3a5ab037369bb1bd29a8521250ddd8e9342de2f6f5dedc10cd7ac8d12382137a9a26a6c5d37cad25e9bce89be160eb4a22ae7bb25c39d3ab398a3cc58e465109fb3fcef42936ae722c4a492b87dc3bc9093916bedb55001240f0543bd0c36a7ba96a1ae94"],

  // d2a8n3.rootcanary.net.	60	IN	RRSIG	DNSKEY 8 3 60 20171019063714 20171009063714 37159 d2a8n3.rootcanary.net. qb8ehqnZ6Hema3fta0thlGTb4ZmhcRjWoIexM3lfMjS8w03HAAKjnbX/4ATi2cyvin5ef4WOYBfQXO1g0M6bbwqGL6v+819v5zqFvhf+LnSMuae6d9lB5eGfRbA4tZ9VyUdESA90WHmd6Lgb8/meK53LcwqXmlMgkyAyWyVPbsc=
  // d2a8n3.rootcanary.net.	60	IN	DNSKEY	257 3 8 AwEAAclCM9uetzQku9beDbotKE6JexUBEpaXLjVxB8Tn46vBSmbez8TwjVXwIkzFOaNuaSnBWKctK7Kxyh4AiQWHwobJ54KEtLbzEK8uMupU/tkU11p7Lyz+QJG3cneIOlIz1FxP4qwk6RNtWuZ2QZyMjYDNk+VqwAcaOIAdHfGRUj53
  [1, "d2a8n3.rootcanary.net.", "003008030000003c59e8481a59db191a912706643261386e330a726f6f7463616e617279036e65740006643261386e330a726f6f7463616e617279036e657400003000010000003c00880101030803010001c94233db9eb73424bbd6de0dba2d284e897b15011296972e357107c4e7e3abc14a66decfc4f08d55f0224cc539a36e6929c158a72d2bb2b1ca1e00890587c286c9e78284b4b6f310af2e32ea54fed914d75a7b2f2cfe4091b77277883a5233d45c4fe2ac24e9136d5ae676419c8c8d80cd93e56ac0071a38801d1df191523e77", "a9bf1e86a9d9e877a66b77ed6b4b619464dbe199a17118d6a087b133795f3234bcc34dc70002a39db5ffe004e2d9ccaf8a7e5e7f858e6017d05ced60d0ce9b6f0a862fabfef35f6fe73a85be17fe2e748cb9a7ba77d941e5e19f45b038b59f55c94744480f7458799de8b81bf3f99e2b9dcb730a979a53209320325b254f6ec7"],

  // secure.d2a8n3.rootcanary.net.	60	IN	RRSIG	A 8 4 60 20171019063714 20171009063714 37159 d2a8n3.rootcanary.net. Qac4y+1zbXx0TF1Aqy2hnrieAWjIjfRGX6hUW150qJ1fZwdGW5jQ5yfK4UuQD+HrGs95kDZFtAwTtNToEz7ba5TeYmBmSklSkvtXy2EummIyI2EU0/kqh9lTgyECcEPyieQbXuSO7PZjMbRqhzLM+4XJt08pGja7ML3kcOvk/44=
  // secure.d2a8n3.rootcanary.net.	60	IN	A	145.97.20.17
  [1, "secure.d2a8n3.rootcanary.net.", "000108040000003c59e8481a59db191a912706643261386e330a726f6f7463616e617279036e6574000673656375726506643261386e330a726f6f7463616e617279036e657400000100010000003c000491611411", "41a738cbed736d7c744c5d40ab2da19eb89e0168c88df4465fa8545b5e74a89d5f6707465b98d0e727cae14b900fe1eb1acf79903645b40c13b4d4e8133edb6b94de6260664a495292fb57cb612e9a6232236114d3f92a87d9538321027043f289e41b5ee48eecf66331b46a8732ccfb85c9b74f291a36bb30bde470ebe4ff8e"]
];

async function verifySubmission(instance, name, data, sig) {
  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(1, name, data, sig);
  assert.equal(tx.receipt.status, "0x1");
  assert.equal(tx.logs.length, 1);
  assert.equal(tx.logs[0].args.name, name);
  return tx;
}

async function verifyFailedSubmission(instance, name, data, sig) {
  var name = dns.hexEncodeName(name);
  var tx = await instance.submitRRSet(1, name, data, sig);
  assert.equal(tx.receipt.status, "0x0");
  return tx;
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
      rrs: [],
    };
  };

  it("should reject signatures with non-matching algorithms", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.push({name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 254, pubkey: new Buffer("1111", "HEX")});
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures with non-matching keytags", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.push({name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")})
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject signatures by keys without the ZK bit set", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs.push({name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0001, protocol: 3, algorithm: 253, pubkey: new Buffer("1211", "HEX")})
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should accept a root DNSKEY', async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.rrs = [
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 4, algorithm: 253, pubkey: new Buffer("1111", "HEX")},
      {name: ".", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0, protocol: 3, algorithm: 253, pubkey: new Buffer("1112", "HEX")}
    ];
    await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should reject signatures with non-matching classes', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_TXT,
      algorithm: 253,
      labels: 1,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "com.", type: dns.TYPE_TXT, klass: 1, ttl: 3600, text: ["foo"]}
      ],
    }), "0x");
  });

  it('should reject signatures with the wrong type covered', async function() {
    var instance = await dnssec.deployed();
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, "net.", dns.hexEncodeSignedSet({
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

  it('should reject signatures with invalid signer names', async function() {
    var instance = await dnssec.deployed();

    await verifySubmission(instance, "net.", dns.hexEncodeSignedSet({
      typeCovered: dns.TYPE_DNSKEY,
      algorithm: 253,
      labels: 0,
      originalTTL: 3600,
      expiration: 0xFFFFFFFF,
      inception: 0,
      keytag: 5647,
      signerName: ".",
      rrs: [
        {name: "net.", type: dns.TYPE_DNSKEY, klass: dns.CLASS_INET, ttl: 3600, flags: 0x0101, protocol: 3, algorithm: 253, pubkey: new Buffer("1111", "HEX")}
      ]
    }), "0x");

    await verifyFailedSubmission(instance, "com.", dns.hexEncodeSignedSet({
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
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries with inceptions in the future", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 0xFFFFFFFF;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");    
  });

  it("should accept updates with newer signatures", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    await verifySubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it("should reject entries that aren't newer", async function() {
    var instance = await dnssec.deployed();
    var keys = rootKeys();
    keys.inception = 1;
    await verifyFailedSubmission(instance, ".", dns.hexEncodeSignedSet(keys), "0x");
  });

  it('should accept real DNSSEC records', async function() {
    var instance = await dnssec.deployed();
    var totalGas = 0;
    for(var rrset of test_rrsets) {
      var tx = await verifySubmission(instance, rrset[1], "0x" + rrset[2], "0x" + rrset[3]);
      totalGas += tx.receipt.gasUsed;
    }
    console.log("Gas used: " + totalGas);
  });
});
