pragma solidity ^0.4.16;

import "./modexp.sol";

library RSAVerify {
    function rsaverify(bytes rawmsg, bytes N, bytes E, bytes S) internal view returns (bool) {
        if (rawmsg.length != N.length) return false;
        // This would be modexp(S, e, N) == modexp(rawmsg, 1, N), but we simplify it a bit.
        var (retS, valS) = ModexpPrecompile.modexp(S, E, N);
        // NOTE: keccak256(valS) == keccak256(rawmsg) is the cheapest shortcut for equality comparison
        return retS == true && keccak256(valS) == keccak256(rawmsg);
        //Memory.equal(valS, 0, hash, 0, hash.length);
    }
}

contract RSAVerifyTest {
    function test() public constant returns(bool) {
        bytes memory rawmsg = hex"0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d060960864801650304020105000420fad256467fc777e2075073e3f84b2f8bdefb8202480e834eed40f89c7665a15c";
        bytes memory E = hex"010001";
        bytes memory N = hex"a80020a95566ba42e886bb804cda84e47ef56dbd7aec612615552cec906d2116d0ef207028c51554144dfeafe7c7cb8f005dd18234133ac0710a81182ce1fd14ad2283bc83435f9df2f6313251931a176df0da51e54f42e604860dfb359580250f559cc543c4ffd51cbe3de8cfd06719237f9fc47ee729da06835fa452e825e9a18ebc2ecbcf563474652c33cf56a9033bcdf5d973121797ec8089041b6e03a1b72d0a735b984e03687309332324f27c2dba85e9db15e83a0143382e974b0621c18e625ecec907577d9e7bade95241a81ebbe8a901d4d3276e40b114c0a2e6fc38d19c2e6aab02644b2813f575fc21601e0dee49cd9ee96a43103e524d62873d";
        bytes memory S = hex"99118f191f80c02289c8bd37164ead5ed50b6e287d8363ed6fb5361c0f7df9fb49ee14ab2d6de7fc998d1d23695f092bb1bcf21bbd895c291619f1afd5342da9cb5b2a06ed9ed7e4ff37f87461907927301a2bc149c77fb5f56c1090d0a08e35ab71729f2e9c912a56563f26f3ab0f6c92fba3e240c808767132f595bbf7a5389ca38ee42160d780c0d99643e00f0aca283a086949333c8ebe45023b43e4873a2b67f6ac8bf1ca3f84a648420d5735fcacd5a4bf882442a96dd1b5d2c83178832b018ed503b07d3bcb481ae5ee30e980e599ad6889e20e9e6ec732b9811a44a3ff0dead0faa54960072e32c338bffdd8c1a419a5055a3706873840716a6b7cfc";
        return RSAVerify.rsaverify(rawmsg, N, E, S);
    }
}
