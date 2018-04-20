pragma solidity ^0.4.17;

import "../contracts/SHA1.sol";

contract SHA1Test {
    function sha1(bytes message) public constant returns(bytes20 ret) {
      return SHA1.sha1(message);
    }
}
