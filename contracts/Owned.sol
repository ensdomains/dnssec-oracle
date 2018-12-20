pragma solidity ^0.5.0;

/**
* @dev Contract mixin for 'owned' contracts.
*/
contract Owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier owner_only() {
        require(msg.sender == owner);
        _;
    }

    function setOwner(address newOwner) public owner_only {
        owner = newOwner;
    }
}
