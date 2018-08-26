pragma solidity ^0.4.23;

// @TODO USE FROM NPM AS SOON AS WE PUBLISH CURVE ARITHMETICS

interface CurveInterface {
    function validateSignature(bytes32 message, uint[2] rs, uint[2] Q) external view returns (bool);
}
