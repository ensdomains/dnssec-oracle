require("@nomiclabs/hardhat-truffle5");

module.exports = {
  networks: {
      hardhat: {
        // Required for real DNS record tests
        initialDate: "2019-03-15T14:06:45.000+13:00"
      }
  },
  mocha: {
  },
  solidity: {
    version: "0.7.4",
  },
};
