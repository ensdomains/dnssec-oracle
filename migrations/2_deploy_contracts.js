var dnssec = artifacts.require("./dnssec.sol");

module.exports = function(deployer) {
  deployer.deploy(dnssec);
};
