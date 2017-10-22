module.exports = {
  networks: {
    development: {
      host: "localhost",
      port: 8545,
      network_id: "*" // Match any network id
    },
    ropsten: {
      host: "localhost",
      port: 8545,
      network_id: "3",
      from: "0xa303ddc620aa7d1390baccc8a495508b183fab59"
    }
  }
};
