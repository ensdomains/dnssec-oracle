module.exports = {
  networks: {
    regtest: {
      host: 'localhost',
      port: 4444,
      network_id: '*',
    },
  },
  mocha: {
    reporter: 'eth-gas-reporter',
    reporterOptions: {
      currency: 'USD',
      gasPrice: 1
    }
  },
  /*  solc: {
    optimizer: {
      enabled: true,
      runs: 200
    }
  }*/
};
