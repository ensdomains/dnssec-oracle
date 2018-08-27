setTime = async function (timestamp) {
    web3.currentProvider.send({
        jsonrpc: "2.0",
        method: "evm_setTime",
        params: [timestamp],
        id: 0
    })
};

module.exports = {
    setTime: setTime
};
