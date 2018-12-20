setTime = async function (timestamp) {
    return web3.currentProvider.send({
        jsonrpc: "2.0",
        method: "evm_setTime",
        params: [timestamp],
        id: 0
    })
};

mine = async function () {
    return web3.currentProvider.send({
        jsonrpc: "2.0",
        method: "evm_mine",
        params: [],
        id: new Date().getTime()
    });
};

module.exports = {
    setTime: setTime,
    mine: mine
};
