# dnssec-oracle
This is an implementation of a DNSSEC oracle for Ethereum. With it, you can securely prove the contents of any DNSSEC-signed DNS record on the Ethereum blockchain, as long as it was signed using supported public key schemes and digests. Presently, the oracle only supports RSA and SHA-256; fortunately, over 3/4 of TLDs use this combination of algorithms.

Once a record is proven to the oracle, any contract or external caller can fetch it with the `rrsets` constant function, allowing other contracts to read data from DNS.

## Usage

A [command line utility](https://github.com/arachnid/dnsprove) is available that automates the task of generating the necessary proofs from DNS data and submitting them to the oracle.

The oracle is still in alpha, and does not yet have any official deployments on the main network or test networks.

## Testing

Tests can be run with `truffle test`. You will first need to update truffle's version of Solidity to at least 0.4.17 by following [these instructions](https://ethereum.stackexchange.com/questions/17551/how-to-upgrade-solidity-compiler-in-truffle).

You will also need a blockchain client that supports Byzantium and can do bignumber modular exponentiation in a reasonable time. Until `testrpc` is capable, we recommend `geth --dev`.
