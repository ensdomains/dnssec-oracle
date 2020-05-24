# DNSSEC Oracle

[![Build Status](https://travis-ci.org/ensdomains/dnssec-oracle.svg?branch=master)](https://travis-ci.org/ensdomains/dnssec-oracle)
[![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

This is an implementation of a DNSSEC oracle for Ethereum. With it, you
can securely prove the contents of any DNSSEC-signed DNS record on the
Ethereum blockchain, as long as it was signed using supported public key
schemes and digests. Presently, the oracle only supports RSA and
SHA-256; fortunately, over 3/4 of TLDs use this combination of
algorithms.

Once a record is proven to the oracle, any contract or external caller
can fetch it with the `rrsets` constant function, allowing other
contracts to read data from DNS.

## Getting Started

These instructions will get you a copy of the project up and running on
your local machine for development and testing purposes.

### Installing

The DNSSEC Oracle uses npm to manage dependencies, therefore the
installation process is kept simple:

```
npm install
```

### Running tests

The DNSSEC Oracle uses truffle for its ethereum development environment.
All tests can be run using truffle:

```
truffle test
```

To run linting, use solium:

```
solium --dir ./contracts
```

## Including DNSSEC Oracle in your project

### Installation

```
npm install dnssec-oracle --save
```

### Within Your contracts

```
import "@ensdomains/dnssec-oracle/build/contracts/DNSSEC"
```

### Within Javascript code

```
var data = require("@ensdomains/dnssec-oracle/build/contracts/DNSSEC.json")
```

The JSON file is same as the one generated using `truffle compile`. You
can pass the loaded data to `truffle-contract` or use it via web3 by
passing `data.abi`.

### Usage

A [command line utility](https://github.com/arachnid/dnsprove) is
available that automates the task of generating the necessary proofs
from DNS data and submitting them to the oracle.

The oracle is still in alpha, and does not yet have any official
deployments on the main network or test networks.

## Built With

- [Truffle](https://github.com/trufflesuite/truffle) - Ethereum
  development environment

## Authors

- **Nick Johnson** - [Arachnid](https://github.com/Arachnid)

See also the list of
[contributors](https://github.com/ensdomains/dnssec-oracle/contributors)
who participated in this project.

## License

This project is licensed under the BSD 2-clause "Simplified" License -
see the [LICENSE](LICENSE) file for details
