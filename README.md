# Library for EVM transaction signing with AWS KMS

[![MIT License](https://img.shields.io/badge/license-MIT-green)](/LICENSE)

EVM transaction signing library using key pairs generated and stored in
[AWS KMS](https://aws.amazon.com/kms).

Features:

* Secure - AWS KMS managed keys which never leave HSM devices.
* Fast and reliable - Implemented in Rust.

## Tool chain compatibility

Works [MUSL](https://musl.libc.org) and [GNU](https://www.gnu.org/software/libc) tool chains.

## Features

* Legacy (type 0) transactions
* [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transactions
* [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) (type 2) transactions
* Easy expandable to future [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) typed transactions

## What's needed

* More more and better tests
* CI/CD pipelines
* Code coverage measuring
* Derivation paths support
* ARM `aarch64` support
