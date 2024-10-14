# Library for EVM transaction signing with AWS KMS

![Crates.io Version](https://img.shields.io/crates/v/evm-signer-kms)
[![evm-signer-kms](https://github.com/orlowskilp/evm-signer-kms/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/orlowskilp/evm-signer-kms/actions/workflows/build-and-test.yml)
[![codecov](https://codecov.io/github/orlowskilp/evm-signer-kms/branch/master/graph/badge.svg?token=DGY9EZFV5L)](https://codecov.io/github/orlowskilp/evm-signer-kms)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](/LICENSE)

EVM transaction signing library using key pairs generated and stored in
[AWS KMS](https://aws.amazon.com/kms).

**Built for**:

* Security - AWS KMS managed keys which never leave HSM devices.
* Speed and reliability - Implemented in Rust.

## Tool chain compatibility

Works with [MUSL](https://musl.libc.org) and [GNU](https://www.gnu.org/software/libc) tool chains.

## Features

* Legacy (type 0) transactions
* [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transactions
* [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) (type 2) transactions
* Easily expandable to future [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) typed transactions

## What's needed

* More more and better tests
* Derivation paths support
* ARM `aarch64` support
