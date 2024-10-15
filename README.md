# Library for signing EVM transactions with AWS KMS

![Crates.io Version](https://img.shields.io/crates/v/evm-signer-kms)
[![evm-signer-kms](https://github.com/orlowskilp/evm-signer-kms/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/orlowskilp/evm-signer-kms/actions/workflows/build-and-test.yml)
[![codecov](https://codecov.io/github/orlowskilp/evm-signer-kms/branch/master/graph/badge.svg?token=DGY9EZFV5L)](https://codecov.io/github/orlowskilp/evm-signer-kms)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](/LICENSE)

EVM transaction signing library using key pairs generated and stored in
[AWS KMS](https://aws.amazon.com/kms).

**Built for**:

* Security - AWS KMS managed keys which never leave HSM devices.
* Speed and reliability - Implemented in Rust.

## Features

* Legacy (type 0) transactions
* [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transactions
* [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) (type 2) transactions
* Easily expandable to future [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) typed transactions

## Tool chain compatibility

Works with [MUSL](https://musl.libc.org) and [GNU](https://www.gnu.org/software/libc) tool chains.

### Building

I suggest using the provided [`Makefile`](./Makefile) to get things running fast. The default build
target is `x86_64-unknown-linux-gnu`, so this command will build the library with the GNU tool
chain:

```bash
make build
```

If you wish to build it with a different tool chain, it suffices to specify it with the `TOOL_CHAIN`
environment variable, e.g.:

```bash
TOOL_CHAIN=x86_64-unknown-linux-musl make build
```

## Setting up

The library communicates with AWS KMS API endpoints and thus requires authorization. Additionally it
requires AWS region and KMS key ID to be specified in the environment. This is because it was
designed with containers and container orchestration in mind.

There are good chances that you will want to inject some secrets into the client application in
the container orchestration solution (e.g. using
[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) or
[HashiCorp Vault](https://www.hashicorp.com/products/vault)). The `KMS_KEY_ID` is a good example.

### Key access policy

At the very least the key policy must allow these actions for the IAM role which you are going to
use as the principal (see [documentation](https://docs.rs/evm-signer-kms) for more details):

```test
kms:DescribeKey
kms:GetPublicKey
kms:Sign
kms:Verify
```

### Authorization

I suggest using STS to assume a role which is granted permissions to use the
[secp256k1](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html)
key pair in KMS. Once the IAM role is set up, you can assume it by e.g. setting the following
environment variables:

```bash
export AWS_ACCESS_KEY_ID="[REDACTED]"
export AWS_SECRET_ACCESS_KEY="[REDACTED]"
export AWS_SESSION_TOKEN="[REDACTED]"
```

### Region specification

The region needs to be inferred from the environment, e.g.:

```bash
export AWS_REGION="[REDACTED]"
```

### KMS key ID

The KMS key which is going to be used for message digests signing can be identified using a key ID
in the UUID format:

```bash
export KMS_KEY_ID="[REDACTED]"
```

### Testing configuration

The easiest way to check whether everything works the way it should is by running tests.

Before running the tests you need to download the public key PEM file and copy it to
`./tests/data/pub-key.pem` and then decode it to `./tests/data/pub-key.der`.

This the `Makefile` provides a directive for that:

```bash
make fetch-public-key
```

Once the PEM and DER files are there, run the tests with:

```bash
make test
```

**Note**: If you downloaded the PEM file using the management console it is going to have the
following format:

```text
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

You can use the supplied helper [`pem2der.sh`](./tests/data/scripts/pem2der.sh) shell script:

```bash
cd tests/data
./scripts/pem2der.sh ./pub-key.pem > pub-key.der
```

If the tests pass, you're all set!

## What's needed

* More more and better tests
* Derivation paths support
* ARM `aarch64` support
