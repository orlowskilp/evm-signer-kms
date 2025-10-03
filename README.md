# Library for signing EVM transactions with AWS KMS

[![Crates.io Version](https://img.shields.io/crates/v/evm-signer-kms)](https://crates.io/crates/evm-signer-kms)
[![evm-signer-kms](https://github.com/orlowskilp/evm-signer-kms/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/orlowskilp/evm-signer-kms/actions/workflows/build-and-test.yml)
[![codecov](https://codecov.io/gh/orlowskilp/evm-signer-kms/graph/badge.svg?token=DGY9EZFV5L)](https://codecov.io/gh/orlowskilp/evm-signer-kms)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](/LICENSE)

EVM transaction signing library using key pairs generated and stored in
[AWS KMS](https://aws.amazon.com/kms).

**Built for**:

- Security - AWS KMS managed keys which never leave HSM devices.
- Speed and reliability - Implemented in Rust.
- Portability - Supports `x86_64` and `arm64`.
- Simplicity - Trying to use as little external libs as possible.

## Features

- Legacy (type 0) transactions
- [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) (type 1) transactions
- [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) (type 2) transactions
- Easily expandable to future [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718) typed transactions
- [EIP-55](https://eips.ethereum.org/EIPS/eip-55) address checksum validation if address has uppercase chars

## Tool chain compatibility

Works with [MUSL](https://musl.libc.org) and [GNU](https://www.gnu.org/software/libc) tool chains.
While GNU is the most widely adopted tool chain, MUSL is somewhat more conservative and favors static
linking over dynamic linking, making it a reasonably good candidate for secure builds.

### Building

I suggest using the provided [`Makefile`](./Makefile) to get things running fast. The default build
target is `x86_64-unknown-linux-gnu`, so this command will build the library with the GNU latest tool
chain for `x86_64` target:

```bash
make build
```

If you wish to build it with a different tool chain, it suffices to specify it with the
`RUSTUP_TOOLCHAIN` environment variable, e.g.:

```bash
RUSTUP_TOOLCHAIN=1.81 make build
```

Similarly, if you want to build for a different target, you need to set the `CARGO_BUILD_TARGET`
variable, e.g. to build for `arm64` (aka `aarch64`) with MUSL do:

```bash
CARGO_BUILD_TARGET=aarch64-unknown-linux-musl make build
```

### Supported platforms

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-gnu`
- `aarch64-unknown-linux-musl`

## Setting up

The library communicates with AWS KMS API endpoints and thus requires authorization. Additionally it
requires AWS region and KMS key ID to be specified in the environment. This is because it was
designed with containers and container orchestration in mind.

There are good chances that you will want to inject some secrets into the client application in
the container orchestration solution (e.g. using
[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) or
[HashiCorp Vault](https://www.hashicorp.com/products/vault)).

### Key access policy

At the very least the key policy must allow these actions for the IAM role which you are going to
use as the principal (see [documentation](https://docs.rs/evm-signer-kms) for more details):

```text
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

**Note:** The library doesn't understand the `KMS_KEY_ID` variable itself, it is just a suggested
way to pass the key ID to the library logic (see examples in the
[documentation](https://docs.rs/evm-signer-kms)) for more details.

### Running examples

You may want to run provided examples with:

```bash
make examples
```

Keep in mind that runtime configuration is required as decribed below.

### Testing configuration

The easiest way to check whether everything works the way it should is by running tests.

Before running the tests you need to download the public key PEM file and copy it to
`./tests/data/pub-key.pem` and then decode it to `./tests/data/pub-key.der`.

[`Makefile`](./Makefile) provides a directive for that:

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

## Call for support

Feel free to contribute to this project. I welcome any and all help. These are some items that could/should be
improved:

- Testing: Always there's a room for making better tests. Coverage alone doesn't really paint the full picture.
- Trimming down dependencies: The less external dependencies, the better. I'm continuously removing them where possible.
- Platform support: The more are supported, the more portable the library. This hinges on AWS SDK platform though.
- Tools: Know any good tools you feel could add value. Feel free to contribute!
