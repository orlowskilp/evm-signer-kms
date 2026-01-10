//! EVM account abstraction for signing transactions using [AWS KMS](https://aws.amazon.com/kms)
//! keys.
//!
//! This library provides an abstraction for EVM accounts to sign transactions using AWS KMS keys.
//! Designed for security, as the private key never leaves the KMS service uncencrypted.
//! With careful KMS keys policy, the key extraction can be completely disabled making the library
//! a perfect fit for verifiably secure production environments.
//!
//! # Examples
//!
//! The following examples demonstrate how to sign EVM transactions using AWS KMS keys.
//!
//! ## Free market transaction (i.e. type 2 transaction)
//!
//! The following example demonstrates how to sign an
//! [`EIP-1559`](https://eips.ethereum.org/EIPS/eip-1559) transaction:
//!
//! ```rust
//!  use anyhow::{Result, bail};
//!  use evm_signer_kms::{
//!      account::EvmAccount, key::aws_kms::AwsKmsKey,
//!      transaction::free_market_transaction::FreeMarketTransaction,
//!  };
//!  use std::env;
//!
//!  // Name of the environment variable with the KMS key ID
//!  const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
//!  // Example EIP-1559 transaction JSON
//!  const FREE_MARKET_TX_JSON: &str = r#"
//!  {
//!      "gasLimit": 21000,
//!      "maxFeePerGas": 100000000000,
//!      "maxPriorityFeePerGas": 3000000000,
//!      "chainId": 11155111,
//!      "nonce": 0,
//!      "to": "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
//!      "value": 10000000000000000,
//!      "data": "",
//!      "accessList": []
//!  }
//!  "#;
//!
//!  // Communication with AWS endpoint is asynchronous, so we need to use async main function
//!  #[tokio::main]
//!  async fn main() -> Result<()> {
//!      // Get KMS key ID from environment variable
//!      let kms_key_id = env::var(KMS_KEY_ID_VAR_NAME).or_else(|_| {
//!          bail!("Not set: {KMS_KEY_ID_VAR_NAME}");
//!      })?;
//!
//!      // Create a new KMS key
//!      let kms_key = &AwsKmsKey::new(
//!          &kms_key_id,
//!         #[cfg(feature = "sts-assume-role")]
//!         None).await;
//!      // Create a new EVM account
//!      let evm_account = EvmAccount::new(kms_key).await.or_else(|err| {
//!          bail!("Create EVM account: {err}");
//!      })?;
//!
//!      // Create a new unsigned EIP-1559 transaction
//!      let unigned_tx =
//!          serde_json::from_str::<FreeMarketTransaction>(FREE_MARKET_TX_JSON).or_else(|err| {
//!              bail!("Parse transaction JSON: {err}");
//!          })?;
//!
//!      // Sign the transaction using EVM account
//!      let signed_tx = evm_account
//!          .sign_transaction(unigned_tx)
//!          .await
//!          .or_else(|err| {
//!              bail!("Sign transaction: {err}");
//!          })?;
//!
//!      // Use the provided string serialization to get the signed transaction encoding.
//!      let signed_tx_encoding = serde_plain::to_string(&signed_tx).or_else(|err| {
//!          bail!("Serialize signed transaction: {err}");
//!      })?;
//!
//!      println!("Encoded signed type-2 transaction: {signed_tx_encoding}");
//!
//!      Ok(())
//!  }
//! ```
//!
//! ## Access list transaction (i.e. type 1 transaction)
//!
//! If you want to use an
//! [`EIP-2930`](https://eips.ethereum.org/EIPS/eip-2930) transaction instead, you declare the
//! transaction as:
//!
//! ```rust
//! const ACCESS_LIST_TX_JSON: &str = r#"
//! {
//!     "gasLimit": 21000,
//!     "gasPrice": 100000000000,
//!     "chainId": 11155111,
//!     "nonce": 0,
//!     "to": "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
//!     "value": 10000000000000000,
//!     "data": "",
//!     "accessList": [
//!         [
//!             "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
//!             [
//!                 "0x0000000000000000000000000000000000000000000000000000000000000003",
//!                 "0x0000000000000000000000000000000000000000000000000000000000000007"
//!             ]
//!         ],
//!         [
//!             "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
//!             []
//!         ]
//!     ]
//! }
//! "#;
//! ```
//!
//! You will also want to serialize the transaction as an `AccessListTransaction`.
//!
//! ## Legacy transaction (i.e. type 0 transaction)
//!
//! Legacy transactions are also supported. You can use the `LegacyTransaction` struct during
//! deserialization, and a sample JSON would look like this:
//!
//! ```rust
//! const LEGACY_TX_JSON: &str = r#"
//! {
//!     "gasLimit": 21000,
//!     "gasPrice": 100000000000,
//!     "nonce": 0,
//!     "to": "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
//!     "value": 10000000000000000,
//!     "data": ""
//! }
//! "#;
//! ```
//!
//! # Key policy requirements
//!
//! The principal your code is going to be executing as needs to have the necessary permissions to
//! use the KMS key. The permissions are set in the KMS key policy.
//!
//! At the very least the KMS key policy should have the following permissions that for the IAM role
//! that your environment assumes:
//! ```json
//! {
//!     "Sid": "AllowKeyUse",
//!     "Effect": "Allow",
//!     "Principal": {
//!         "AWS": "<iam_role_your_environment_assumes>"
//!     },
//!     "Action": [
//!         "kms:DescribeKey",
//!         "kms:GetPublicKey",
//!         "kms:Sign",
//!         "kms:Verify"
//!     ],
//!     "Resource": "*"
//! }
//! ```
//!
//! Furthermore, if you wish to use the library in client code which runs as an AWS resource like
//! e.g. a AWS Lambda function or a ECS task, you need to allow grants:
//! ```json
//! {
//!     "Sid": "AllowGrantsForAwsResources",
//!     "Effect": "Allow",
//!     "Principal": {
//!         "AWS": "<iam_role_your_environment_assumes>"
//!     },
//!     "Action": [
//!         "kms:CreateGrant",
//!         "kms:ListGrants",
//!         "kms:RevokeGrant"
//!     ],
//!     "Resource": "*",
//!     "Condition": {
//!         "Bool": {
//!             "kms:GrantIsForAWSResource": "true"
//!         }
//!     }
//! }
//! ```
//!

/// Abstraction over EVM accounts for signing transactions with AWS KMS keys.
pub mod account;
/// Implementation of the KMS key abstraction using AWS KMS SDK.
pub mod key;
/// Representations of EVM transactions.
pub mod transaction;
/// Type shorthands.
pub(crate) mod types;
