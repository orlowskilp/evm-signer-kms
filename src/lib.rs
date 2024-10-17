//! EVM account abstraction for signing transactions using [AWS KMS](https://aws.amazon.com/kms)
//! keys.
//!
//! This library provides an abstraction for EVM accounts to sign transactions using AWS KMS keys.
//! Designed for security, as the private key never leaves the KMS service uncencrypted.
//! With careful KMS keys policy, the key extraction can be completely disabled making the library
//! a perfect fit for verifiably secure production environments.
//!
//! # Key policy requirements
//!
//! At the very least the KMS key policy should have the following permissions that for the IAM role
//! that your environment assumes:
//! ```json
//! {
//!     "Sid": "Allow key use",
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
//!     "Sid": "Allow grants for AWS resources",
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
//! # Examples
//!
//! The following example demonstrates how to sign an
//! [`EIP-1559`](https://eips.ethereum.org/EIPS/eip-1559) transaction:
//!
//! ```rust
//! use evm_signer_kms::evm_account::{
//!     kms_key::KmsKey,
//!     transaction::{
//!         free_market_transaction::FreeMarketTransaction,
//!         AccountAddress, SignedTransaction, Transaction
//!     }, EvmAccount,
//! };
//! use std::{env, io::{Error, ErrorKind, Result}};
//!
//! // Name of the environment variable that contains the KMS key ID
//! const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
//! // Recipient address of the transaction represented as a byte array
//! const TO_ADDRESS_BYTES: AccountAddress = [
//!     0xa9, 0xe7, 0x81, 0x76, 0xcb, 0xa5, 0x61, 0xd8, 0xee, 0x13, 0x42, 0xef, 0x2d, 0xb2,
//!     0x58, 0x60, 0x81, 0x52, 0x88, 0x71,
//! ];
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Get KMS key ID from environment variable
//!     let kms_key_id = env::var(KMS_KEY_ID_VAR_NAME).map_err(|_| {
//!         Error::new(ErrorKind::NotFound, format!(
//!             "Environment variable {} not set",
//!             KMS_KEY_ID_VAR_NAME,
//!         ))
//!     })?;
//!
//!     // Create a new KMS key
//!     let kms_key = &KmsKey::new(&kms_key_id).await;
//!     // Create a new EVM account
//!     let evm_account = EvmAccount::new(kms_key)
//!         .await
//!         .map_err(|error| Error::new(ErrorKind::PermissionDenied, format!(
//!             "Failed to create EVM account: {}",
//!             error,
//!         ))
//!     )?;
//!
//!     // Create a new unsigned EIP-1559 transaction
//!     let unigned_tx = FreeMarketTransaction {
//!         gas_limit: 21_000,
//!         max_fee_per_gas: 100_000_000_000,
//!         max_priority_fee_per_gas: 3_000_000_000,
//!         chain_id: 11155111,
//!         nonce: 0,
//!         to: Some(TO_ADDRESS_BYTES),
//!         value: 10_000_000_000_000_000,
//!         data: vec![],
//!         access_list: vec![],
//!     };
//!
//!     // Sign the transaction using EVM account
//!     let signed_tx = evm_account
//!         .sign_transaction(unigned_tx)
//!         .await
//!         .map_err(|error| Error::new(ErrorKind::PermissionDenied, format!(
//!             "Failed to sign transaction: {}",
//!             error,
//!         ))
//!     )?;
//!
//!     // Use the provided string serialization to get the signed transaction encoding.
//!
//!     Ok(())
//! }
//! ```

/// Provides abstraction for EVM accounts to sign transactions using AWS KMS keys.
pub mod evm_account;
