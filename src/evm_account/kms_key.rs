use aws_config::SdkConfig;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
    Client,
};
use std::io::{Error, ErrorKind, Result};

/// Representation of `secp256k1` key pair stored in AWS KMS.
///
/// Provides minimal functionality to interact with the key pair for digest signing purposes.
///
/// # Cryptographic Configuration
///
/// The cryptographic configuration of the key pair should looks something like this:
/// ```json
/// {
///     "KeyMetadata": {
///         "AWSAccountId": "REDACTED",
///         "KeyId": "REDACTED",
///         "Arn": "REDACTED",
///         "CreationDate": REDACTED,
///         "Enabled": true,
///         "Description": "",
///         "KeyUsage": "SIGN_VERIFY",
///         "KeyState": "Enabled",
///         "Origin": "AWS_KMS",
///         "KeyManager": "CUSTOMER",
///         "CustomerMasterKeySpec": "ECC_SECG_P256K1",
///         "KeySpec": "ECC_SECG_P256K1",
///         "SigningAlgorithms": [
///             "ECDSA_SHA_256"
///         ],
///         "MultiRegion": false
///     }
/// }
/// ```
pub struct KmsKey<'a> {
    config: SdkConfig,
    kms_key_id: &'a str,
}

impl<'a> KmsKey<'a> {
    /// Creates a new `KmsKey` instance tied to KMS key identified by KMS key ID.
    ///
    /// Expects that AWS configuration is set in the environment, including a valid `AWS_REGION`.
    /// The key ID is in UUID format and can be obtained e.g. using AWS CLI:
    /// ```shell
    /// $ aws kms list-keys --region $AWS_REGION
    /// {
    ///     "Keys": [
    ///         {
    ///             "KeyId": "<kms_key_id>",
    ///             "KeyArn": "arn:aws:kms:<aws_region>:<aws_account_no>:key/<kms_key_id>"
    ///         },
    ///         ...
    ///     ]
    /// }
    /// ```
    ///
    /// **Note**: Neither the key ID nor the key's cryptographic configuration are verified.
    /// The method relies on the AWS SDK to do the validation.

    pub async fn new(kms_key_id: &'a str) -> KmsKey<'a> {
        let config = aws_config::from_env().load().await;

        KmsKey { config, kms_key_id }
    }

    /// Retrieves the public key associated with the private key.
    ///
    /// Returns the public key in DER encoded format.
    ///
    /// **Note**: If you fetch the key using AWS CLI for verification purposes, the key will be
    /// base64 encoded not DER encoded. You need to decode it and hex it, i.e.:
    /// ```shell
    /// $ aws kms get-public-key --key-id <kms_key_id> --region $AWS_REGION | jq -r .PublicKey | base64 -d | xxd -c 0 -ps
    /// 3056301006072a8648ce3d020106052b8104000a034200043b5ca9876d1c4ca39838fd8ef1bc4b138a1edf73ad8e29b9f6338f39e4a6f64c7d83df86b01deb689c6d14536413fce6752f4df7240d7180b53f27f5611d06a3
    /// ```
    pub async fn get_public_key(&self) -> Result<Vec<u8>> {
        let client = Client::new(&self.config);

        let get_public_key_output = client.get_public_key().key_id(self.kms_key_id).send();

        // Retrieve DER encoded public key
        let public_key_blob = get_public_key_output
            .await
            .map_err(|error| {
                Error::new(
                    ErrorKind::NotFound,
                    format!("Error getting public key: {:?}", error),
                )
            })?
            .public_key()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "Invalid response. No public key found",
                )
            })?
            .clone();

        Ok(public_key_blob.into_inner())
    }

    /// Signs a message digest using the private key.
    ///
    /// Expects a 32-byte digest of the message to be signed.
    ///
    /// Returns a DER encoded signature. Note that the signature is different every time.
    pub async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let client = Client::new(&self.config);

        let sign_output = client
            .sign()
            .key_id(self.kms_key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Digest)
            .message(Blob::new(message))
            .send();

        let signature = sign_output
            .await
            .map_err(|error| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    format!("Error signing message: {:?}", error),
                )
            })?
            .signature()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "Invalid response data. Signature not found",
                )
            })?
            .clone();

        // TODO: Remove cloning
        Ok(signature.into_inner())
    }
}
