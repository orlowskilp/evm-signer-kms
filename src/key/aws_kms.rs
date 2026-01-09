use aws_config::{SdkConfig, sts::AssumeRoleProvider};
use aws_sdk_kms::{
    Client as KmsClient,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
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
///         "AWSAccountId": "[REDACTED]",
///         "KeyId": "[REDACTED]",
///         "Arn": "[REDACTED]",
///         "CreationDate": [REDACTED],
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
pub struct AwsKmsKey<'a> {
    kms_client: KmsClient,
    kms_key_id: &'a str,
}

impl<'a> AwsKmsKey<'a> {
    /// Assumes an IAM role and returns a new AWS SDK configuration, which then can be used to create
    /// AWS service clients with the assumed role's permissions.
    async fn assume_role(config: &SdkConfig, role_arn: &str, session_name: &str) -> SdkConfig {
        let provider = AssumeRoleProvider::builder(role_arn)
            .session_name(session_name)
            .configure(config)
            .build()
            .await;
        aws_config::from_env()
            .credentials_provider(provider)
            .load()
            .await
    }
    /// Creates a new `KmsKey` instance tied to KMS key identified by KMS key ID.
    ///
    /// Expects that AWS configuration is set in the environment, including a valid `AWS_REGION`.
    /// The key ID is in UUID format and can be obtained e.g. using AWS CLI:
    /// ```shell
    /// $ aws kms list-keys --region $AWS_REGION
    /// {
    ///     "Keys": [
    ///         {
    ///             "KeyId": "[`The key ID you are looking for`]",
    ///             "KeyArn": [REDACTED]"
    ///         },
    ///         ...
    ///     ]
    /// }
    /// ```
    ///
    /// **Note**: Neither the key ID nor the key's cryptographic configuration are verified.
    /// The method relies on the AWS SDK to do the validation. The public key OID is later verified
    /// during key decoding.
    pub async fn new(kms_key_id: &'a str, role: Option<&'a str>) -> Self {
        // TODO: Make session name configurable, depending on identity provider used.
        const AWS_STS_SESSION_NAME: &str = "evm-signer-kms-session";
        let mut config = aws_config::from_env().load().await;
        if let Some(role_arn) = role {
            config = Self::assume_role(&config, role_arn, AWS_STS_SESSION_NAME).await;
            tracing::info!("Assumed role: {role_arn}");
        }
        tracing::info!("AWS credentials and region loaded successfully");
        let kms_client = KmsClient::new(&config);
        tracing::info!("AWS KMS client created successfully");
        Self {
            kms_client,
            kms_key_id,
        }
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
        self.kms_client
            .get_public_key()
            .key_id(self.kms_key_id)
            .send()
            .await
            .map_err(|err| {
                let msg = format!("Error getting public key: {err:?}");
                tracing::error!(msg);
                Error::new(ErrorKind::NotFound, msg)
            })?
            .public_key()
            .ok_or_else(|| {
                let msg = "Invalid response. No public key found";
                tracing::error!(msg);
                Error::new(ErrorKind::InvalidData, msg)
            })
            .map(|pk| pk.to_owned().into_inner())
    }

    /// Signs a message digest using the private key.
    ///
    /// Expects a 32-byte digest of the message to be signed.
    ///
    /// Returns a DER encoded signature. Note that the signature is different every time.
    pub async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.kms_client
            .sign()
            .key_id(self.kms_key_id)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message_type(MessageType::Digest)
            .message(Blob::new(message))
            .send()
            .await
            .map_err(|err| {
                let msg = format!("Error signing message: {err:?}");
                tracing::error!(msg);
                Error::new(ErrorKind::PermissionDenied, msg)
            })?
            .signature()
            .ok_or_else(|| {
                let msg = "Invalid response data. Signature not found";
                tracing::error!(msg);
                Error::new(ErrorKind::InvalidData, msg)
            })
            .map(|sig| sig.to_owned().into_inner())
    }

    /// Enables previously disabled KMS key.
    pub async fn enable(&self) -> Result<()> {
        self.kms_client
            .enable_key()
            .key_id(self.kms_key_id)
            .send()
            .await
            .map_err(|err| {
                let msg = format!("Error enabling KMS key: {err:?}");
                tracing::error!(msg);
                Error::new(ErrorKind::PermissionDenied, msg)
            })
            .map(|_| tracing::info!("KMS key enabled: {}", self.kms_key_id))
    }

    /// Disables the KMS key, preventing any signing operations.
    pub async fn disable(&self) -> Result<()> {
        self.kms_client
            .disable_key()
            .key_id(self.kms_key_id)
            .send()
            .await
            .map_err(|err| {
                let msg = format!("Error disabling KMS key: {err:?}");
                tracing::error!(msg);
                Error::new(ErrorKind::PermissionDenied, msg)
            })
            .map(|_| tracing::info!("KMS key disabled: {}", self.kms_key_id))
    }
}
