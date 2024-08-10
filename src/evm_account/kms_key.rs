use aws_config::SdkConfig;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
    Client,
};
use std::io::{Error, ErrorKind, Result};

pub struct KmsKey<'a> {
    config: SdkConfig,
    kms_key_id: &'a str,
}

impl<'a> KmsKey<'a> {
    pub async fn new(kms_key_id: &'a str) -> KmsKey<'a> {
        let config = aws_config::from_env().load().await;

        KmsKey { config, kms_key_id }
    }

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
