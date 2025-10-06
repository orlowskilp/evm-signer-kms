mod kms_key {
    mod integration_tests {
        use aws_sdk_kms::{
            primitives::Blob,
            types::{MessageType, SigningAlgorithmSpec},
        };
        use evm_signer_kms::key::aws_kms::AwsKmsKey;
        use lazy_static::lazy_static;
        use std::env;
        use test_log::test;

        // Reads the KMS_KEY_ID environment variable using lazy static evaluation.
        // Assumes no default value and fails if the key ID is not set!
        const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
        lazy_static! {
            static ref KMS_KEY_ID: String = env::var(KMS_KEY_ID_VAR_NAME).unwrap_or_else(
                |_| panic!("⚠️ `{KMS_KEY_ID_VAR_NAME}` environment variable not set")
            );
        }

        fn get_public_key_from_env() -> [u8; 88] {
            let pub_key_hex = env::var("TEST_DER_PUB_KEY")
                .unwrap_or_else(|_| panic!("⚠️ `TEST_DER_PUB_KEY` environment variable not set"));
            hex::decode(pub_key_hex)
                .expect("Invalid hex in TEST_DER_PUB_KEY")
                .try_into()
                .expect("Public key length mismatch")
        }

        const DUMMY_KMS_KEY_ID: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        const DUMMY_MESSAGE_DIGEST: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        async fn verify_kms_signature(message: &[u8], signature: &[u8]) -> bool {
            let sdk_config = aws_config::from_env().load().await;
            let kms_client = aws_sdk_kms::Client::new(&sdk_config);
            kms_client
                .verify()
                .key_id(KMS_KEY_ID.to_string())
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .message_type(MessageType::Digest)
                .message(Blob::new(message))
                .signature(Blob::new(signature))
                .send()
                .await
                .map(|resp| resp.signature_valid())
                .expect("Error verifying KMS signature")
        }

        #[test(tokio::test)]
        async fn test_get_public_key_ok() {
            let signing_key = AwsKmsKey::new(&KMS_KEY_ID, None).await;
            let left = signing_key.get_public_key().await.unwrap();
            let right = get_public_key_from_env();
            assert_eq!(left, right);
        }

        #[test(tokio::test)]
        #[should_panic]
        async fn test_get_public_key_fail() {
            let kms_key = AwsKmsKey::new(DUMMY_KMS_KEY_ID, None);
            kms_key.await.get_public_key().await.unwrap();
        }

        #[test(tokio::test)]
        async fn test_sign_ok() {
            let kms_key = AwsKmsKey::new(&KMS_KEY_ID, None);
            let message = &DUMMY_MESSAGE_DIGEST.to_vec();
            let signature = &kms_key.await.sign(message).await.unwrap();
            assert!(verify_kms_signature(message, signature).await);
        }
    }
}
