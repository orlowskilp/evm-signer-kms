mod kms_key {
    mod integration_tests {
        use evm_signer_kms::key::aws_kms::AwsKmsKey;
        use lazy_static::lazy_static;
        use std::env;
        use tracing_test::traced_test;

        // Reads the KMS_KEY_ID environment variable using lazy static evaluation.
        // Assumes no default value and fails if the key ID is not set!
        const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
        lazy_static! {
            static ref KMS_KEY_ID: String = env::var(KMS_KEY_ID_VAR_NAME).unwrap_or_else(
                |_| panic!("⚠️ `{KMS_KEY_ID_VAR_NAME}` environment variable not set")
            );
        }

        const TEST_DER_ENCODED_PUBLIC_KEY: &str = "3056301006072a8648ce3d020106052b8104000a03420004f952b96eb7a7845adabe934be3438d92e997647856dbc4897c661d2e8f39be7a2783234742d411b3c9e4554db4c8662a547160f7ee30d0aa680088e1a1dd80c0";
        const DUMMY_KMS_KEY_ID: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        const DUMMY_MESSAGE_DIGEST: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        #[tokio::test]
        #[traced_test]
        async fn test_get_public_key_ok() {
            let signing_key = AwsKmsKey::new(&KMS_KEY_ID).await;
            let left = signing_key.get_public_key().await.unwrap();
            let right = hex::decode(TEST_DER_ENCODED_PUBLIC_KEY).unwrap();
            assert_eq!(left, right);
        }

        #[tokio::test]
        #[traced_test]
        #[should_panic]
        async fn test_get_public_key_fail() {
            let kms_key = AwsKmsKey::new(DUMMY_KMS_KEY_ID);
            kms_key.await.get_public_key().await.unwrap();
        }

        // Just verifies if the signature process works
        #[tokio::test]
        #[traced_test]
        async fn test_sign_ok() {
            let kms_key = AwsKmsKey::new(&KMS_KEY_ID);
            let message = &DUMMY_MESSAGE_DIGEST.to_vec();
            kms_key.await.sign(message).await.unwrap();
        }
    }
}
