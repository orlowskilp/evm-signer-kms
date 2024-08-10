mod kms_key {
    mod integration_tests {
        use std::{fs::File, io::Read};

        use evm_signer_kms::evm_account::kms_key::KmsKey;

        const KMS_KEY_ID: &str = "52c9a19f-bcfd-46a7-bd56-6d0cf98d8616";
        const DUMMY_KMS_KEY_ID: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        const DUMMY_MESSAGE_DIGEST: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        #[tokio::test]
        async fn get_public_key_succeed() {
            let kms_key = KmsKey::new(KMS_KEY_ID);
            let mut public_key_file = File::open(format!("tests/data/{}.der", KMS_KEY_ID)).unwrap();

            let metadata_len = public_key_file.metadata().unwrap().len() as usize;
            let mut public_key_from_file = vec![0; metadata_len];
            public_key_file.read(&mut public_key_from_file).unwrap();

            let public_key_from_kms = kms_key.await.get_public_key().await.unwrap();

            assert_eq!(public_key_from_file, public_key_from_kms);
        }

        #[tokio::test]
        #[should_panic]
        async fn get_public_key_fail() {
            let kms_key = KmsKey::new(DUMMY_KMS_KEY_ID);

            kms_key.await.get_public_key().await.unwrap();
        }

        // Just verifies if the signature process works
        #[tokio::test]
        async fn sign_succeed() {
            let kms_key = KmsKey::new(KMS_KEY_ID);
            let message = &DUMMY_MESSAGE_DIGEST.to_vec();

            kms_key.await.sign(message).await.unwrap();
        }
    }
}
