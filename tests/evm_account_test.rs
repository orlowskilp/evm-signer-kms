mod evm_account {
    mod integration_tests {
        use lazy_static::lazy_static;
        use std::env;
        use std::fs::File;

        use evm_signer_kms::{
            evm_account::{
                EvmAccount,
                transaction::{
                    access_list_transaction::AccessListTransaction,
                    free_market_transaction::FreeMarketTransaction,
                    legacy_transaction::LegacyTransaction,
                },
            },
            key::kms_key,
        };

        // Reads the KMS_KEY_ID environment variable using lazy static evaluation.
        // Assumes no default value and fails if the key ID is not set!
        const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
        lazy_static! {
            static ref KMS_KEY_ID: String = env::var(KMS_KEY_ID_VAR_NAME).unwrap_or_else(
                |_| panic!("⚠️ `{}` environment variable not set", KMS_KEY_ID_VAR_NAME)
            );
        }

        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        // NOTE: Digest signatures from KMS are non-deterministic, so the output of this test will
        // vary. For this reason, the test is not asserting any specific value, but rather just
        // assess whether transaction encoding can be performed without errors.
        //
        // The transactions are printed, so that they can be manually verified.

        #[tokio::test]
        async fn sign_transaction_succeed() {
            let kms_key = &kms_key::KmsKey::new(&KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(kms_key);

            let tx = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 1,
                nonce: 0,
                to: Some(TEST_TO_ADDRESS_BYTES),
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![],
            };

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            // Print the signed transaction bytes for manual verification
            println!("{:02x?}", signed_tx);
        }

        #[tokio::test]
        async fn encode_signed_legacy_tx_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-legacy-tx-01.json";

            let kms_key = &kms_key::KmsKey::new(&KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(kms_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            let signed_tx_encoding_string = serde_plain::to_string(&signed_tx).unwrap();

            // Print the signed transaction bytes for manual verification
            println!("{}", signed_tx_encoding_string);
        }

        #[tokio::test]
        async fn encode_signed_access_list_tx_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-access-list-tx-02.json";

            let kms_key = &kms_key::KmsKey::new(&KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(kms_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: AccessListTransaction = serde_json::from_reader(tx_file).unwrap();

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            let signed_tx_encoding_string = serde_plain::to_string(&signed_tx).unwrap();

            // Print the signed transaction bytes for manual verification
            println!("{}", signed_tx_encoding_string);
        }

        #[tokio::test]
        async fn encode_signed_free_market_tx_no_access_list_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-01.json";

            let kms_key = &kms_key::KmsKey::new(&KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(kms_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            let signed_tx_encoding_string = serde_plain::to_string(&signed_tx).unwrap();

            // Print the signed transaction bytes for manual verification
            println!("{}", signed_tx_encoding_string);
        }

        #[tokio::test]
        async fn encode_signed_free_market_tx_with_access_list_1_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-03.json";

            let kms_key = &kms_key::KmsKey::new(&KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(kms_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            let signed_tx_encoding_string = serde_plain::to_string(&signed_tx).unwrap();

            // Print the signed transaction bytes for manual verification
            println!("{}", signed_tx_encoding_string);
        }

        #[tokio::test]
        async fn encode_signed_free_market_tx_with_access_list_2_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-04.json";

            let kms_key = &kms_key::KmsKey::new(&KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(kms_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            let signed_tx_encoding_string = serde_plain::to_string(&signed_tx).unwrap();

            // Print the signed transaction bytes for manual verification
            println!("{}", signed_tx_encoding_string);
        }
    }
}
