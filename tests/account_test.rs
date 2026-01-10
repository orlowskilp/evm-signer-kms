mod evm_account {
    mod integration_tests {
        use evm_signer_kms::{
            account::EvmAccount,
            key::aws_kms,
            transaction::{
                access_list_transaction::AccessListTransaction, address::AccountAddress,
                free_market_transaction::FreeMarketTransaction,
                legacy_transaction::LegacyTransaction,
            },
        };
        use lazy_static::lazy_static;
        use std::env;
        use std::fs::File;
        use test_log::test;

        // Reads the KMS_KEY_ID environment variable using lazy static evaluation.
        // Assumes no default value and fails if the key ID is not set!
        const KMS_KEY_ID_VAR_NAME: &str = "KMS_KEY_ID";
        lazy_static! {
            static ref KMS_KEY_ID: String = env::var(KMS_KEY_ID_VAR_NAME).unwrap_or_else(
                |_| panic!("⚠️ `{KMS_KEY_ID_VAR_NAME}` environment variable not set")
            );
        }

        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        // NOTE: Digest signatures from KMS are non-deterministic, so the output of this test will
        // vary. For this reason, the test is not asserting any specific value, but rather just
        // assess whether transaction encoding can be performed without errors.
        #[test(tokio::test)]
        async fn test_sign_transaction_ok() {
            let signing_key = &aws_kms::AwsKmsKey::new(
                &KMS_KEY_ID,
                #[cfg(feature = "sts-assume-role")]
                None,
            )
            .await;
            let evm_account = EvmAccount::new(signing_key);
            let tx = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 1,
                nonce: 0,
                to: Some(AccountAddress::from(TEST_TO_ADDRESS_BYTES)),
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![],
            };
            evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();
        }

        #[test(tokio::test)]
        async fn test_encode_signed_legacy_tx_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-legacy-tx-01.json";
            let signing_key = &aws_kms::AwsKmsKey::new(
                &KMS_KEY_ID,
                #[cfg(feature = "sts-assume-role")]
                None,
            )
            .await;
            let evm_account = EvmAccount::new(signing_key);
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();
            evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();
        }

        #[test(tokio::test)]
        async fn test_encode_signed_access_list_tx_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-access-list-tx-02.json";

            let signing_key = &aws_kms::AwsKmsKey::new(
                &KMS_KEY_ID,
                #[cfg(feature = "sts-assume-role")]
                None,
            )
            .await;
            let evm_account = EvmAccount::new(signing_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: AccessListTransaction = serde_json::from_reader(tx_file).unwrap();

            evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();
        }

        #[test(tokio::test)]
        async fn test_encode_signed_free_market_tx_no_access_list_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-01.json";
            let signing_key = &aws_kms::AwsKmsKey::new(
                &KMS_KEY_ID,
                #[cfg(feature = "sts-assume-role")]
                None,
            )
            .await;
            let evm_account = EvmAccount::new(signing_key);
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();
        }

        #[test(tokio::test)]
        async fn test_encode_signed_free_market_tx_with_access_list_1_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-03.json";
            let signing_key = &aws_kms::AwsKmsKey::new(
                &KMS_KEY_ID,
                #[cfg(feature = "sts-assume-role")]
                None,
            )
            .await;
            let evm_account = EvmAccount::new(signing_key);
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();
        }

        #[test(tokio::test)]
        async fn test_encode_signed_free_market_tx_with_access_list_2_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-04.json";
            let signing_key = &aws_kms::AwsKmsKey::new(
                &KMS_KEY_ID,
                #[cfg(feature = "sts-assume-role")]
                None,
            )
            .await;
            let evm_account = EvmAccount::new(signing_key);
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();
        }
    }
}
