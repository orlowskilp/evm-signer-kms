mod evm_account {
    mod integration_tests {
        use serde_json;
        use serde_plain;
        use std::fs::File;

        use evm_signer_kms::evm_account::{
            transaction::free_market_transaction::FreeMarketTransactionUnsigned,
            {kms_key, EvmAccount},
        };

        const KMS_KEY_ID: &str = "52c9a19f-bcfd-46a7-bd56-6d0cf98d8616";
        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        // Only verifies if the signature can be generated
        #[tokio::test]
        async fn sign_transaction_succeed() {
            let kms_key = &kms_key::KmsKey::new(KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(1, kms_key);

            let tx = FreeMarketTransactionUnsigned {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 1,
                nonce: 0,
                to: TEST_TO_ADDRESS_BYTES,
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

            println!("{:02x?}", signed_tx);
        }

        #[tokio::test]
        async fn encode_signed_tx_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-tx-01.json";
            const CHAIN_ID: u64 = 421614;

            let kms_key = &kms_key::KmsKey::new(KMS_KEY_ID).await;
            let evm_account = EvmAccount::new(CHAIN_ID, kms_key);

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let tx: FreeMarketTransactionUnsigned = serde_json::from_reader(tx_file).unwrap();

            let signed_tx = evm_account
                .await
                .unwrap()
                .sign_transaction(tx)
                .await
                .unwrap();

            let signed_tx_encoding_string = serde_plain::to_string(&signed_tx).unwrap();

            // TODO: Verify the encoding string
            println!("{}", signed_tx_encoding_string);
        }
    }
}
