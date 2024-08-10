mod evm_account {
    mod integration_tests {
        use serde_json;
        use std::fs::File;

        use evm_signer_kms::evm_account::transaction::free_market_transaction::FreeMarketTransactionUnsigned;

        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        #[test]
        fn deserialize_valid_tx_01_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-tx-01.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransactionUnsigned {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 2,
                to: TEST_TO_ADDRESS_BYTES,
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![],
            };

            let right: FreeMarketTransactionUnsigned = serde_json::from_reader(tx_file).unwrap();

            assert_eq!(left, right);
        }

        #[test]
        fn deserialize_valid_tx_02_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-tx-02.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransactionUnsigned {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 0,
                to: TEST_TO_ADDRESS_BYTES,
                value: 10_000_000_000_000_000,
                data: vec![171, 205],
                access_list: vec![],
            };

            let right: FreeMarketTransactionUnsigned = serde_json::from_reader(tx_file).unwrap();

            assert_eq!(left, right);
        }

        #[test]
        #[should_panic]
        fn deserialize_invalid_tx_01_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-tx-01.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();

            let _: FreeMarketTransactionUnsigned = serde_json::from_reader(tx_file).unwrap();
        }

        #[test]
        #[should_panic]
        fn deserialize_invalid_tx_02_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-tx-02.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();

            let _: FreeMarketTransactionUnsigned = serde_json::from_reader(tx_file).unwrap();
        }

        #[test]
        #[should_panic]
        fn deserialize_invalid_tx_03_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-tx-03.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();

            let _: FreeMarketTransactionUnsigned = serde_json::from_reader(tx_file).unwrap();
        }
    }
}
