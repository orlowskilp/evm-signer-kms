mod free_market_transaction {
    mod integration_tests {
        use evm_signer_kms::transaction::{
            access_list::{Access, StorageKey},
            address::AccountAddress,
            free_market_transaction::FreeMarketTransaction,
        };
        use std::fs::File;
        use tracing_test::traced_test;

        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        #[test]
        #[traced_test]
        fn test_deserialize_valid_free_market_tx_01_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-01.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 5,
                to: Some(AccountAddress::from(TEST_TO_ADDRESS_BYTES)),
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![],
            };
            let right: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        fn test_deserialize_valid_free_market_tx_02_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-02.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 0,
                to: Some(AccountAddress::from(TEST_TO_ADDRESS_BYTES)),
                value: 10_000_000_000_000_000,
                data: vec![171, 205],
                access_list: vec![],
            };
            let right: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        fn test_deserialize_valid_free_market_tx_03_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-03.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 2,
                to: Some(AccountAddress::from(TEST_TO_ADDRESS_BYTES)),
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![Access {
                    address: AccountAddress::from([
                        0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc,
                        0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13,
                    ]),
                    storage_keys: vec![],
                }],
            };
            let right: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        fn test_deserialize_valid_free_market_tx_04_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-04.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 2,
                to: Some(AccountAddress::from(TEST_TO_ADDRESS_BYTES)),
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![
                    Access {
                        address: AccountAddress::from([
                            0xde, 0x0b, 0x29, 0x56, 0x69, 0xa9, 0xfd, 0x93, 0xd5, 0xf2, 0x8d, 0x9e,
                            0xc8, 0x5e, 0x40, 0xf4, 0xcb, 0x69, 0x7b, 0xae,
                        ]),
                        storage_keys: vec![
                            StorageKey::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                            ]),
                            StorageKey::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
                            ]),
                        ],
                    },
                    Access {
                        address: AccountAddress::from([
                            0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc,
                            0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13,
                        ]),
                        storage_keys: vec![],
                    },
                ],
            };
            let right: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        fn test_deserialize_valid_free_market_tx_05_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-free-market-tx-05.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = FreeMarketTransaction {
                gas_limit: 21_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 3_000_000_000,
                chain_id: 421614,
                nonce: 2,
                to: None,
                value: 10_000_000_000_000_000,
                data: vec![],
                access_list: vec![
                    Access {
                        address: AccountAddress::from([
                            0xde, 0x0b, 0x29, 0x56, 0x69, 0xa9, 0xfd, 0x93, 0xd5, 0xf2, 0x8d, 0x9e,
                            0xc8, 0x5e, 0x40, 0xf4, 0xcb, 0x69, 0x7b, 0xae,
                        ]),
                        storage_keys: vec![
                            StorageKey::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                            ]),
                            StorageKey::from([
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
                            ]),
                        ],
                    },
                    Access {
                        address: AccountAddress::from([
                            0xbb, 0x9b, 0xc2, 0x44, 0xd7, 0x98, 0x12, 0x3f, 0xde, 0x78, 0x3f, 0xcc,
                            0x1c, 0x72, 0xd3, 0xbb, 0x8c, 0x18, 0x94, 0x13,
                        ]),
                        storage_keys: vec![],
                    },
                ],
            };
            let right: FreeMarketTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_free_market_tx_01_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-free-market-tx-01.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, FreeMarketTransaction>(tx_file).unwrap();
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_free_market_tx_02_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-free-market-tx-02.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, FreeMarketTransaction>(tx_file).unwrap();
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_free_market_tx_03_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-free-market-tx-03.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, FreeMarketTransaction>(tx_file).unwrap();
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_free_market_tx_04_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-free-market-tx-04.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, FreeMarketTransaction>(tx_file).unwrap();
        }
    }
}
