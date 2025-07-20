mod legacy_transaction {
    mod integration_tests {
        use evm_signer_kms::transaction::{
            address::AccountAddress, legacy_transaction::LegacyTransaction,
        };
        use std::fs::File;
        use tracing_test::traced_test;

        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        #[test]
        #[traced_test]
        fn test_deserialize_valid_legacy_tx_01_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-legacy-tx-01.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = LegacyTransaction {
                nonce: 5,
                gas_limit: 21_000,
                gas_price: 100_000_000_000,
                to: Some(AccountAddress::from(TEST_TO_ADDRESS_BYTES)),
                value: 10_000_000_000_000_000,
                data: vec![],
            };
            let right: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        #[ignore = "This may actually not be a valid format for deserialization after all"]
        fn test_deserialize_valid_legacy_tx_02_ok() {
            const TX_FILE_PATH: &str = "tests/data/valid-legacy-tx-02.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = LegacyTransaction {
                nonce: 5,
                gas_limit: 21_000,
                gas_price: 100_000_000_000,
                to: None,
                value: 10_000_000_000_000_000,
                data: vec![],
            };
            let right: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();
            assert_eq!(left, right);
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_legacy_tx_01_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-legacy-tx-01.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, LegacyTransaction>(tx_file).unwrap();
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_legacy_tx_02_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-legacy-tx-02.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, LegacyTransaction>(tx_file).unwrap();
        }

        #[test]
        #[traced_test]
        #[should_panic]
        fn test_deserialize_invalid_legacy_tx_03_fail() {
            const TX_FILE_PATH: &str = "tests/data/invalid-legacy-tx-03.json";
            let tx_file = File::open(TX_FILE_PATH).unwrap();
            serde_json::from_reader::<_, LegacyTransaction>(tx_file).unwrap();
        }
    }
}
