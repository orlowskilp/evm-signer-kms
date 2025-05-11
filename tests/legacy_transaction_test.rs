mod legacy_transaction {
    mod integration_tests {
        use std::fs::File;

        use evm_signer_kms::transaction::legacy_transaction::LegacyTransaction;

        const TEST_TO_ADDRESS_BYTES: [u8; 20] = [
            0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3,
            0x59, 0x62, 0x80, 0x62, 0x55, 0x73,
        ];

        #[test]
        fn deserialize_valid_legacy_tx_01_succeed() {
            const TX_FILE_PATH: &str = "tests/data/valid-legacy-tx-01.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();
            let left = LegacyTransaction {
                nonce: 5,
                gas_limit: 21_000,
                gas_price: 100_000_000_000,
                to: Some(TEST_TO_ADDRESS_BYTES),
                value: 10_000_000_000_000_000,
                data: vec![],
            };

            let right: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();

            assert_eq!(left, right);
        }

        #[test]
        fn deserialize_valid_legacy_tx_02_succeed() {
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
        #[should_panic]
        fn deserialize_invalid_legacy_tx_01_succeed() {
            const TX_FILE_PATH: &str = "tests/data/invalid-legacy-tx-01.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();

            let _: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();
        }

        #[test]
        #[should_panic]
        fn deserialize_invalid_legacy_tx_02_succeed() {
            const TX_FILE_PATH: &str = "tests/data/invalid-legacy-tx-02.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();

            let _: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();
        }

        #[test]
        #[should_panic]
        fn deserialize_invalid_legacy_tx_03_succeed() {
            const TX_FILE_PATH: &str = "tests/data/invalid-legacy-tx-03.json";

            let tx_file = File::open(TX_FILE_PATH).unwrap();

            let _: LegacyTransaction = serde_json::from_reader(tx_file).unwrap();
        }
    }
}
