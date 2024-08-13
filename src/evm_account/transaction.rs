use std::io::{Error, ErrorKind};

use serde::{Deserialize, Deserializer};

pub mod access_list;
pub mod free_market_transaction;

use crate::evm_account::{Keccak256Digest, SignatureComponent};
use access_list::Access;

const EIP_1559_TX_TYPE_ID: u8 = 0x02;
const HEX_PREFIX: &str = "0x";
const ADDRESS_LENGTH: usize = 20;

type AccountAddress = [u8; ADDRESS_LENGTH];

fn hex_data_string_to_bytes(hex_data: &str) -> Result<Vec<u8>, Error> {
    const HEX_RADIX: u32 = 16;
    const STEP_BY: usize = 2;

    let hex_data = hex_data.trim_start_matches(HEX_PREFIX);

    (0..hex_data.len())
        .step_by(STEP_BY)
        .map(|i| {
            u8::from_str_radix(&hex_data[i..i + STEP_BY], HEX_RADIX)
                .map_err(|error| Error::new(ErrorKind::InvalidData, error))
        })
        .collect()
}

fn deserialize_hex_data_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string = String::deserialize(deserializer)?;

    hex_data_string_to_bytes(&hex_string).map_err(|error| {
        serde::de::Error::custom(format!("Failed to deserialize hex data: {}", error))
    })
}

fn deserialize_address_string<'de, D>(deserializer: D) -> Result<AccountAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let address_string = String::deserialize(deserializer)?;

    hex_data_string_to_bytes(&address_string)
        .map_err(|error| {
            serde::de::Error::custom(format!("Failed to deserialize address: {}", error))
        })?
        // Checks whether address is of proper length
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid address length"))
}

#[cfg(test)]
mod unit_tests {
    use super::{hex_data_string_to_bytes, AccountAddress};

    const TEST_ADDR_STR: &str = "0xa9d89186cAA663C8Ef0352Fd1Db3596280625573";

    const TEST_ADDR_BYTES: AccountAddress = [
        0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3, 0x59,
        0x62, 0x80, 0x62, 0x55, 0x73,
    ];

    #[test]
    fn evm_address_to_bytes_test() {
        let input = TEST_ADDR_STR;
        let left = TEST_ADDR_BYTES.to_vec();

        let right = hex_data_string_to_bytes(input).unwrap();

        assert_eq!(left, right);
    }
}
