use crate::transaction::{ADDRESS_LENGTH, HEX_PREFIX, HEX_RADIX};
use serde::{Deserialize, Serialize, Serializer, de::Error as DeError};
use sha3::{Digest, Keccak256};
use std::io::{Error as IoError, ErrorKind};

/// EVM address abstraction.
#[derive(Debug, PartialEq)]
pub struct AccountAddress {
    bytes: [u8; ADDRESS_LENGTH],
}

impl From<[u8; ADDRESS_LENGTH]> for AccountAddress {
    fn from(bytes: [u8; ADDRESS_LENGTH]) -> Self {
        Self { bytes }
    }
}

impl Serialize for AccountAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        format!("{}{}", HEX_PREFIX, hex::encode(self.bytes)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AccountAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let addr_str = String::deserialize(deserializer)?;
        if !validate_address_checksum(&addr_str) {
            return Err(DeError::custom(format!(
                "Invalid address checksum: {addr_str}"
            )));
        }
        hex::decode(addr_str.trim_start_matches(HEX_PREFIX))
            .map_err(DeError::custom)?
            .try_into()
            .map_err(|v: Vec<_>| {
                DeError::custom(format!(
                    "Expected 20 bytes for account address, got {}",
                    v.len()
                ))
            })
            .map(|fb: [u8; ADDRESS_LENGTH]| AccountAddress::from(fb))
    }
}

impl AccountAddress {
    /// Returns the address as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

fn compute_address_checksum(address: &str) -> Result<String, IoError> {
    let address_ascii_lowercase = address.trim_start_matches(HEX_PREFIX).to_ascii_lowercase();
    // Compute the hash of the address and represent it as numerical values
    let hex_hash = hex::encode(Keccak256::digest(&address_ascii_lowercase))
        .chars()
        // Safety: If this errors, then the keccak256 digest is not valid hex, which should never happen
        .map(|ch| u8::from_str_radix(&ch.to_string(), HEX_RADIX).expect("Invalid hex character"))
        .collect::<Vec<_>>();
    // Iterate over the address and hash, and construct the checksummed address according to EIP-55
    address_ascii_lowercase.chars().zip(hex_hash).try_fold(
        HEX_PREFIX.to_string(),
        |mut address_checksum, (nibble, hashed_address_nibble)| {
            address_checksum.push(match nibble {
                '0'..='9' => nibble,
                'a'..='f' if hashed_address_nibble > 7 => nibble.to_ascii_uppercase(),
                'a'..='f' => nibble,
                _ => {
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        format!("Invalid character in address: {nibble}"),
                    ));
                }
            });
            Ok(address_checksum)
        },
    )
}

fn validate_address_checksum(address: &str) -> bool {
    // If the address is all in lowercase, this means no checksum was applied and no validation is
    // needed. This is acceptable, however a warning should be logged.
    if address == address.to_ascii_lowercase() {
        return true;
    }
    // Otherwise strict chgecksum validation is required.
    match compute_address_checksum(address) {
        Ok(checksum) => checksum == address,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDRESS_BYTES_1: [u8; ADDRESS_LENGTH] = [
        0xa9, 0xd8, 0x91, 0x86, 0xca, 0xa6, 0x63, 0xc8, 0xef, 0x03, 0x52, 0xfd, 0x1d, 0xb3, 0x59,
        0x62, 0x80, 0x62, 0x55, 0x73,
    ];
    const TEST_ADDRESS_BYTES_2: [u8; ADDRESS_LENGTH] = [
        0x5a, 0xae, 0xb6, 0x05, 0x3F, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94, 0x35,
        0xe7, 0xef, 0x1b, 0xea, 0xed,
    ];
    const TEST_ADDR_STR_1: &str = "0xa9d89186caa663c8ef0352fd1db3596280625573";
    const TEST_ADDR_STR_2: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    #[test]
    fn test_serialize_address_ok() {
        let address = AccountAddress::from(TEST_ADDRESS_BYTES_1);
        let left = serde_plain::to_string(&address).unwrap();
        let right = TEST_ADDR_STR_1;
        assert_eq!(left, right);
    }

    #[test]
    fn test_deserialize_address_ok_not_checksumed() {
        let left = serde_plain::from_str::<AccountAddress>(TEST_ADDR_STR_1)
            .unwrap()
            .bytes;
        let right = TEST_ADDRESS_BYTES_1;
        assert_eq!(left, right);
    }

    #[test]
    fn test_deserialize_address_ok_checksumed() {
        let left = serde_plain::from_str::<AccountAddress>(TEST_ADDR_STR_2)
            .unwrap()
            .bytes;
        let right = TEST_ADDRESS_BYTES_2;
        assert_eq!(left, right);
    }

    #[test]
    #[should_panic(expected = "Expected 20 bytes for account address")]
    fn test_deserialize_address_fail_too_short() {
        serde_plain::from_str::<AccountAddress>(&TEST_ADDR_STR_1[..(2 * ADDRESS_LENGTH - 2)])
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Expected 20 bytes for account address")]
    fn test_deserialize_address_fail_too_long() {
        serde_plain::from_str::<AccountAddress>(format!("{}{}", TEST_ADDR_STR_1, "00").as_str())
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Odd number of digits")]
    fn test_deserialize_address_fail_even_str_len() {
        serde_plain::from_str::<AccountAddress>(&TEST_ADDR_STR_1[..(2 * ADDRESS_LENGTH - 1)])
            .unwrap();
    }

    #[test]
    fn test_deserialize_address_fail_no_prefix() {
        let left =
            serde_plain::from_str::<AccountAddress>("a9d89186caa663c8ef0352fd1db3596280625573")
                .unwrap()
                .bytes;
        let right = TEST_ADDRESS_BYTES_1;
        assert_eq!(left, right);
    }

    #[test]
    #[should_panic(expected = "Invalid address checksum")]
    fn test_deserialize_address_fail_invalid_checksum() {
        serde_plain::from_str::<AccountAddress>("0xA9d89186caa663c8ef0352fd1db3596280625573")
            .unwrap();
    }
}
