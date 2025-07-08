use super::AccountAddress;
use rlp::{Encodable, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, de::Error};

const STORAGE_KEY_LEN: usize = 32;

type StorageKeyBytes = [u8; STORAGE_KEY_LEN];

#[derive(Debug, PartialEq, Serialize)]
pub struct StorageKey {
    bytes: StorageKeyBytes,
}

impl From<StorageKeyBytes> for StorageKey {
    fn from(bytes: StorageKeyBytes) -> Self {
        Self { bytes }
    }
}

impl<'de> Deserialize<'de> for StorageKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<StorageKey, D::Error> {
        super::fit_bytes::<StorageKeyBytes, D>(&super::deserialize(deserializer)?)
            .map_err(|err| D::Error::custom(format!("Expected 32 bytes for storage key: {err}")))
            .map(StorageKey::from)
    }
}

impl StorageKey {
    /// Returns the storage key as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Structure of an access i.e. an address and a list of storage keys accessed by a transaction.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Access {
    /// Address of the account accessed by the transaction.
    pub address: AccountAddress,
    /// List of storage keys accessed by the transaction.
    pub storage_keys: Vec<StorageKey>,
}

impl Encodable for Access {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list()
            .append(&self.address.as_slice())
            .begin_unbounded_list();
        self.storage_keys.iter().for_each(|key| {
            s.append(&key.as_slice());
        });
        s.finalize_unbounded_list();
        s.finalize_unbounded_list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_STORAGE_KEY_STR_1: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000003";
    const TEST_STORAGE_KEY_BYTES_1: StorageKeyBytes = {
        let mut d = [0u8; STORAGE_KEY_LEN];
        d[STORAGE_KEY_LEN - 1] = 0x03;
        d
    };

    #[test]
    fn test_deserialize_storage_key_ok() {
        let left = serde_plain::from_str::<StorageKey>(TEST_STORAGE_KEY_STR_1)
            .unwrap()
            .bytes;
        let right = TEST_STORAGE_KEY_BYTES_1;
        assert_eq!(left, right);
    }

    #[test]
    #[should_panic(expected = "Expected 32 bytes for storage key")]
    fn test_deserialize_storage_key_fail_too_short() {
        serde_plain::from_str::<StorageKey>(&TEST_STORAGE_KEY_STR_1[..(2 * STORAGE_KEY_LEN - 2)])
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Expected 32 bytes for storage key")]
    fn test_deserialize_storage_key_fail_too_long() {
        serde_plain::from_str::<StorageKey>(format!("{}{}", TEST_STORAGE_KEY_STR_1, "00").as_str())
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Odd number of digits")]
    fn test_deserialize_storage_key_fail_odd_str_len() {
        serde_plain::from_str::<StorageKey>(&TEST_STORAGE_KEY_STR_1[..(2 * STORAGE_KEY_LEN - 1)])
            .unwrap();
    }
}
