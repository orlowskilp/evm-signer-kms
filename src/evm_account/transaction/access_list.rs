use serde::{Deserialize, Deserializer};

use super::{deserialize_address_string, hex_data_string_to_bytes, AccountAddress};

const STORAGE_KEY_LEN: usize = 32;

type StorageKey = [u8; STORAGE_KEY_LEN];

#[derive(Debug, Deserialize, PartialEq)]
pub struct Access {
    #[serde(deserialize_with = "deserialize_address_string")]
    pub address: AccountAddress,
    #[serde(deserialize_with = "deserialize_storage_keys_string_list")]
    pub storage_keys: Vec<StorageKey>,
}

fn deserialize_storage_keys_string_list<'de, D>(
    deserializer: D,
) -> Result<Vec<StorageKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let storage_key_strings_vec: Vec<String> = Vec::deserialize(deserializer)?;

    storage_key_strings_vec
        .into_iter()
        .map(|storage_key_string| {
            let storage_key_bytes_slice =
                hex_data_string_to_bytes(&storage_key_string).map_err(|error| {
                    serde::de::Error::custom(format!(
                        "Failed to deserialize storage key: {}",
                        error
                    ))
                })?;

            let storage_key_bytes: StorageKey = storage_key_bytes_slice
                .try_into()
                .map_err(|_| serde::de::Error::custom("Invalid storage key length"))?;

            Ok(storage_key_bytes)
        })
        .collect()
}
