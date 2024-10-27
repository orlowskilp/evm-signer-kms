use rlp::Encodable;
use serde::{Deserialize, Deserializer, Serialize};

use super::{hex_data_string_to_bytes, validate_address_checksum, AccountAddress};

const STORAGE_KEY_LEN: usize = 32;

type StorageKey = [u8; STORAGE_KEY_LEN];

/// Structure of an access i.e. an address and a list of storage keys accessed by a transaction.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Access {
    /// Address of the account accessed by the transaction.
    #[serde(deserialize_with = "deserialize_address_string")]
    pub address: AccountAddress,
    /// List of storage keys accessed by the transaction.
    #[serde(deserialize_with = "deserialize_storage_keys_string_list")]
    pub storage_keys: Vec<StorageKey>,
}

impl Encodable for Access {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list()
            .append(&self.address.as_slice())
            .begin_unbounded_list();
        for storage_key in &self.storage_keys {
            s.append(&storage_key.as_slice());
        }
        s.finalize_unbounded_list();
        s.finalize_unbounded_list()
    }
}

fn deserialize_address_string<'de, D>(deserializer: D) -> Result<AccountAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let address_string = String::deserialize(deserializer)?;

    if !validate_address_checksum(&address_string) {
        return Err(serde::de::Error::custom("Invalid address checksum"));
    }

    hex_data_string_to_bytes(&address_string)
        .map_err(|error| {
            serde::de::Error::custom(format!("Failed to deserialize address: {}", error))
        })?
        // Checks whether address is of proper length
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid address length"))
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
